#!/usr/bin/env python3
"""Weekly malware audit of redn3/blue-compressor.

Reads the upstream source and the release assets as data. It never builds, runs or
installs anything from upstream. Usage:

    python3 -I scripts/audit.py --target <clone> --repo-root . --out <dir> [--release-tag vX]

Outputs in <dir>:
    findings.json      verdict and findings
    report.md          the weekly report
    inventory/*.txt    current inventories (compared with baseline/*.txt)
    manifests/*.txt    per-file sha256 of the macOS app in the checked release
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

TARGET_REPO = os.environ.get("TARGET_REPO", "redn3/blue-compressor")
PLATFORM = os.environ.get("AUDIT_PLATFORM", "macOS_arm64")  # what the owner runs
UPDATER_KEY = {"macOS_arm64": "darwin-aarch64", "macOS_x64": "darwin-x86_64"}[PLATFORM]
RELEASE_TARGET = {"macOS_arm64": "aarch64-apple-darwin", "macOS_x64": "x86_64-apple-darwin"}[PLATFORM]
UA = "blue-compressor-audit"

RED, YELLOW, INFO = "red", "yellow", "info"

# Source patterns that can carry malicious behaviour. A new hit is not a verdict; it
# means a person reads the line. Hits that were reviewed live in baseline/.
PATTERNS = {
    "network": r"\b(TcpStream|TcpListener|UdpSocket|ureq::|reqwest|hyper::|curl|wget|fetch\(|XMLHttpRequest|WebSocket|http_request)\b",
    "process": r"(Command::new|process::Command|posix_spawn|execv|\bsystem\(|osascript|/bin/sh|bash -c|child_process|shell:allow)",
    "persistence": r"(LaunchAgents|LaunchDaemons|crontab|login ?items|SMAppService|\.bashrc|\.zshrc|\.profile|RunOnce|CurrentVersion\\\\Run|systemd/user)",
    "secrets": r"(\.ssh|id_rsa|Keychain|keychain|SecItem|Cookies|Login Data|\.aws|\.config/gh|wallet|seed phrase|TCC\.db)",
    "obfuscation": r"(from_utf8_unchecked|\beval\(|new Function\(|atob\(|fromCharCode|xor_decrypt|\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2})",
    "dynamic-code": r"\b(dlopen|libloading|LoadLibrary|include_bytes!|include_str!|global_asm!|asm!)\b",
    "env": r"(env::var|process\.env|getenv\()",
    "fs-wide": r"(home_dir|HOME\b|/Users/|/etc/|AppData|remove_dir_all)",
}
TEXT_EXT = {".rs", ".toml", ".yml", ".yaml", ".json", ".js", ".mjs", ".ts", ".html", ".css",
            ".py", ".sh", ".md", ".h", ".c", ".cu", ".cl", ".metal", ".wgsl", ".txt", ".lock",
            ".dockerignore", ".gitignore", ""}
IMAGE_EXT = {".png", ".ico", ".icns", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
URL_RE = re.compile(rb"[a-zA-Z][a-zA-Z0-9+.-]{1,15}://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|localhost|\d+\.\d+\.\d+\.\d+)")
# Hosts in compiled binaries: Rust strings are not NUL-terminated, so a URL often runs
# into the next string. Keep only hosts with a plausible TLD to avoid noise.
BIN_TLDS = {"com", "net", "org", "io", "dev", "app", "info", "xyz", "top", "site", "online", "club",
            "cloud", "link", "live", "tech", "store", "pro", "biz", "shop", "icu", "fun", "space",
            "website", "page", "zip", "mov", "onion", "run", "host", "email", "services", "network"}
NOT_SHIPPED = ("tests/", "examples/", "benches/")
B64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def q(x) -> str:
    """Quote upstream-derived text for Markdown: one line, no backticks, no @mentions."""
    t = re.sub(r"\s+", " ", str(x)).replace("`", "'").replace("@", "(at)")
    return f"`{t[:300]}`"


MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
FFMPEG_HOSTS = ("https://ffmpeg.martin-riedl.de/",)  # where release.yml may fetch the macOS ffmpeg


class Audit:
    def __init__(self, target: Path, root: Path, out: Path, tag: str | None, token: str | None):
        self.t, self.root, self.out = target, root, out
        self.tag_req, self.token = tag, token
        self.findings: list[dict] = []
        self.facts: dict = {}
        self.inv: dict[str, list[str]] = {}
        (out / "inventory").mkdir(parents=True, exist_ok=True)
        (out / "manifests").mkdir(parents=True, exist_ok=True)
        (out / "dl").mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- helpers
    def add(self, level: str, check: str, msg: str):
        self.findings.append({"level": level, "check": check, "msg": msg})

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.t), *args], check=True,
                              capture_output=True, text=True).stdout

    def api(self, path: str):
        req = urllib.request.Request(f"https://api.github.com/{path.lstrip('/')}",
                                     headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    def download(self, url: str, dest: Path) -> Path:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return dest

    def tracked(self) -> list[str]:
        return [p for p in self.git("ls-files", "-z").split("\0") if p]

    def baseline(self, name: str) -> list[str] | None:
        p = self.root / "baseline" / f"{name}.txt"
        return p.read_text().splitlines() if p.exists() else None

    def inventory(self, name: str, lines, level: str, check: str, what: str, details: dict | None = None):
        """Store an inventory and flag lines that are not in the reviewed baseline."""
        cur = sorted(set(lines))
        self.inv[name] = cur
        (self.out / "inventory" / f"{name}.txt").write_text("".join(f"{x}\n" for x in cur))
        base = self.baseline(name)
        if base is None:
            self.add(INFO, check, f"No baseline for {q(name)} yet; this run creates it ({len(cur)} lines).")
            return
        added = [x for x in cur if x not in set(base)]
        gone = [x for x in set(base) - set(cur)]
        for x in added[:40]:
            extra = ""
            if details and details.get(x):
                extra = " Lines: " + "; ".join(q(d) for d in details[x][:3])
            self.add(level, check, f"New {what}: {q(x)}.{extra}")
        if len(added) > 40:
            self.add(level, check, f"... and {len(added) - 40} more new {what} lines (see inventory/{name}.txt).")
        if gone:
            self.add(INFO, check, f"{len(gone)} {what} line(s) from the baseline are gone.")

    # ----------------------------------------------------------- source checks
    def source(self):
        head = self.git("rev-parse", "HEAD").strip()
        self.facts["upstream_sha"] = head
        self.facts["upstream_date"] = self.git("log", "-1", "--format=%cI").strip()
        last = self.state().get("upstream_sha")
        if last and last != head:
            try:
                log = self.git("log", "--format=%h %cI %an <%ae> %s", f"{last}..{head}").strip()
                self.facts["new_commits"] = log.splitlines()
            except subprocess.CalledProcessError:
                self.add(YELLOW, "history", f"Last checked commit {last[:12]} is not an ancestor of HEAD: upstream history was rewritten.")
        files = self.tracked()

        # commit authors over the whole history
        authors = self.git("log", "--format=%an <%ae>").splitlines()
        self.inventory("authors", authors, YELLOW, "authors", "commit author")

        hits, hosts, blobs, wf, builds = {}, {}, [], [], []
        for rel in files:
            p = self.t / rel
            if not p.is_file() or p.is_symlink():
                if p.is_symlink():
                    blobs.append(f"symlink {rel} -> {os.readlink(p)}")
                continue
            data = p.read_bytes()
            ext = p.suffix.lower()
            if rel.startswith(".github/"):
                wf.append(f"{hashlib.sha256(data).hexdigest()[:16]}  {rel}")
            if p.name == "build.rs":
                builds.append(f"{hashlib.sha256(data).hexdigest()[:16]}  {rel}")
            if b"\0" in data[:8192]:
                if ext not in IMAGE_EXT:
                    blobs.append(f"binary {rel} sha256:{hashlib.sha256(data).hexdigest()[:16]} {len(data)}B")
                continue
            if ext not in TEXT_EXT and ext not in IMAGE_EXT:
                blobs.append(f"unknown-type {rel} {len(data)}B")
            for m in URL_RE.finditer(data):
                hosts.setdefault(m.group(1).decode().lower(), set()).add(rel)
            text = data.decode("utf-8", "replace")
            if rel == "Cargo.lock":
                continue
            for i, line in enumerate(text.splitlines()):
                s = line.strip()
                if len(s) > 2000 or (len(s) > 400 and " " not in s[:400]):
                    blobs.append(f"long-line {rel} ({len(s)} chars, likely minified or packed)")
                for m in B64_RE.finditer(s):
                    blobs.append(f"base64 {rel} sha256:{hashlib.sha256(m.group().encode()).hexdigest()[:16]} {len(m.group())} chars")
                if s.startswith(("//", "#", "*", "/*")) and not rel.endswith((".yml", ".yaml", ".sh")):
                    continue
                if any(f"/{d}" in f"/{rel}" for d in NOT_SHIPPED):
                    continue
                for name, rx in PATTERNS.items():
                    for m in re.finditer(rx, s):
                        key = f"{name} | {rel} | {m.group(0)}"
                        hits.setdefault(key, []).append(f"L{i + 1}: {re.sub(r'\s+', ' ', s)[:200]}")
        # One line per (category, file, token) with a count, so edits elsewhere in a file
        # do not show up as new; a new call site changes the count.
        self.inventory("source-patterns", [f"{k} x{len(v)}" for k, v in hits.items()], YELLOW, "source",
                       "risky source token", details={f"{k} x{len(v)}": v for k, v in hits.items()})
        self.inventory("source-hosts", [f"{h}" for h in hosts], YELLOW, "hosts", "host in source")
        self.facts["source_hosts"] = {h: sorted(v)[:5] for h, v in sorted(hosts.items())}
        self.inventory("blobs", blobs, YELLOW, "blobs", "binary or packed content")
        self.inventory("workflows", wf, YELLOW, "workflows", "changed CI/release file")
        self.inventory("build-scripts", builds, YELLOW, "build", "build script")
        self.lockfile()
        self.tauri()

    def lockfile(self):
        lock = (self.t / "Cargo.lock").read_text()
        deps, bad = [], []
        for block in lock.split("[[package]]")[1:]:
            name = re.search(r'^name = "([^"]+)"', block, re.M)
            ver = re.search(r'^version = "([^"]+)"', block, re.M)
            src = re.search(r'^source = "([^"]+)"', block, re.M)
            if not name:
                continue
            s = src.group(1) if src else "path"
            deps.append(f"{name.group(1)} {ver.group(1) if ver else '?'} {s.split('+')[0]}")
            if src and not s.startswith("registry+https://github.com/rust-lang/crates.io-index"):
                bad.append(f"{name.group(1)} from {s}")
        for b in bad:
            self.add(RED, "deps", f"Crate not from crates.io: {q(b)}.")
        self.facts["dep_count"] = len(deps)
        # Version bumps are routine; new crate NAMES are what a person reads.
        self.inventory("dep-names", [d.split()[0] for d in deps], YELLOW, "deps", "crate")
        (self.out / "inventory" / "deps-full.txt").write_text("".join(f"{d}\n" for d in sorted(deps)))

    def tauri(self):
        conf = json.loads((self.t / "app/src-tauri/tauri.conf.json").read_text())
        upd = conf.get("plugins", {}).get("updater", {})
        caps = []
        for p in sorted((self.t / "app/src-tauri/capabilities").glob("*.json")):
            c = json.loads(p.read_text())
            caps += [f"permission {x if isinstance(x, str) else json.dumps(x, sort_keys=True)}" for x in c.get("permissions", [])]
        lines = [f"updater-pubkey {upd.get('pubkey', '')}",
                 *[f"updater-endpoint {e}" for e in upd.get("endpoints", [])],
                 f"csp {conf.get('app', {}).get('security', {}).get('csp')}",
                 f"identifier {conf.get('identifier')}",
                 f"withGlobalTauri {conf.get('app', {}).get('withGlobalTauri')}",
                 *caps]
        base = self.baseline("tauri") or []
        for key in ("updater-pubkey", "updater-endpoint"):
            if base and sorted(x for x in lines if x.startswith(key)) != sorted(x for x in base if x.startswith(key)):
                self.add(RED, "updater", f"The in-app updater `{key}` changed. A new key or endpoint can deliver any code to installed apps.")
        self.inventory("tauri", lines, YELLOW, "tauri", "Tauri security setting")
        self.facts["updater_pubkey_b64"] = upd.get("pubkey", "")

    def cargo_audit(self, path: Path):
        if not path.exists():
            self.add(INFO, "cargo-audit", "cargo-audit did not run.")
            return
        try:
            data = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            self.add(YELLOW, "cargo-audit", "cargo-audit output is not JSON; see the run log.")
            return
        code_file = path.with_suffix(".exit")
        code = code_file.read_text().strip() if code_file.exists() else "?"
        if "database" not in data or "lockfile" not in data or code not in ("0", "1"):
            self.add(YELLOW, "cargo-audit", f"cargo-audit did not finish (exit {code}); dependencies were not checked against RustSec.")
            return
        vulns = data.get("vulnerabilities", {}).get("list", [])
        warns = [w for ws in data.get("warnings", {}).values() for w in ws]
        rows = []
        for v in vulns + warns:
            a = v.get("advisory") or {}
            pkg = v.get("package", {})
            text = a.get("title", "").lower()  # descriptions of ordinary bugs often say "a malicious file"
            row = f"{a.get('id', '?')} {pkg.get('name')} {pkg.get('version')}: {a.get('title', v.get('kind', ''))}"
            rows.append(row)
            if re.search(r"\b(malicious|malware|backdoor|compromised)\b", text) or a.get("informational") == "malicious":
                self.add(RED, "cargo-audit", f"Advisory marks a dependency as malicious: {row}")
        self.facts["advisories"] = rows
        self.add(INFO, "cargo-audit", f"{len(vulns)} vulnerability and {len(warns)} warning advisories (bugs, not malware). See the list below.")

    # ---------------------------------------------------------- release checks
    def release(self):
        rel = self.api(f"repos/{TARGET_REPO}/releases/tags/{self.tag_req}") if self.tag_req \
            else self.api(f"repos/{TARGET_REPO}/releases/latest")
        tag = rel["tag_name"]
        self.facts["release"] = {"tag": tag, "published": rel.get("published_at"), "author": rel.get("author", {}).get("login")}
        assets = {a["name"]: a for a in rel["assets"]}
        for a in rel["assets"]:
            if a.get("uploader", {}).get("login") != "github-actions[bot]":
                self.add(RED, "release", f"Asset {q(a['name'])} was uploaded by {q(a.get('uploader', {}).get('login'))}, not by the release workflow.")

        # provenance: a successful Release workflow run built this tag's commit
        try:
            ref = self.api(f"repos/{TARGET_REPO}/git/ref/tags/{tag}")["object"]
            if ref["type"] == "tag":
                ref = self.api(f"repos/{TARGET_REPO}/git/tags/{ref['sha']}")["object"]
            tag_sha = ref["sha"]
            runs = self.api(f"repos/{TARGET_REPO}/actions/workflows/release.yml/runs?head_sha={tag_sha}&per_page=20")["workflow_runs"]
            ok = [r for r in runs if r["conclusion"] == "success"]
            self.facts["release"].update(tag_sha=tag_sha, runs=[f"{r['id']} {r['event']} {r['conclusion']} {r['created_at']}..{r['updated_at']}" for r in runs])
            if not ok:
                self.add(RED, "provenance", f"No successful `release.yml` run for {q(tag)} ({tag_sha[:12]}). The assets may not come from the public workflow.")
            else:
                start = min(r["created_at"] for r in ok)
                end = max(r["updated_at"] for r in ok)
                for a in rel["assets"]:
                    if not (start <= a["updated_at"] <= end):
                        self.add(YELLOW, "provenance", f"Asset {q(a['name'])} changed at {a['updated_at']}, outside the release runs ({start}..{end}).")
        except urllib.error.HTTPError as e:
            self.add(YELLOW, "provenance", f"Could not read the release runs: HTTP {e.code}.")

        v = tag.lstrip("v")
        want = {
            "app": f"Blue-Compressor_{v}_{PLATFORM}.app.tar.gz",
            "sig": f"Blue-Compressor_{v}_{PLATFORM}.app.tar.gz.sig",
            "dmg": f"Blue-Compressor_{v}_{PLATFORM}.dmg",
            "cli": f"bluecompress-cli_{v}_{PLATFORM}.tar.gz",
            "latest": "latest.json",
        }
        files: dict[str, Path] = {}
        for k, name in want.items():
            if name not in assets:
                self.add(YELLOW if k != "app" else RED, "release", f"Release {q(tag)} has no {q(name)}.")
                continue
            a = assets[name]
            p = self.download(a["browser_download_url"], self.out / "dl" / name)
            digest = "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
            if a.get("digest") and a["digest"] != digest:
                self.add(RED, "release", f"{q(name)} download does not match the digest GitHub lists ({a['digest']}).")
            files[k] = p
        self.facts["assets"] = {p.name: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in files.values()}
        self.facts["asset_paths"] = [str(p) for p in files.values()]
        subs = [("provenance", lambda: self.tag_ancestry(tag))]
        if "app" in files:
            subs += [("signature", lambda: self.verify_signature(files, tag)), ("app", lambda: self.inspect_app(files["app"], tag))]
        if "latest" in files and "sig" in files:
            subs.append(("updater", lambda: self.check_latest_json(files, tag)))
        if "cli" in files:
            subs.append(("cli", lambda: self.inspect_cli(files["cli"])))
        for name, fn in subs:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                # A check on an upstream file that cannot finish is treated as failed.
                self.add(RED, name, f"The {q(name)} check could not finish on the release file: {type(e).__name__}: {q(e)}")

    def tag_ancestry(self, tag: str):
        """The release tag should be a commit on the main branch that the source checks read."""
        r = subprocess.run(["git", "-C", str(self.t), "merge-base", "--is-ancestor", tag, "HEAD"], capture_output=True)
        if r.returncode != 0:
            self.add(YELLOW, "provenance", f"Release tag {q(tag)} is not on upstream main. The source checks above did not read the code of this release.")
        try:
            wf = self.git("show", f"{tag}:.github/workflows/release.yml")
            head_wf = (self.t / ".github/workflows/release.yml").read_text()
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.add(RED, "provenance", f"release.yml is missing at {q(tag)} or on main; the release cannot be tied to a workflow.")
            return
        if wf != head_wf:
            self.add(YELLOW, "provenance", f"release.yml at {q(tag)} differs from release.yml on main; read it before trusting this release.")

    def verify_signature(self, files, tag):
        """Check the updater signature with the public key from tauri.conf.json at the tag."""
        if not shutil.which("minisign"):
            self.add(YELLOW, "signature", "minisign is not installed; the updater signature was not checked.")
            return
        conf = json.loads(self.git("show", f"{tag}:app/src-tauri/tauri.conf.json"))
        pub_b64 = conf["plugins"]["updater"]["pubkey"]
        if pub_b64 != self.facts.get("updater_pubkey_b64"):
            self.add(RED, "signature", f"The updater key at {q(tag)} differs from the key on main.")
        d = self.out / "sigcheck"
        d.mkdir(exist_ok=True)
        (d / "pub.key").write_bytes(base64.b64decode(pub_b64))
        (d / "file.sig").write_bytes(base64.b64decode(files["sig"].read_text().strip()))
        r = subprocess.run(["minisign", "-V", "-p", str(d / "pub.key"), "-x", str(d / "file.sig"), "-m", str(files["app"])],
                           capture_output=True, text=True)
        self.facts["signature"] = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            self.add(RED, "signature", f"The updater signature of {q(files['app'].name)} does NOT verify: {q(self.facts['signature'])}")

    def check_latest_json(self, files, tag):
        data = json.loads(files["latest"].read_text())
        plat = data.get("platforms", {}).get(UPDATER_KEY)
        if not plat:
            self.add(YELLOW, "updater", f"latest.json has no `{UPDATER_KEY}` entry.")
            return
        prefix = f"https://github.com/{TARGET_REPO}/releases/download/"
        if not plat.get("url", "").startswith(prefix):
            self.add(RED, "updater", f"latest.json sends `{UPDATER_KEY}` updates to {q(plat.get('url'))}, outside {prefix}.")
        if plat.get("signature", "").strip() != files["sig"].read_text().strip():
            self.add(RED, "updater", "The signature in latest.json differs from the .sig asset.")
        for k, p in data.get("platforms", {}).items():
            if not p.get("url", "").startswith(prefix):
                self.add(RED, "updater", f"latest.json {q(k)} URL points outside the upstream releases: {q(p.get('url'))}.")
        self.facts["latest_json_version"] = data.get("version")

    def safe_members(self, tf: tarfile.TarFile):
        return [m for m in tf.getmembers() if m.isfile()]

    def inspect_app(self, path: Path, tag: str):
        manifest, binaries = [], {}
        with tarfile.open(path) as tf:
            members = tf.getmembers()
            tops = {m.name.split("/", 1)[0] for m in members}
            if len(tops) != 1 or not next(iter(tops)).endswith(".app"):
                self.add(RED, "app", f"The app archive has more than one top-level entry or no .app folder: {q(sorted(tops)[:5])}.")
            names = [m.name for m in members]
            norm = [posixpath.normpath(n.removeprefix("./")) for n in names]
            # macOS file systems ignore case and Unicode form, so compare folded names.
            folded = [unicodedata.normalize("NFD", k).casefold() for k in norm]
            if len(folded) != len(set(folded)):
                self.add(RED, "app", "The app archive has duplicate entries after path normalization (a later one can hide an earlier one).")
            odd = [n for n, k in zip(names, norm) if n.removeprefix("./").rstrip("/") != k or k.startswith(("/", "../"))]
            if odd:
                self.add(RED, "app", f"The app archive has non-canonical paths: {q(odd[:5])}.")
            for m in members:
                if m.issym() or m.islnk():
                    manifest.append(f"link {m.name} -> {m.linkname}")
                    if m.linkname.startswith("/") or ".." in Path(m.linkname).parts:
                        self.add(RED, "app", f"Link {q(m.name)} points outside the bundle: {q(m.linkname)}.")
                    continue
                if not m.isfile():
                    continue
                data = tf.extractfile(m).read()
                rel = posixpath.normpath(m.name.removeprefix("./")).split(".app/", 1)[-1]
                manifest.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
                if data[:4] in MACHO_MAGICS or data[:2] == b"#!" or m.mode & 0o111:
                    binaries[rel] = data
                if m.mode & 0o6000:
                    self.add(RED, "app", f"{q(rel)} has a setuid or setgid bit.")
        (self.out / "manifests" / f"{tag}-{PLATFORM}.txt").write_text("".join(f"{x}\n" for x in sorted(manifest)))
        self.facts["app_files"] = len(manifest)
        expected = {"Contents/MacOS/blue-compressor", "Contents/Resources/ffmpeg"}
        extra = set(binaries) - expected
        for x in sorted(extra):
            self.add(YELLOW, "app", f"Unexpected executable code in the bundle: {q(x)}.")
        for x in sorted(expected - set(binaries)):
            self.add(YELLOW, "app", f"Expected executable not found in the bundle: {q(x)}.")
        plist = next((n for n in manifest if n.endswith("Contents/Info.plist")), None)
        main = binaries.get("Contents/MacOS/blue-compressor")
        if main:
            mo = MachO(main)
            self.inventory("app-dylibs", mo.dylibs(), YELLOW, "app-binary", "linked library in the main binary")
            self.inventory("app-hosts", hosts_in(main), YELLOW, "app-binary", "host in the main binary")
            self.facts["main_binary"] = {"sha256": hashlib.sha256(main).hexdigest(), "arch": mo.arch, "signed": mo.has_signature}
        ff = binaries.get("Contents/Resources/ffmpeg")
        if ff:
            self.check_ffmpeg(ff, tag)
        _ = plist

    def check_ffmpeg(self, bundled: bytes, tag: str):
        """Compare the bundled ffmpeg with the build release.yml says it downloads."""
        wf = self.git("show", f"{tag}:.github/workflows/release.yml")
        m = re.search(rf"target: {RELEASE_TARGET}.*?ffmpeg: \"([^\"]+)\"", wf)
        if not m:
            self.add(YELLOW, "ffmpeg", f"Could not find the ffmpeg URL for {RELEASE_TARGET} in release.yml at {q(tag)}.")
            return
        url = m.group(1)
        self.facts["ffmpeg_url"] = url
        if not url.startswith(FFMPEG_HOSTS):
            self.add(RED, "ffmpeg", f"release.yml at {q(tag)} fetches ffmpeg from a new place: {q(url)}. Allowed: {', '.join(FFMPEG_HOSTS)}.")
        try:
            z = self.download(url, self.out / "dl" / "ffmpeg-official.zip")
        except Exception as e:  # noqa: BLE001
            self.add(YELLOW, "ffmpeg", f"Could not download the official ffmpeg from {q(url)}: {q(e)}")
            return
        with zipfile.ZipFile(z) as zf:
            name = next((n for n in zf.namelist() if Path(n).name == "ffmpeg"), None)
            if not name:
                self.add(YELLOW, "ffmpeg", "The official ffmpeg zip has no `ffmpeg` file.")
                return
            official = zf.read(name)
        b, o = hashlib.sha256(bundled).hexdigest(), hashlib.sha256(official).hexdigest()
        self.facts["ffmpeg"] = {"bundled": b, "official": o}
        if b == o:
            self.facts["ffmpeg"]["result"] = "byte-identical"
            return
        try:
            same = MachO(bundled).section_digest() == MachO(official).section_digest()
        except (ValueError, struct.error, IndexError) as e:
            same = False
            self.facts["ffmpeg"]["parse_error"] = str(e)
        if same:
            self.facts["ffmpeg"]["result"] = "same code and data; only the code signature differs"
        else:
            self.facts["ffmpeg"]["result"] = "DIFFERENT"
            self.add(RED, "ffmpeg", f"The bundled ffmpeg is not the build from {q(url)}: its code or data differs.")

    def inspect_cli(self, path: Path):
        with tarfile.open(path) as tf:
            for m in self.safe_members(tf):
                data = tf.extractfile(m).read()
                if Path(m.name).name == "bluecompress" and data[:4] in MACHO_MAGICS:
                    self.inventory("cli-hosts", hosts_in(data), YELLOW, "cli-binary", "host in the CLI binary")
                    self.inventory("cli-dylibs", MachO(data).dylibs(), YELLOW, "cli-binary", "linked library in the CLI binary")

    # -------------------------------------------------------------- scanners
    def clamav(self, path: Path):
        if not path.exists():
            self.add(YELLOW, "clamav", "ClamAV did not run.")
            return
        r = json.loads(path.read_text())
        self.facts["clamav"] = r
        if r.get("exit") == 1:
            self.add(RED, "clamav", f"ClamAV found something: {q(r.get('infected', ''))}")
        elif r.get("exit") != 0:
            self.add(YELLOW, "clamav", f"ClamAV did not finish (exit {r.get('exit')}): {r.get('error', '')[:300]}")

    def virustotal(self):
        """Look up each release binary on VirusTotal; upload it if VirusTotal does not know it.

        Free public API: 4 requests per minute, so every request waits for the rate limit.
        Uploaded files become public on VirusTotal (they are public on GitHub already).
        """
        key = os.environ.get("VT_API_KEY")
        if not key:
            self.facts["virustotal"] = "skipped (no VT_API_KEY secret)"
            return
        vt = VirusTotal(key)
        paths = {Path(p).name: Path(p) for p in self.facts.get("asset_paths", [])}
        out, pending = {}, {}
        for name, digest in self.facts.get("assets", {}).items():
            if name.endswith((".sig", ".json")):
                continue  # text files, nothing to scan
            h = digest.split(":", 1)[1]
            link = f"https://www.virustotal.com/gui/file/{h}"
            try:
                st = vt.stats(h)
                if st is None and name in paths and os.environ.get("VT_UPLOAD", "1") == "1":
                    pending[name] = (vt.upload(paths[name]), h, link)
                    out[name] = f"uploaded for scanning ({link})"
                    continue
                out[name] = self.vt_judge(name, st, link) if st else "not known to VirusTotal"
            except Exception as e:  # noqa: BLE001
                out[name] = f"VirusTotal error: {type(e).__name__}: {e}"
                self.add(YELLOW, "virustotal", f"VirusTotal check of {q(name)} failed: {q(e)}")
        deadline = time.monotonic() + int(os.environ.get("VT_WAIT_SECONDS", "900"))
        while pending and time.monotonic() < deadline:
            for name, (aid, h, link) in list(pending.items()):
                try:
                    st = vt.analysis(aid)
                except Exception as e:  # noqa: BLE001
                    out[name] = f"uploaded; polling failed: {type(e).__name__} ({link})"
                    pending.pop(name)
                    continue
                if st is not None:
                    out[name] = self.vt_judge(name, st, link)
                    pending.pop(name)
        for name, (_, _, link) in pending.items():
            out[name] = f"uploaded, scan still running; see {link}"
            self.add(INFO, "virustotal", f"{q(name)} was uploaded to VirusTotal; the scan did not finish in time. The next run reads it.")
        self.facts["virustotal"] = out

    def vt_judge(self, name: str, st: dict, link: str) -> str:
        bad, sus = st.get("malicious", 0), st.get("suspicious", 0)
        scanned = bad + sus + st.get("undetected", 0) + st.get("harmless", 0)
        text = f"{bad} malicious, {sus} suspicious of {scanned} engines ({link})"
        if bad >= 2:
            self.add(RED, "virustotal", f"{q(name)}: {text}.")
        elif bad or sus:
            self.add(YELLOW, "virustotal", f"{q(name)}: {text}. One engine alone is often a false positive; read the detection names.")
        return text

    # ---------------------------------------------------------------- output
    def state(self) -> dict:
        p = self.root / "state" / "last.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def verdict(self) -> str:
        lv = {f["level"] for f in self.findings}
        return "RED" if RED in lv else "YELLOW" if YELLOW in lv else "GREEN"

    def write(self, run_url: str):
        v = self.verdict()
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        rel = self.facts.get("release", {})
        meaning = {
            "GREEN": "No sign of malware or tampering. Nothing to do.",
            "YELLOW": "Something changed that a person must read. It is not proof of malware. Read the yellow lines, then accept the new baseline if they are fine.",
            "RED": "A check failed that protects against malware or tampering. Do not install or update Blue Compressor until a person reads this.",
        }[v]
        L = [f"# Blue Compressor malware audit, {today}", "",
             f"**Verdict: {v}.** {meaning}", "",
             f"- Upstream `{TARGET_REPO}` main at `{self.facts.get('upstream_sha', '?')[:12]}` ({self.facts.get('upstream_date', '?')})",
             f"- Release checked: {q(rel.get('tag', '?'))} (published {rel.get('published', '?')}), platform `{PLATFORM}`",
             f"- Run: {run_url}", ""]
        for level, title in ((RED, "Red: possible malware or tampering"), (YELLOW, "Yellow: read and decide"), (INFO, "Info")):
            rows = [f for f in self.findings if f["level"] == level]
            if rows:
                L += [f"## {title}", ""] + [f"- **{f['check']}**: {f['msg']}" for f in rows] + [""]
        L += ["## Checks that passed or ran", ""]
        sig = self.facts.get("signature")
        L.append(f"- Updater signature (minisign, key from tauri.conf.json): {'verified' if sig and 'verified' in sig.lower() else sig or 'not checked'}")
        ff = self.facts.get("ffmpeg", {})
        L.append(f"- Bundled ffmpeg against {q(self.facts.get('ffmpeg_url', '?'))}: {ff.get('result', 'not checked')}")
        mb = self.facts.get("main_binary")
        if mb:
            L.append(f"- Main binary: {mb['arch']}, sha256 `{mb['sha256'][:16]}…`, embedded signature: {mb['signed']}")
        L.append(f"- App bundle files hashed: {self.facts.get('app_files', 0)} (manifest in `manifests/`)")
        cv = self.facts.get("clamav", {})
        L.append(f"- ClamAV: exit {cv.get('exit', '?')} ({cv.get('db', 'db ?')}), {cv.get('scanned', '?')}")
        L.append(f"- VirusTotal hash lookup: {json.dumps(self.facts.get('virustotal'))}")
        L.append(f"- Crates in Cargo.lock: {self.facts.get('dep_count', '?')}")
        L.append(f"- Release runs for the tag commit: {'; '.join(rel.get('runs', [])) or 'none found'}")
        L.append("")
        if self.facts.get("new_commits"):
            L += ["## New upstream commits since the last report", ""] + [f"- {q(c)}" for c in self.facts["new_commits"][:60]] + [""]
        if self.facts.get("assets"):
            L += ["## Release asset hashes", ""] + [f"- {q(n)} `{h}`" for n, h in self.facts["assets"].items()] + [""]
        if self.facts.get("advisories"):
            L += ["## RustSec advisories (known bugs, not malware)", ""] + [f"- {q(a)}" for a in self.facts["advisories"]] + [""]
        L += ["## Network hosts in the source", ""] + [f"- {q(h)} ({q(', '.join(f))})" for h, f in self.facts.get("source_hosts", {}).items()] + [""]
        L += ["---", "This audit reads upstream code and release files as data. It never builds or runs them. "
              "Yellow lines come from comparing with `baseline/`; to accept them after review, run the workflow with `accept_baseline: true`.", ""]
        (self.out / "report.md").write_text("\n".join(L))
        facts = {k: v for k, v in self.facts.items() if k != "asset_paths"}
        (self.out / "findings.json").write_text(json.dumps({"verdict": v, "date": today, "findings": self.findings, "facts": facts}, indent=2))
        (self.out / "state.json").write_text(json.dumps({
            "upstream_sha": self.facts.get("upstream_sha"), "release_tag": rel.get("tag"),
            "checked": today, "verdict": v}, indent=2) + "\n")


class VirusTotal:
    """Small VirusTotal v3 client for the free API (4 requests per minute)."""

    API = "https://www.virustotal.com/api/v3"
    GAP = 16.0  # seconds between requests

    def __init__(self, key: str):
        self.key, self.last = key, 0.0

    def _req(self, url: str, data: bytes | None = None, ctype: str | None = None, timeout: int = 120):
        wait = self.last + self.GAP - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self.last = time.monotonic()
        req = urllib.request.Request(url, data=data, headers={"x-apikey": self.key, "User-Agent": UA})
        if ctype:
            req.add_header("Content-Type", ctype)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)

    def stats(self, sha256: str) -> dict | None:
        try:
            return self._req(f"{self.API}/files/{sha256}")["data"]["attributes"]["last_analysis_stats"]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def upload(self, path: Path) -> str:
        url = f"{self.API}/files"
        if path.stat().st_size > 32 * 1024 * 1024:
            url = self._req(f"{self.API}/files/upload_url")["data"]
        boundary = "----bcaudit" + hashlib.sha256(path.name.encode()).hexdigest()[:24]
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        body = head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        return self._req(url, body, f"multipart/form-data; boundary={boundary}", timeout=600)["data"]["id"]

    def analysis(self, analysis_id: str) -> dict | None:
        a = self._req(f"{self.API}/analyses/{analysis_id}")["data"]["attributes"]
        return a["stats"] if a.get("status") == "completed" else None


def hosts_in(data: bytes) -> list[str]:
    out = set()
    for m in URL_RE.finditer(data):
        h = m.group(1).decode().lower()
        tld = h.rsplit(".", 1)[-1]
        if h == "localhost" or re.fullmatch(r"[\d.]+", h) or len(tld) == 2 or tld in BIN_TLDS:
            out.add(h)
    return sorted(out)


class MachO:
    """Minimal Mach-O reader: picks the 64-bit slice, lists dylibs, hashes sections."""

    def __init__(self, data: bytes):
        self.arch = "?"
        if data[:4] == b"\xca\xfe\xba\xbe":  # fat, big endian
            n = struct.unpack(">I", data[4:8])[0]
            slices = [struct.unpack(">iiIII", data[8 + 20 * i: 28 + 20 * i]) for i in range(n)]
            pick = next((s for s in slices if s[0] == 0x0100000C), slices[0])
            data = data[pick[2]: pick[2] + pick[3]]
        if data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("not a 64-bit little-endian Mach-O")
        self.d = data
        cpu, _, _, ncmds, _ = struct.unpack("<iiIII", data[4:24])
        self.arch = {0x0100000C: "arm64", 0x01000007: "x86_64"}.get(cpu, hex(cpu))
        self.cmds = []
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", data[off: off + 8])
            self.cmds.append((cmd, off, size))
            off += size
        self.has_signature = any(c == 0x1D for c, _, _ in self.cmds)

    def dylibs(self) -> list[str]:
        out = []
        for cmd, off, size in self.cmds:
            if cmd in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
                name_off = struct.unpack("<I", self.d[off + 8: off + 12])[0]
                out.append(self.d[off + name_off: off + size].split(b"\0")[0].decode(errors="replace"))
        return out

    def section_digest(self) -> str:
        h = hashlib.sha256()
        for cmd, off, _ in self.cmds:
            if cmd != 0x19:
                continue
            seg = self.d[off + 8: off + 24].split(b"\0")[0]
            if seg in (b"__LINKEDIT", b"__PAGEZERO"):
                continue
            nsects = struct.unpack("<I", self.d[off + 64: off + 68])[0]
            for i in range(nsects):
                s = off + 72 + 80 * i
                sect = self.d[s: s + 16].split(b"\0")[0]
                size = struct.unpack("<Q", self.d[s + 40: s + 48])[0]
                foff = struct.unpack("<I", self.d[s + 48: s + 52])[0]
                flags = struct.unpack("<I", self.d[s + 64: s + 68])[0]
                h.update(seg + b"/" + sect + struct.pack("<Q", size))
                if flags & 0xFF not in (0x1, 0xC, 0x12):  # zerofill types have no file bytes
                    h.update(self.d[foff: foff + size])
        return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, type=Path)
    ap.add_argument("--repo-root", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--release-tag", default="")
    ap.add_argument("--stage", choices=["scan", "report"], default="scan")
    a = ap.parse_args()
    au = Audit(a.target.resolve(), a.repo_root.resolve(), a.out.resolve(), a.release_tag or None,
               os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    run_url = os.environ.get("RUN_URL", "local run")
    if a.stage == "scan":
        steps = [("source", au.source), ("release", au.release)]
        for name, fn in steps:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                au.add(YELLOW, name, f"The {q(name)} check crashed: {type(e).__name__}: {q(e)}")
        json.dump({"findings": au.findings, "facts": au.facts}, open(a.out / "scan.json", "w"))
        (a.out / "asset-paths.txt").write_text("\n".join(au.facts.get("asset_paths", [])) + "\n")
        return
    scan = json.loads((a.out / "scan.json").read_text())
    au.findings, au.facts = scan["findings"], scan["facts"]
    au.cargo_audit(a.out / "audit.json")
    au.clamav(a.out / "clamav.json")
    au.virustotal()
    au.write(run_url)
    print((a.out / "report.md").read_text())


if __name__ == "__main__":
    sys.exit(main())
