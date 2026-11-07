#!/usr/bin/env python3
"""Write the latest result into README.md and state/badge.json.

    python3 -I scripts/readme_status.py <findings.json> <report path in repo> <repo root>

The README design is locked: this script replaces only the text between
<!-- status:start --> and <!-- status:end -->. Everything else in README.md is
written by hand and stays as it is.
"""
import html
import json
import re
import sys
import urllib.parse
from pathlib import Path

START, END = "<!-- status:start -->", "<!-- status:end -->"
REPO = "https://github.com/alperkaganavci/blue-compressor-audit"
UPSTREAM = "https://github.com/redn3/blue-compressor"
ICON = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}
COLOR = {"GREEN": "brightgreen", "YELLOW": "yellow", "RED": "red"}


TAG_RE = re.compile(r"^v?[0-9A-Za-z._-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def cell(text: str) -> str:
    """Make upstream-derived text safe for one Markdown table cell: one line, HTML
    escaped, Markdown specials escaped, no backticks, no @mentions."""
    t = html.escape(re.sub(r"\s+", " ", str(text)), quote=True)
    t = t.replace("`", "'").replace("@", "(at)")
    return re.sub(r"([\\|\[\]()!*_~#<>])", r"\\\1", t)


def vt_cell(facts: dict) -> str:
    vt = facts.get("virustotal")
    if not isinstance(vt, dict) or not vt:
        return "not run"
    parts = []
    for name, text in vt.items():
        kind = "app" if name.endswith(".app.tar.gz") else "dmg" if name.endswith(".dmg") else "cli"
        m = re.match(r"(\d+) malicious, (\d+) suspicious of (\d+) engines \((https://www\.virustotal\.com/gui/file/[0-9a-f]{64})\)", text)
        if m:
            bad, sus, total, link = m.groups()
            parts.append(f"[{kind} {int(bad) + int(sus)}/{total}]({link})")
        else:
            parts.append(f"{kind}: {cell(text)[:60]}")
    return " · ".join(parts)


def main():
    findings, report, root = json.loads(Path(sys.argv[1]).read_text()), sys.argv[2], Path(sys.argv[3])
    v, f = findings["verdict"], findings["facts"]
    rel = f.get("release", {})
    raw_tag = str(rel.get("tag", ""))
    tag_ok = bool(TAG_RE.fullmatch(raw_tag))
    tag = raw_tag if tag_ok else "invalid tag"
    raw_sha = str(f.get("upstream_sha", ""))
    sha_ok = bool(SHA_RE.fullmatch(raw_sha))
    sig = f.get("signature") or ""
    ff = (f.get("ffmpeg") or {}).get("result", "not checked")
    cv = f.get("clamav") or {}
    clam = {0: "clean", 1: "FOUND", 2: "error"}.get(cv.get("exit"), "not run")
    reds = sum(1 for x in findings["findings"] if x["level"] == "red")
    yellows = sum(1 for x in findings["findings"] if x["level"] == "yellow")
    sha = raw_sha[:7] if sha_ok else "unknown"
    first_run = (rel.get("runs") or [""])[0].split()
    run_id = first_run[0] if first_run and first_run[0].isdigit() else ""
    rows = [
        ("Verdict", f"{ICON.get(v, '')} **{v}**" + (f" ({reds} red, {yellows} yellow)" if reds or yellows else "")),
        ("Release", (f"[`{tag}`]({UPSTREAM}/releases/tag/{urllib.parse.quote(tag, safe='')})" if tag_ok else "⚠️ invalid tag")
         + " · macOS Apple silicon"),
        ("Updater signature", "✅ verified" if "verified" in sig.lower() else "❌ " + (cell(sig)[:80] or "not checked")),
        ("Bundled ffmpeg", ("✅ " if ff.startswith(("byte-identical", "same code")) else "❌ ") + cell(ff)),
        ("Built by", f"✅ upstream `release.yml`, run {run_id}" if run_id else "❌ no release run found"),
        ("ClamAV", ("✅ " if clam == "clean" else "❌ ") + f"{clam} ({cell(cv.get('db', '?'))})"),
        ("VirusTotal (detections/engines)", vt_cell(f)),
        ("Source checked", f"[`{sha}`]({UPSTREAM}/commit/{raw_sha}) on `main`" if sha_ok else "⚠️ unknown commit"),
        ("Checked", f"{cell(findings.get('date', '?'))} · [full report]({report})"),
    ]
    block = "\n".join([START, "", "| Check | Result |", "|---|---|", *[f"| {k} | {val} |" for k, val in rows], "", END])
    readme = root / "README.md"
    text = readme.read_text()
    if START not in text or END not in text:
        raise SystemExit("README.md has no status markers; the design was changed by hand.")
    text = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _: block, text, count=1, flags=re.S)
    readme.write_text(text)
    (root / "state").mkdir(exist_ok=True)
    (root / "state" / "badge.json").write_text(json.dumps({
        "schemaVersion": 1, "label": "latest audit", "message": f"{v} · {tag}",
        "color": COLOR.get(v, "lightgrey"), "cacheSeconds": 3600}) + "\n")
    print(block)


if __name__ == "__main__":
    main()
