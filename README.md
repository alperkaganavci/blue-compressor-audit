# Blue Compressor: independent weekly malware audit

An independent, weekly check of [redn3/blue-compressor](https://github.com/redn3/blue-compressor) for malware and tampering. Blue Compressor is a useful tool for shrinking raw R3D and N-RAW footage, and people install it on machines that hold their camera originals. This repo gives users and the maintainer a public, repeatable answer to one question: *is the app I download the app the source says it is, and does it do anything it should not?*

This is a community contribution. It is not affiliated with the Blue Compressor project.

The audit reads upstream code and release files as **data**. It never builds, runs or installs anything from upstream, and it never writes to upstream.

- Latest report: see [`reports/`](reports/) (newest file).
- Method: [`scripts/audit.py`](scripts/audit.py) and [`.github/workflows/audit.yml`](.github/workflows/audit.yml).

## When it runs

- Every Monday at 05:17 UTC, and on manual dispatch.
- Each run commits `reports/<date>.md`, `findings/<date>.json`, `manifests/<tag>-macOS_arm64.txt` and `state/last.json`.
- A **RED** or **YELLOW** verdict opens an issue here, or adds a comment to the open one.

## Verdicts

| Verdict | Meaning |
|---|---|
| GREEN | No sign of malware or tampering. |
| YELLOW | Something changed that a person must read (new network or process call, new host, new crate, changed CI file, new author). It is not proof of malware. After review, the baseline is updated with `accept_baseline: true`. |
| RED | A check that protects against malware or tampering failed. Do not install or update until the report is understood. |

## Checks

**Release (what users install).** The audit currently checks the macOS Apple silicon build.

1. Every asset was uploaded by `github-actions[bot]`, and a successful `release.yml` run built the tag's commit. Asset upload times fall inside that run. The tag is on `main`.
2. Each downloaded file matches the sha256 digest GitHub lists.
3. The `.app.tar.gz` updater signature verifies with minisign against the public key in `tauri.conf.json` at the tag, and that key is the same as on `main`.
4. `latest.json` (the in-app updater feed) points only at upstream release URLs, and its signature equals the `.sig` asset.
5. The bundled `ffmpeg` is byte-identical to the build `release.yml` downloads (or has the same code and data sections if only the signature differs), and that download comes from an allowed host.
6. The app archive has one `.app` folder, no duplicate or non-canonical paths, only the two expected executables, no setuid files and no links that leave the bundle. Linked libraries and URL hosts inside the main binary and the CLI binary are compared with the baseline.
7. ClamAV scans the downloaded files. VirusTotal looks up the app archive, the DMG and the CLI archive by hash. If VirusTotal does not know a file yet, the audit uploads it, so about 70 antivirus engines scan it, and the report links the public VirusTotal page. Two or more engines flagging a file is RED; one is YELLOW, because a single detection is often a false positive.

**Source (what the next release will contain).**

1. Risky tokens per file (network, process, persistence, secrets, obfuscation, dynamic code, environment, wide file access) are counted and compared with the baseline. Tests and examples are skipped because they do not ship.
2. URL hosts in all tracked files, binary or packed files, long base64 strings, build scripts, CI and release files, commit authors, crate names in `Cargo.lock`, and the Tauri security settings (updater key and endpoint, CSP, permissions) are compared with the baseline.
3. Any crate that does not come from crates.io is RED. A changed updater key or endpoint is RED.
4. cargo-audit lists RustSec advisories. An advisory that marks a crate as malicious is RED; ordinary vulnerabilities are listed as info.

## Check your own installed app (macOS)

```bash
scripts/check-installed.sh
```

It hashes every file in `/Applications/Blue Compressor.app` and compares the result with the manifest of the same version, then runs `codesign --verify --deep --strict`. If no manifest exists for your version, run the workflow (or `scripts/run-local.sh vX.Y.Z`) for that tag first.

## Run the audit yourself

```bash
brew install minisign clamav cargo-audit
scripts/run-local.sh            # latest release
scripts/run-local.sh v0.3.6     # a specific release
```

## Limits

- The main binary is not rebuilt here to prove it matches the source (the build is not reproducible yet). The checks above show it came from the public workflow, carries the upstream updater signature and did not change after the build.
- Upstream ships the macOS app ad-hoc signed and not notarized, so Gatekeeper rejects it. That is expected and not a finding.
- Only the macOS Apple silicon release is inspected today. Windows and Linux builds are not.
- The first baseline was reviewed by hand on 2026-11-07 against upstream `4d35f31` and release v1.0.0.
