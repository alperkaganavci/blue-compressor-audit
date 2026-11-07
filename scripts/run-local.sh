#!/usr/bin/env bash
# Run the same audit as .github/workflows/audit.yml on this Mac, for when GitHub Actions
# cannot run. Needs: git, python3, minisign, clamav, cargo-audit (brew install minisign
# clamav cargo-audit). Upstream code and release files are read as data, never run.
#
#   scripts/run-local.sh [release_tag] [--accept-baseline]
#
# It writes the same files the workflow commits (reports/, findings/, manifests/, state/,
# and baseline/ when missing or accepted) into this checkout. Commit and push them yourself.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tag=""; accept=false
for a in "$@"; do case "$a" in --accept-baseline) accept=true ;; *) tag="$a" ;; esac; done
for t in git python3 minisign clamscan freshclam cargo-audit; do command -v "$t" >/dev/null || { echo "missing: $t"; exit 2; }; done

work="$(mktemp -d "${TMPDIR:-/tmp}/bc-audit.XXXXXX")"; trap 'rm -rf "$work"' EXIT
cache="${XDG_CACHE_HOME:-$HOME/.cache}/blue-compressor-audit"; mkdir -p "$cache/clamav"
out="$work/out"; mkdir -p "$out"
export TARGET_REPO="${TARGET_REPO:-redn3/blue-compressor}" AUDIT_PLATFORM="${AUDIT_PLATFORM:-macOS_arm64}"

git clone -q --no-tags "https://github.com/$TARGET_REPO.git" "$work/target"
git -C "$work/target" fetch -q --tags
python3 -I "$here/scripts/audit.py" --target "$work/target" --repo-root "$here" --out "$out" --release-tag "$tag"

set +e
cargo-audit audit --file "$work/target/Cargo.lock" --json > "$out/audit.json" 2> "$out/audit.stderr"
echo $? > "$out/audit.exit"
printf 'DatabaseDirectory %s\nDatabaseMirror database.clamav.net\n' "$cache/clamav" > "$cache/freshclam.conf"
freshclam --config-file="$cache/freshclam.conf" --stdout > "$out/freshclam.log" 2>&1
clamscan --database="$cache/clamav" --recursive --infected --max-filesize=600M --max-scansize=2000M \
  --max-files=50000 --max-recursion=20 "$out/dl" > "$out/clamscan.log" 2>&1
echo $? > "$out/clamscan.exit"
set -e
python3 -I "$here/scripts/clamav_json.py" "$out" > /dev/null

RUN_URL="local run on $(hostname -s)" python3 -I "$here/scripts/audit.py" --target "$work/target" --repo-root "$here" --out "$out" --stage report > /dev/null
day="$(date -u +%F)"; name="$day"; [ -n "$tag" ] && name="$day-$tag"
mkdir -p "$here"/{reports,findings,manifests,state}
cp "$out/report.md" "$here/reports/$name.md"
cp "$out/findings.json" "$here/findings/$name.json"
cp "$out"/manifests/*.txt "$here/manifests/" 2>/dev/null || true
[ -z "$tag" ] && cp "$out/state.json" "$here/state/last.json"
if [ ! -d "$here/baseline" ] || $accept; then mkdir -p "$here/baseline"; cp "$out"/inventory/*.txt "$here/baseline/"; echo "baseline written"; fi
echo "verdict: $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$out/findings.json")"
echo "report: reports/$name.md"
