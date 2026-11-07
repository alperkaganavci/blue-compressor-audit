#!/usr/bin/env bash
# Compare the Blue Compressor app installed on this Mac with the release it claims to be.
# It hashes every file in the app and compares with manifests/<tag>-macOS_arm64.txt,
# which the weekly audit wrote from the signed release file. It changes nothing.
#
#   scripts/check-installed.sh ["/Applications/Blue Compressor.app"]
#
# If the manifest for the installed version is missing, run the workflow once with
# release_tag set to that version (for example v0.3.6).
set -euo pipefail
app="${1:-/Applications/Blue Compressor.app}"
here="$(cd "$(dirname "$0")/.." && pwd)"
ver="$(defaults read "$app/Contents/Info" CFBundleShortVersionString)"
man="$here/manifests/v${ver}-macOS_arm64.txt"
echo "Installed: $app, version $ver"
[ -f "$man" ] || { echo "NO MANIFEST: $man is missing. Run the audit workflow with release_tag=v$ver, pull, and run this again."; exit 2; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
grep -v '^link ' "$man" | sort -k2 > "$tmp/want"
( cd "$app" && find . -type f | sed 's|^\./||' | while IFS= read -r f; do shasum -a 256 "$f"; done ) | sort -k2 > "$tmp/have"

status=0
if diff -u "$tmp/want" "$tmp/have" > "$tmp/diff"; then
  echo "FILES MATCH: all $(wc -l < "$tmp/want" | tr -d ' ') files are identical to the signed release v$ver."
else
  status=1
  echo "FILES DIFFER from the signed release v$ver:"
  cat "$tmp/diff"
fi
if codesign --verify --deep --strict "$app" 2>"$tmp/cs"; then
  echo "codesign: the bundle seal is intact (ad-hoc signature, as upstream ships it)."
else
  status=1; echo "codesign: FAILED"; cat "$tmp/cs"
fi
exit $status
