#!/usr/bin/env python3
"""Turn the ClamAV logs in <out> into <out>/clamav.json for audit.py."""
import json
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])
log = (out / "clamscan.log").read_text(errors="replace") if (out / "clamscan.log").exists() else ""
fc = (out / "freshclam.log").read_text(errors="replace") if (out / "freshclam.log").exists() else ""
try:
    code = int((out / "clamscan.exit").read_text().strip())
except (OSError, ValueError):
    code = -1
known = re.search(r"Known viruses: (\d+)", log)
files = re.search(r"Scanned files: (\d+)", log)
db = re.findall(r"(daily|main|bytecode)\.c[vl]d (?:database )?is up[- ]to[- ]date \(version: (\d+)|(daily|main|bytecode)\.c[vl]d updated \(version: (\d+)", fc)
res = {
    "exit": code,  # 0 clean, 1 found, 2 error
    "infected": "; ".join(line for line in log.splitlines() if line.endswith(" FOUND")),
    "db": f"{known.group(1)} signatures" if known else "signature count unknown",
    "scanned": f"{files.group(1)} files scanned" if files else "scan count unknown",
    "error": "; ".join(line for line in (log + fc).splitlines() if "ERROR" in line)[:500],
}
(out / "clamav.json").write_text(json.dumps(res, indent=2))
print(json.dumps(res, indent=2))
_ = db
