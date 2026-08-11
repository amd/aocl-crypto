#!/usr/bin/env bash
# Extract ipps* symbols marked IPP_COMPAT_EXPORT in ipp-compat .cc sources.
# Skips #if 0 blocks so disabled stubs are not listed.
set -euo pipefail

SRC_DIR="${1:?usage: extract_ipp_export_symbols.sh <lib/compat/ipp>}"

python3 - "$SRC_DIR" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
symbols: set[str] = set()
if0_depth = 0

for path in sorted(src.rglob("*.cc")):
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if re.match(r"#if\s+0\b", stripped):
            if0_depth += 1
            continue
        if if0_depth and stripped.startswith("#endif"):
            if0_depth -= 1
            continue
        if if0_depth:
            continue
        match = re.search(r"IPP_COMPAT_EXPORT\s+(ipps[A-Za-z0-9_]+)", line)
        if match:
            symbols.add(match.group(1))

for symbol in sorted(symbols):
    print(symbol)
PY
