#!/usr/bin/env bash
# Extract documented alcp_* symbols marked ALCP_API_EXPORT from public headers.
set -euo pipefail

HEADER_DIR="${1:?usage: extract_alcp_export_symbols.sh <include/alcp dir>}"

python3 - "$HEADER_DIR" <<'PY'
import re
import sys
from pathlib import Path

header_dir = Path(sys.argv[1])
symbols: set[str] = set()

for path in sorted(header_dir.glob("*.h")):
    text = path.read_text()
    for match in re.finditer(
        r"ALCP_API_EXPORT[^\n]*\n\s*(alcp_[a-zA-Z0-9_]+)",
        text,
    ):
        symbols.add(match.group(1))

for symbol in sorted(symbols):
    print(symbol)
PY
