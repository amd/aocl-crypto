#!/usr/bin/env bash
# Extract documented alcp_* symbols marked ALCP_API_EXPORT from public headers.
set -euo pipefail

HEADER_DIR="${1:?usage: extract_alcp_export_symbols.sh <include/alcp dir>}"

PYTHON="$(command -v python3 || true)"
if [[ -z "${PYTHON}" ]]; then
    echo "Python 3.9 or newer required for export manifest generation" >&2
    exit 1
fi
if ! "${PYTHON}" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
    echo "Python 3.9 or newer required for export manifest generation" >&2
    exit 1
fi

exec "${PYTHON}" "$(dirname "$0")/extract_export_symbols.py" \
    --kind alcp "${HEADER_DIR}"
