#!/usr/bin/env bash
# Extract symbols marked IPP_COMPAT_EXPORT in ipp-compat .cc sources.
# Skips #if 0 blocks so disabled stubs are not listed.
set -euo pipefail

SRC_DIR="${1:?usage: extract_ipp_export_symbols.sh <lib/compat/ipp>}"

PYTHON="$(command -v python3 || true)"
if [[ -z "${PYTHON}" ]]; then
    echo "Python 3.9 or newer required for IPP export manifest generation" >&2
    exit 1
fi
if ! "${PYTHON}" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
    echo "Python 3.9 or newer required for IPP export manifest generation" >&2
    exit 1
fi

exec "${PYTHON}" "$(dirname "$0")/extract_export_symbols.py" \
    --kind ipp "${SRC_DIR}"
