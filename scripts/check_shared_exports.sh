#!/usr/bin/env bash
# Verify shared library export surfaces match documented manifests.
set -euo pipefail

BUILD_DIR="${1:?usage: check_shared_exports.sh <build-dir>}"
ALCP_SO="${BUILD_DIR}/libalcp.so"
MANIFEST="${BUILD_DIR}/tests/export/alcp_export_symbols.txt"

if [[ ! -f "${ALCP_SO}" ]]; then
    echo "missing ${ALCP_SO}" >&2
    exit 1
fi

if [[ ! -f "${MANIFEST}" ]]; then
    echo "missing ${MANIFEST}" >&2
    exit 1
fi

missing=0
while IFS= read -r sym; do
    [[ -z "${sym}" ]] && continue
    if ! nm -D "${ALCP_SO}" 2>/dev/null | awk '{print $3}' | grep -Fxq "${sym}"; then
        echo "missing export: ${sym}" >&2
        missing=1
    fi
done < "${MANIFEST}"

if nm -D --defined-only "${ALCP_SO}" 2>/dev/null | grep -Eq ' T .*_Z'; then
    echo "mangled C++ symbol leaked from libalcp.so" >&2
    missing=1
fi

if [[ -f "${BUILD_DIR}/libopenssl-compat.so" ]]; then
    ENABLE_OPENSSL_COMPAT=1
fi

if [[ -f "${BUILD_DIR}/libipp-compat.so" ]]; then
    ENABLE_IPP_COMPAT=1
fi

if [[ "${ENABLE_OPENSSL_COMPAT:-0}" == "1" ]]; then
    OSSL_SO="${BUILD_DIR}/libopenssl-compat.so"
    if ! nm -D "${OSSL_SO}" 2>/dev/null | grep -q ' T OSSL_provider_init'; then
        echo "missing OSSL_provider_init in ${OSSL_SO}" >&2
        missing=1
    fi
fi

if [[ "${ENABLE_IPP_COMPAT:-0}" == "1" ]]; then
    IPP_SO="${BUILD_DIR}/libipp-compat.so"
    IPP_MANIFEST="${BUILD_DIR}/tests/export/ipp_compat_symbols.txt"
    while IFS= read -r sym; do
        [[ -z "${sym}" ]] && continue
        if ! nm -D "${IPP_SO}" 2>/dev/null | awk '{print $3}' | grep -Fxq "${sym}"; then
            echo "missing ipp export: ${sym}" >&2
            missing=1
        fi
    done < "${IPP_MANIFEST}"
fi

exit "${missing}"
