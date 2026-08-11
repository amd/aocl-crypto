#!/usr/bin/env bash
# Verify shared library export surfaces match documented manifests.
set -euo pipefail

if [[ "$#" -ne 9 ]]; then
    echo "usage: check_shared_exports.sh <source-root> <manifest-dir> <alcp-library> <openssl-enabled> <openssl-library> <ipp-enabled> <ipp-library> <hidden-enabled> <cpp-exports-enabled>" >&2
    exit 2
fi

SOURCE_DIR="$1"
MANIFEST_DIR="$2"
ALCP_SO="$3"
OPENSSL_ENABLED="$4"
OSSL_SO="$5"
IPP_ENABLED="$6"
IPP_SO="$7"
HIDDEN_ENABLED="$8"
CPP_EXPORTS_ENABLED="$9"

bool_is_on() {
    case "$1" in
        1|ON|TRUE|YES) return 0 ;;
        0|OFF|FALSE|NO) return 1 ;;
        *)
            echo "invalid boolean value: $1" >&2
            exit 2
            ;;
    esac
}

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "missing $2: $1" >&2
        exit 1
    fi
}

require_file "${SOURCE_DIR}/scripts/extract_alcp_export_symbols.sh" "manifest generator"
require_file "${SOURCE_DIR}/scripts/check_alcp_exports.py" "ALCP export checker"
require_file "${SOURCE_DIR}/tests/export/alcp_export_cpp_exceptions.txt" \
    "C++ exception manifest"
require_file "${ALCP_SO}" "enabled alcp target artifact"

mkdir -p "${MANIFEST_DIR}"
MANIFEST="$(mktemp "${MANIFEST_DIR}/alcp_export_symbols.XXXXXX.txt")"
trap 'rm -f "${MANIFEST}"' EXIT
"${SOURCE_DIR}/scripts/extract_alcp_export_symbols.sh" \
    "${SOURCE_DIR}/include/alcp" > "${MANIFEST}"

CPP_EXCEPTIONS="${SOURCE_DIR}/tests/export/alcp_export_cpp_exceptions.txt"

missing=0
checker_args=(
    --library "${ALCP_SO}"
    --c-manifest "${MANIFEST}"
    --cpp-manifest "${CPP_EXCEPTIONS}"
)
if ! bool_is_on "${HIDDEN_ENABLED}"; then
    checker_args+=(--allow-unlisted)
fi
if ! bool_is_on "${CPP_EXPORTS_ENABLED}"; then
    checker_args+=(--cpp-exports-disabled)
fi
if ! "${SOURCE_DIR}/scripts/check_alcp_exports.py" "${checker_args[@]}"; then
    missing=1
fi

if bool_is_on "${OPENSSL_ENABLED}"; then
    require_file "${OSSL_SO}" "enabled openssl-compat target artifact"
    ossl_symbol_names="$(
        nm -D --defined-only "${OSSL_SO}" | awk 'NF >= 3 { print $3 }'
    )"
    if ! grep -Fxq 'OSSL_provider_init' <<< "${ossl_symbol_names}"; then
        echo "missing OSSL_provider_init in ${OSSL_SO}" >&2
        missing=1
    fi
    if bool_is_on "${HIDDEN_ENABLED}"; then
        ossl_unexpected="$(
            grep -Fxv 'OSSL_provider_init' <<< "${ossl_symbol_names}" || true
        )"
        if [[ -n "${ossl_unexpected}" ]]; then
            while IFS= read -r sym; do
                echo "unexpected openssl-compat export: ${sym}" >&2
            done <<< "${ossl_unexpected}"
            missing=1
        fi
    fi
fi

if bool_is_on "${IPP_ENABLED}"; then
    require_file "${IPP_SO}" "enabled ipp-compat target artifact"
    IPP_MANIFEST="${SOURCE_DIR}/lib/compat/ipp/ipp_compat_symbols.txt"
    require_file "${IPP_MANIFEST}" "IPP export manifest"
    mapfile -t ipp_expected < <(
        awk 'NF && $1 !~ /^#/ { print $1 }' "${IPP_MANIFEST}"
    )
    if [[ "${#ipp_expected[@]}" -ne 73 ]]; then
        echo "IPP export manifest must contain exactly 73 symbols; found ${#ipp_expected[@]}" >&2
        exit 1
    fi
    ipp_symbol_names="$(
        nm -D --defined-only "${IPP_SO}" | awk 'NF >= 3 { print $3 }'
    )"
    for sym in "${ipp_expected[@]}"; do
        if ! grep -Fxq "${sym}" <<< "${ipp_symbol_names}"; then
            echo "missing ipp export: ${sym}" >&2
            missing=1
        fi
    done
    if bool_is_on "${HIDDEN_ENABLED}"; then
        ipp_unexpected="$(
            comm -23 \
                <(sort -u <<< "${ipp_symbol_names}") \
                <(printf '%s\n' "${ipp_expected[@]}" | sort -u)
        )"
        if [[ -n "${ipp_unexpected}" ]]; then
            while IFS= read -r sym; do
                echo "unexpected ipp-compat export: ${sym}" >&2
            done <<< "${ipp_unexpected}"
            missing=1
        fi
    fi
fi

exit "${missing}"
