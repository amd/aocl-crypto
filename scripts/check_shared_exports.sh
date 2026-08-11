#!/usr/bin/env bash
# Verify shared library export surfaces match documented manifests.
set -euo pipefail

BUILD_DIR="${1:?usage: check_shared_exports.sh <build-dir>}"
MANIFEST_DIR="${BUILD_DIR}/tests/export"
CACHE="${BUILD_DIR}/CMakeCache.txt"

resolve_source_dir() {
    if [[ -f "${CACHE}" ]]; then
        local dir
        dir="$(awk -F= \
            '/^(CMAKE_HOME_DIRECTORY:INTERNAL|CMAKE_SOURCE_DIR:STATIC)=/ {
                print substr($0, index($0, "=") + 1)
                exit
            }' "${CACHE}")"
        if [[ -n "${dir}" && -d "${dir}/include/alcp" ]]; then
            echo "${dir}"
            return 0
        fi
    fi

    local script_root
    script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [[ -d "${script_root}/include/alcp" ]]; then
        echo "${script_root}"
    fi
}

resolve_alcp_so() {
    local candidate
    for candidate in \
        "${BUILD_DIR}/libalcp.so" \
        "${BUILD_DIR}/libalcp_DEBUG.so" \
        "${BUILD_DIR}/lib/libalcp.so" \
        "${BUILD_DIR}/lib/libalcp_DEBUG.so"; do
        if [[ -f "${candidate}" ]]; then
            echo "${candidate}"
            return 0
        fi
    done
}

cache_bool_on() {
    local key="$1"
    [[ -f "${CACHE}" ]] && grep -q "^${key}:BOOL=ON" "${CACHE}"
}

SOURCE_DIR="$(resolve_source_dir)"
ALCP_SO="$(resolve_alcp_so)"

if [[ -z "${ALCP_SO}" ]]; then
    echo "missing libalcp.so under ${BUILD_DIR}" >&2
    exit 1
fi

if [[ -z "${SOURCE_DIR}" ]]; then
    echo "cannot locate ALCP source tree for ${BUILD_DIR}" >&2
    exit 1
fi

mkdir -p "${MANIFEST_DIR}"
MANIFEST="$(mktemp "${MANIFEST_DIR}/alcp_export_symbols.XXXXXX.txt")"
trap 'rm -f "${MANIFEST}"' EXIT
"${SOURCE_DIR}/scripts/extract_alcp_export_symbols.sh" \
    "${SOURCE_DIR}/include/alcp" > "${MANIFEST}"

if [[ ! -f "${SOURCE_DIR}/tests/export/alcp_export_cpp_exceptions.txt" ]]; then
    echo "missing ${SOURCE_DIR}/tests/export/alcp_export_cpp_exceptions.txt" >&2
    exit 1
fi
CPP_EXCEPTIONS="${SOURCE_DIR}/tests/export/alcp_export_cpp_exceptions.txt"

missing=0
checker_args=(
    --library "${ALCP_SO}"
    --c-manifest "${MANIFEST}"
    --cpp-manifest "${CPP_EXCEPTIONS}"
)
if ! cache_bool_on ALCP_HIDDEN_VISIBILITY; then
    checker_args+=(--allow-unlisted)
fi
if ! cache_bool_on ALCP_ENABLE_TESTS \
   && ! cache_bool_on ALCP_ENABLE_EXAMPLES \
   && ! cache_bool_on ALCP_ENABLE_BENCH; then
    checker_args+=(--cpp-exports-disabled)
fi
if ! "${SOURCE_DIR}/scripts/check_alcp_exports.py" "${checker_args[@]}"; then
    missing=1
fi

if cache_bool_on ENABLE_OPENSSL_COMPAT \
   && [[ -f "${BUILD_DIR}/libopenssl-compat.so" ]]; then
    OSSL_SO="${BUILD_DIR}/libopenssl-compat.so"
    ossl_nm_out="$(nm -D "${OSSL_SO}" 2>/dev/null || true)"
    if ! grep -q ' T OSSL_provider_init' <<< "${ossl_nm_out}"; then
        echo "missing OSSL_provider_init in ${OSSL_SO}" >&2
        missing=1
    fi
fi

if cache_bool_on ENABLE_IPP_COMPAT \
   && [[ -f "${BUILD_DIR}/libipp-compat.so" ]]; then
    IPP_SO="${BUILD_DIR}/libipp-compat.so"
    IPP_MANIFEST="${SOURCE_DIR}/lib/compat/ipp/ipp_compat_symbols.txt"
    if [[ ! -s "${IPP_MANIFEST}" ]]; then
        echo "empty IPP export manifest: ${IPP_MANIFEST}" >&2
        missing=1
    fi
    ipp_nm_out="$(nm -D "${IPP_SO}" 2>/dev/null || true)"
    ipp_symbol_names="$(awk '{print $3}' <<< "${ipp_nm_out}")"
    while IFS= read -r sym; do
        [[ -z "${sym}" ]] && continue
        if ! grep -Fxq "${sym}" <<< "${ipp_symbol_names}"; then
            echo "missing ipp export: ${sym}" >&2
            missing=1
        fi
    done < "${IPP_MANIFEST}"
fi

exit "${missing}"
