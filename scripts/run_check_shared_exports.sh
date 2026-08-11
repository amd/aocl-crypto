#!/usr/bin/env bash
# Forward CMake-resolved export-check inputs without inspecting its cache.
set -euo pipefail

if [[ "$#" -ne 9 ]]; then
    echo "usage: run_check_shared_exports.sh <source-root> <manifest-dir> <alcp-library> <openssl-enabled> <openssl-library> <ipp-enabled> <ipp-library> <hidden-enabled> <cpp-exports-enabled>" >&2
    exit 2
fi

exec "$(dirname "$0")/check_shared_exports.sh" "$@"
