#!/usr/bin/env bash
# Verify libalcp.so export surface (manifests regenerated from source at test time).
set -euo pipefail

BUILD_DIR="${1:?usage: run_check_shared_exports.sh <build-dir>}"
exec "$(dirname "$0")/check_shared_exports.sh" "${BUILD_DIR}"
