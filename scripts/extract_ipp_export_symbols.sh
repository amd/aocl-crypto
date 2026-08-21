#!/usr/bin/env bash
# Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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
