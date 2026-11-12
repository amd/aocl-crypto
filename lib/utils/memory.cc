/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/utils/memory.hh"

#ifdef ALCP_BUILD_OS_LINUX
#include <sys/mman.h>
#else
// TODO: Windows header goes here
#endif

namespace alcp::utils {
alc_error_t
memlock(const void* mem, Uint64 size)
{
    // Workaround for sshd crash.
    // TODO: FIX by making mlock optional be a build time option.
    return ALC_ERROR_NONE;
#ifdef ALCP_BUILD_OS_LINUX
    int err = mlock(mem, size);
    if (err) {
        return ALC_ERROR_GENERIC;
    }
    return ALC_ERROR_NONE;
#else
    return ALC_ERROR_NONE; // Needs to be implemented
#endif
}

alc_error_t
memunlock(const void* mem, Uint64 size)
{
    // TODO: FIX by making munlock optional be a build time option.
    return ALC_ERROR_NONE;
#ifdef ALCP_BUILD_OS_LINUX
    int err = munlock(mem, size);
    if (err) {
        return ALC_ERROR_GENERIC;
    }
    return ALC_ERROR_NONE;
#else
    return ALC_ERROR_NONE; // Needs to be implemented
#endif
}

void
SecureClear(void* buff, Uint64 size)
{
    /* volatile so that the writes are never dead stores to the compiler */
    volatile Uint8* p = static_cast<volatile Uint8*>(buff);
    while (size--) {
        *p++ = 0;
    }
}
} // namespace alcp::utils
