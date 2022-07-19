/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
#include "rng.hh"
#include <iostream>

#ifdef USE_AOCL_SRNG
#include "srng_wrapper.hh"
#endif
// Enable debug for debugging the code
// #define DEBUG

namespace alcp::rng {

alc_error_t
ArchRng::readRandom(Uint8* pBuf, Uint64 size)
{
#ifdef DEBUG
    printf("Engine amd_rdrand_bytes\n");
#endif
#ifdef USE_AOCL_SRNG
    int opt;
    opt = get_rdrand_bytes_arr(
        pBuf,
        size,
        100 // Retires is hard coded as 100, may be add this to context.
    );
    if (opt != SECRNG_SUCCESS) {
        return ALC_ERROR_NO_ENTROPY;
    } else {
        return ALC_ERROR_NONE;
    }
#else
    return ALC_ERROR_NOT_SUPPORTED; // Error not implemented
#endif
}

ArchRng::ArchRng(const alc_rng_info_t& rRngInfo) {}

void
ArchRng::finish()
{}

} // namespace alcp::rng
