/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include "alcp/macros.h"
#include <secrng.h>
#include <stdio.h>

// Enable debug for debugging the code
#define DEBUG

namespace alcp::rng {
int
ArchRng::rdRandReadBytes(uint8_t* buffer, int buffersize)
{
#ifdef DEBUG
    printf("Engine amd_rdrand_bytes\n");
#endif
#if 0
    int opt = is_RDRAND_supported();
    if (opt == 0) {
        opt = -1;
    } else {
        opt = get_rdrand_bytes_arr(
            buffer,
            buffersize,
            100 // Retires is hard coded as 100, may be add this to context.
        );
        if (opt <= 0) {
            opt = -1;
        } else {
            opt = buffersize;
        }
    }
    return opt;
#else
    return -1; // Error not implemented
#endif
}
int
ArchRng::engineDefault(uint8_t* buffer, int buffersize)
{
    return rdRandReadBytes(buffer, buffersize);
}
} // namespace alcp::rng