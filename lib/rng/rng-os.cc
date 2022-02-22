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

#include "error.hh"
#include "rng.hh"
#include <iostream>
#ifndef WIN32
#include <sys/random.h>
#endif

// Enable debug for debugging the code
// #define DEBUG

namespace alcp::rng {
int
OsRng::randomRead(uint8_t* buffer, int buffersize)
{
#ifdef DEBUG
    printf("Engine linux_urandom64\n");
#endif
    // Linux Systemcall to get random values.
    int out = getrandom(buffer, buffersize, 0);
    return out;
}
int
OsRng::urandomRead(uint8_t* buffer, int buffersize)
{
#ifdef DEBUG
    printf("Engine linux_random64\n");
#endif
    // Linux Systemcall to get random values.
    int out = getrandom(buffer, buffersize, GRND_RANDOM);
    return out;
}
int
OsRng::engineDefault(uint8_t* buffer, int buffersize)
{
    return urandomRead(buffer, buffersize);
}
} // namespace alcp::rng
