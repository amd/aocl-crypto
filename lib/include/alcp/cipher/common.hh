/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/types.h"
#include "alcp/utils/copy.hh"
namespace alcp::cipher {

/**
    @brief Does an XOR operation on two array of Uint8 a and b store it to c
    @param a Input a (first input)
    @param b Input b (second input)
    @param c Output c (output of xor operation)
    @param len Entities to XOR
*/
template<typename T>
inline void
xor_a_b(const T a[], const T b[], T c[], Uint64 len)
{
    for (Uint64 j = 0; j < len; j++) {
        c[j] = b[j] ^ a[j];
    }
}

inline void
left_shift(const Uint8 in[], Uint8 out[])
{
    int i = 0;
    for (i = 0; i < 15; i++) {
        out[i] = (in[i] << 1) | ((in[i + 1] >> 7));
    }
    out[i] = in[i] << 1;
}

void inline dbl(const Uint8 in[], const Uint8 rb[], Uint8 out[])
{
    Uint8 in_leftshift[16]{};
    left_shift(in, in_leftshift);
    utils::CopyBlock(out, in_leftshift, 16);
    if (in[0] & 0x80) {
        out[15] = in_leftshift[15] ^ rb[15];
    }
}

// dbl inplace
void inline dbl(Uint8 mem[], const Uint8 rb[])
{
    Uint8 msb = mem[0];
    Uint8 in_leftshift[16]{};
    left_shift(mem, in_leftshift);
    utils::CopyBlock(mem, in_leftshift, 16);
    if (msb & 0x80) {
        mem[15] = in_leftshift[15] ^ rb[15];
    }
}
} // namespace alcp::cipher
