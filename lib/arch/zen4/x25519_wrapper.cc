/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include <immintrin.h>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

#include "alcp/ec/ecdh.hh"
#include "alcp/ec/ed_25519_table.hh"
#include "alcp/utils/copy.hh"
#include "x25519_radix51bit.hh"

namespace alcp::ec {
using namespace radix51bit;
/*
 * Current version supports radix51bit arithmetic kernels.
 * when radix64bit support is added, its sufficient to change the namespace. */

static inline void
ConditionalSwap(__m512i& a_512, __m512i& b_512, const __m512i swap_512)
{
    __m512i temp_512;

    temp_512 = _mm512_xor_epi64(a_512, b_512);
    temp_512 = _mm512_and_epi64(swap_512, temp_512);
    a_512    = _mm512_xor_epi64(a_512, temp_512);
    b_512    = _mm512_xor_epi64(b_512, temp_512);
}

/* Note: wrapper is with avx512 registers, when all arithmetic kernels are
 * added to avx512 typecast to Uint64* will be avoided. */

/* Compute Inverse of Z:
 * Inverse(z) = z ^ (p-2) mod p
 * p          = 2^255 - 19
 * p - 2      = 2^255 - 21
 * 2^255 - 21 = 2^5 * (2^250-1) + 11
 */
#if 0
static void
MontCore(__m512i*      x2, // output x2
         __m512i*      z2, // output z2
         __m512i*      x3, // output x3
         __m512i*      z3, // output z3
         __m512i       a,  // input x
         __m512i       b,  // input z
         __m512i       c,  // input xp
         __m512i       d,  // input zp
         __m512i       basePoint512,
         const __m512i subConst_512)
{
    __m512i t1, t2, t3, t, a2, c2, m, n, p;

    const Uint64* p64BasePoint = (Uint64*)&basePoint512;

    SumX25519((Uint64*)&t1, (Uint64*)&a, (Uint64*)&b);
    SubX25519((Uint64*)&b, (Uint64*)&a, (Uint64*)&b);

    SumX25519((Uint64*)&t2, (Uint64*)&c, (Uint64*)&d);
    SubX25519((Uint64*)&d, (Uint64*)&c, (Uint64*)&d);

    // to do: parallel mul once r*19 is reducted to 52 bits
    MulX25519((Uint64*)&m, (Uint64*)&t2, (Uint64*)&b);
    MulX25519((Uint64*)&n, (Uint64*)&t1, (Uint64*)&d);

    SumX25519((Uint64*)&t3, (Uint64*)&m, (Uint64*)&n);
    SubX25519((Uint64*)&n, (Uint64*)&m, (Uint64*)&n);

    // to do, parallel square
    SquareX25519Count((Uint64*)x3, (Uint64*)&t3, 1);
    SquareX25519Count((Uint64*)&p, (Uint64*)&n, 1);
    SquareX25519Count((Uint64*)&a2, (Uint64*)&t1, 1);
    SquareX25519Count((Uint64*)&c2, (Uint64*)&b, 1);

    MulX25519((Uint64*)z3, (Uint64*)&p, p64BasePoint);

    MulX25519((Uint64*)x2, (Uint64*)&a2, (Uint64*)&c2);
    SubX25519((Uint64*)&c2, (Uint64*)&a2, (Uint64*)&c2);

    ScalarMulX25519((Uint64*)&t, (Uint64*)&c2);

    SumX25519((Uint64*)&t, (Uint64*)&t, (Uint64*)&a2);
    MulX25519((Uint64*)z2, (Uint64*)&c2, (Uint64*)&t);
}
static void
MontLadder(__m512i*      resultx_512,
           __m512i*      resultz_512,
           const Uint8*  pScalar,
           const __m512i basePoint512)
{
    __m512i a_512 = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, 1);
    __m512i b_512 = _mm512_set1_epi64(0);
    __m512i c_512 = b_512; // 0
    __m512i d_512 = a_512; // 1

    __m512i g_512 = b_512; // 0
    __m512i h_512 = a_512; // 1
    __m512i e_512 = b_512; // 0
    __m512i f_512 = a_512; // 1

    unsigned i, j;
    c_512 = basePoint512;

    static const Uint64 constA = (((Uint64)1) << 54) - 152;
    static const Uint64 constB = (((Uint64)1) << 54) - 8;

    __m512i subConst_512 =
        _mm512_set_epi64(0, 0, 0, constB, constB, constB, constB, constA);

    for (i = 0; i < 32; ++i) {
        Uint8 byte = pScalar[31 - i];
        for (j = 0; j < 8; ++j) {
            const Uint64 bit = byte >> 7;

            const __m512i swap_512 = _mm512_set1_epi64(-bit);

            ConditionalSwap(a_512, c_512, swap_512);
            ConditionalSwap(b_512, d_512, swap_512);

            MontCore(&e_512,
                     &f_512,
                     &g_512,
                     &h_512,
                     a_512,
                     b_512,
                     c_512,
                     d_512,
                     basePoint512,
                     subConst_512);

            ConditionalSwap(e_512, g_512, swap_512);
            ConditionalSwap(f_512, h_512, swap_512);

            __m512i t_512 = a_512;
            a_512         = e_512;
            e_512         = t_512;

            // swap d,h
            t_512 = b_512;
            b_512 = f_512;
            f_512 = t_512;

            // swap a,e
            t_512 = c_512;
            c_512 = g_512;
            g_512 = t_512;

            // swap b,f
            t_512 = d_512;
            d_512 = h_512;
            h_512 = t_512;

            byte <<= 1;
        }
    }
    *resultx_512 = a_512;
    *resultz_512 = b_512;
}


namespace experimentalParallel {
static void
MontCore(__m512i*      x2,
         __m512i*      z2,
         __m512i*      x3,
         __m512i*      z3,
         __m512i       a, // x
         __m512i       b, // z
         __m512i       c, // xp
         __m512i       d, // zp
         __m512i       basePoint512,
         const __m512i subConst_512)
{
    __m512i       t, a2, c2, m, n, p;
    const Uint64* p64BasePoint = (Uint64*)&basePoint512;

    // a = a + b
    // b = a - b
    // c = c + d
    // d = c - d
    AddSubX25519(a, b, c, d, subConst_512);

    MulX25519((Uint64*)&m, (Uint64*)&c, (Uint64*)&b);
    MulX25519((Uint64*)&n, (Uint64*)&a, (Uint64*)&d);

    // m = m + n
    // n = m - n
    AddSubX25519(m, n, subConst_512);

    SquareX25519Count((Uint64*)x3, (Uint64*)&m, 1);
    SquareX25519Count((Uint64*)&p, (Uint64*)&n, 1);
    SquareX25519Count((Uint64*)&a2, (Uint64*)&a, 1);
    SquareX25519Count((Uint64*)&c2, (Uint64*)&b, 1);

    MulX25519((Uint64*)z3, (Uint64*)&p, p64BasePoint);
    MulX25519((Uint64*)x2, (Uint64*)&a2, (Uint64*)&c2);

    // c2 = a2 - c2
    SubX25519(c2, a2, c2, subConst_512);

    ScalarMulX25519((Uint64*)&t, (Uint64*)&c2, 121665);

    // t = t + a2
    AddX25519(t, t, a2);
    MulX25519((Uint64*)z2, (Uint64*)&c2, (Uint64*)&t);
}
} // namespace experimentalParallel
#endif

} // namespace alcp::ec