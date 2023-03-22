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

#include "ec.hh"
#include "ec/ecdh.hh"
#include "x25519_radix51bit.hh"
#include <immintrin.h>

namespace alcp::ec { namespace zen4 {
#define MONT_CORE_AVX512
#include "../../ec/x25519.cc.inc"

    using namespace radix51bit;
    static inline void ConditionalSwap(__m512i&      a,
                                       __m512i&      b,
                                       const __m512i swap)
    {
        __m512i temp;

        temp = _mm512_xor_epi64(a, b);
        temp = _mm512_and_epi64(swap, temp);
        a    = _mm512_xor_epi64(a, temp);
        b    = _mm512_xor_epi64(b, temp);
    }

    static inline void MontCore(__m512i* x2, // output x2
                                __m512i* z2, // output z2
                                __m512i* x3, // output x3
                                __m512i* z3, // output z3
                                __m512i  a,  // input x
                                __m512i  b,  // input z
                                __m512i  c,  // input xp
                                __m512i  d,  // input zp
                                __m512i  basePoint512)
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

    static inline void MontLadder(Uint64       resultx[4],
                                  Uint64       resultz[4],
                                  const Uint8* pScalar,
                                  const Uint64 basePoint[4])
    {
        __m512i a = { 1, 0, 0, 0, 0, 0, 0, 0 };

        __m512i b = { 0 };
        __m512i c = { 0 };
        __m512i d = { 1, 0, 0, 0, 0, 0, 0, 0 };

        __m512i g;
        __m512i h;
        __m512i e;
        __m512i f;

        c = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(basePoint));
        __m512i  basePoint512 = c;
        unsigned i, j;

        for (i = 0; i < 32; ++i) {
            Uint8 byte = pScalar[31 - i];
            for (j = 0; j < 8; ++j) {
                const Uint64 bit = byte >> 7;

                const __m512i swap = _mm512_set1_epi64(-bit);
                ConditionalSwap(a, c, swap);
                ConditionalSwap(b, d, swap);

                MontCore(&e, &f, &g, &h, a, b, c, d, basePoint512);

                ConditionalSwap(e, g, swap);
                ConditionalSwap(f, h, swap);

                a = e;
                b = f;
                c = g;
                d = h;
                byte <<= 1;
            }
        }

        _mm512_storeu_si512(reinterpret_cast<__m512i*>(resultx), a);
        _mm512_storeu_si512(reinterpret_cast<__m512i*>(resultz), b);
    }

    // Todo remove this. This is dummy to prevent compilation warning
    static inline void FetchIntermediateMul(Int8              i,
                                            Int8              j,
                                            PrecomputedPoint& point)
    {}
#if 0
    namespace experimentalParallel {
        static void MontCore(__m512i*      x2,
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
#undef MONT_CORE_AVX512

}} // namespace alcp::ec::zen4
