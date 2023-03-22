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
#include <immintrin.h>

namespace alcp::ec { namespace avx2 {
#include "../../ec/x25519.cc.inc"
    static inline void alcp_load_conditional(__m128i& a_128,
                                             __m128i& b_128,
                                             Uint64   iswap)
    {
        const __m128i swap_128 = _mm_set1_epi64x(-iswap);
        __m128i       x_128;

        x_128 = _mm_xor_si128(a_128, b_128);
        x_128 = _mm_and_si128(swap_128, x_128);
        a_128 = _mm_xor_si128(a_128, x_128);
    }

    static inline void ConditionalSwap(__m128i&      a_128,
                                       __m128i&      b_128,
                                       const __m128i swap)
    {
        __m128i temp;
        temp  = _mm_xor_si128(a_128, b_128);
        temp  = _mm_and_si128(swap, temp);
        a_128 = _mm_xor_si128(a_128, temp);
        b_128 = _mm_xor_si128(b_128, temp);
    }

    static inline void AlcpLoadPrecomputed(__m128i&     x_128_0,
                                           __m128i&     x_128_1,
                                           __m128i&     y_128_0,
                                           __m128i&     y_128_1,
                                           __m128i&     z_128_0,
                                           __m128i&     z_128_1,
                                           const Uint64 point[3][4],
                                           Uint64       iswap)
    {

        __m128i pt_x_128_0 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[0]));
        __m128i pt_x_128_1 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[0]) + 1);

        __m128i pt_y_128_0 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[1]));

        __m128i pt_y_128_1 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[1]) + 1);

        __m128i pt_z_128_0 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[2]));

        __m128i pt_z_128_1 =
            _mm_lddqu_si128(reinterpret_cast<const __m128i*>(point[2]) + 1);

        alcp_load_conditional(x_128_0, pt_x_128_0, iswap);
        alcp_load_conditional(x_128_1, pt_x_128_1, iswap);
        alcp_load_conditional(y_128_0, pt_y_128_0, iswap);
        alcp_load_conditional(y_128_1, pt_y_128_1, iswap);
        alcp_load_conditional(z_128_0, pt_z_128_0, iswap);
        alcp_load_conditional(z_128_1, pt_z_128_1, iswap);
    }

    static inline void FetchIntermediateMul(Int8              i,
                                            Int8              j,
                                            PrecomputedPoint& point)
    {

        __m128i negative_point_x_128[2], negative_point_y_128[2],
            negative_point_z_128[2];

        __m128i x_128[2] = { 1, 0, 0, 0 };
        __m128i y_128[2] = { 1, 0, 0, 0 };

        __m128i z_128[2] = { 0 };

        const int abs_j = abs(j);

        UNROLL_16
        for (Uint8 z = 0; z < 16; z++) {
            AlcpLoadPrecomputed(x_128[0],
                                x_128[1],
                                y_128[0],
                                y_128[1],
                                z_128[0],
                                z_128[1],
                                &alcp::ec::cPrecomputedTable[i][z][0],
                                abs_j == z + 1);
        }

        negative_point_x_128[0] = x_128[0];
        negative_point_x_128[1] = x_128[1];
        negative_point_y_128[0] = y_128[0];
        negative_point_y_128[1] = y_128[1];

        Uint64 temp[4] = { 0 };
        SubX25519((Uint64*)&negative_point_z_128, temp, (Uint64*)&z_128);

        Uint64 iswap = ((Uint8)j >> 7);
        alcp_load_conditional(x_128[0], negative_point_x_128[0], iswap);
        alcp_load_conditional(x_128[1], negative_point_x_128[1], iswap);
        alcp_load_conditional(y_128[0], negative_point_y_128[0], iswap);
        alcp_load_conditional(y_128[1], negative_point_y_128[1], iswap);
        alcp_load_conditional(z_128[0], negative_point_z_128[0], iswap);
        alcp_load_conditional(z_128[1], negative_point_z_128[1], iswap);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_x), x_128[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_x) + 1, x_128[1]);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_y), y_128[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_y) + 1, y_128[1]);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_z), z_128[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(point.m_z) + 1, z_128[1]);
    }

    static inline void MontLadder(Uint64       resultx[4],
                                  Uint64       resultz[4],
                                  const Uint8* pScalar,
                                  const Uint64 basePoint[4])
    {
        __m128i a[2] = { 1, 0, 0, 0 };
        __m128i b[2] = { 0 };
        __m128i c[2] = { 0 };
        __m128i d[2] = { 1, 0, 0, 0 };

        __m128i g[2] = { 0 };
        __m128i h[2] = { 1, 0, 0, 0 };
        __m128i e[2] = { 0 };
        __m128i f[2] = { 1, 0, 0, 0 };

        c[0] = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(basePoint));
        c[1] = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(basePoint) + 1);

        unsigned i, j;

        for (i = 0; i < 32; ++i) {
            Uint8 byte = pScalar[31 - i];
            for (j = 0; j < 8; ++j) {
                const Uint64 bit = byte >> 7;

                const __m128i swap = _mm_set1_epi64x(-bit);

                ConditionalSwap(a[0], c[0], swap);
                ConditionalSwap(a[1], c[1], swap);
                ConditionalSwap(b[0], d[0], swap);
                ConditionalSwap(b[1], d[1], swap);

                MontCore((Uint64*)e,
                         (Uint64*)f,
                         (Uint64*)g,
                         (Uint64*)h,
                         (Uint64*)a,
                         (Uint64*)b,
                         (Uint64*)c,
                         (Uint64*)d,
                         basePoint);

                ConditionalSwap(e[0], g[0], swap);
                ConditionalSwap(e[1], g[1], swap);
                ConditionalSwap(f[0], h[0], swap);
                ConditionalSwap(f[1], h[1], swap);

                a[0] = e[0];
                a[1] = e[1];
                b[0] = f[0];
                b[1] = f[1];
                c[0] = g[0];
                c[1] = g[1];
                d[0] = h[0];
                d[1] = h[1];
                byte <<= 1;
            }
        }

        _mm_storeu_si128(reinterpret_cast<__m128i*>(resultx), a[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(resultx) + 1, a[1]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(resultz), b[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(resultz) + 1, b[1]);
    }

}} // namespace alcp::ec::avx2
