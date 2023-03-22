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

namespace alcp::ec { namespace zen3 {
#include "../../ec/x25519.cc.inc"

    static inline void alcp_load_conditional(__m256i& a_256,
                                             __m256i& b_256,
                                             Uint64   iswap)
    {
        const __m256i swap_256 = _mm256_set1_epi64x(-iswap);
        __m256i       x_256;

        x_256 = _mm256_xor_si256(a_256, b_256);
        x_256 = _mm256_and_si256(swap_256, x_256);
        a_256 = _mm256_xor_si256(a_256, x_256);
    }

    static inline void ConditionalSwap(__m256i&      a_256,
                                       __m256i&      b_256,
                                       const __m256i swap_256)
    {
        __m256i temp_256;

        temp_256 = _mm256_xor_si256(a_256, b_256);
        temp_256 = _mm256_and_si256(swap_256, temp_256);
        a_256    = _mm256_xor_si256(a_256, temp_256);
        b_256    = _mm256_xor_si256(b_256, temp_256);
    }

    static inline void AlcpLoadPrecomputed(__m256i&     x_256,
                                           __m256i&     y_256,
                                           __m256i&     z_256,
                                           const Uint64 point[3][4],
                                           Uint64       iswap)
    {

        __m256i pt_x_256 =
            _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[0]));
        __m256i pt_y_256 =
            _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[1]));
        __m256i pt_z_256 =
            _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[2]));

        alcp_load_conditional(x_256, pt_x_256, iswap);
        alcp_load_conditional(y_256, pt_y_256, iswap);
        alcp_load_conditional(z_256, pt_z_256, iswap);
    }

    static inline void FetchIntermediateMul(Int8              i,
                                            Int8              j,
                                            PrecomputedPoint& point)
    {

        __m256i negative_point_x_256, negative_point_y_256,
            negative_point_z_256;

        __m256i x_256 = { 1, 0, 0, 0 };
        __m256i y_256 = { 1, 0, 0, 0 };
        __m256i z_256 = { 0 };

        const int abs_j = abs(j);

        UNROLL_16
        for (Uint8 z = 0; z < 16; z++) {
            AlcpLoadPrecomputed(x_256,
                                y_256,
                                z_256,
                                &alcp::ec::cPrecomputedTable[i][z][0],
                                abs_j == z + 1);
        }

        negative_point_x_256 = y_256;
        negative_point_y_256 = x_256;

        Uint64 temp[4] = { 0 };
        SubX25519((Uint64*)&negative_point_z_256, temp, (Uint64*)&z_256);

        Uint64 iswap = ((Uint8)j >> 7);
        alcp_load_conditional(x_256, negative_point_x_256, iswap);
        alcp_load_conditional(y_256, negative_point_y_256, iswap);
        alcp_load_conditional(z_256, negative_point_z_256, iswap);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_x), x_256);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_y), y_256);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_z), z_256);
    }

    static inline void MontLadder(Uint64       resultx[4],
                                  Uint64       resultz[4],
                                  const Uint8* pScalar,
                                  const Uint64 basePoint[4])
    {
        __m256i a = { 1, 0, 0, 0 };

        __m256i b = { 0 };
        __m256i c = { 0 };
        __m256i d = { 1, 0, 0, 0 };

        __m256i g;
        __m256i h;
        __m256i e;
        __m256i f;

        c = _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(basePoint));

        unsigned i, j;

        for (i = 0; i < 32; ++i) {
            Uint8 byte = pScalar[31 - i];
            for (j = 0; j < 8; ++j) {
                const Uint64 bit = byte >> 7;

                const __m256i swap = _mm256_set1_epi64x(-bit);
                ConditionalSwap(a, c, swap);
                ConditionalSwap(b, d, swap);

                MontCore((Uint64*)&e,
                         (Uint64*)&f,
                         (Uint64*)&g,
                         (Uint64*)&h,
                         (Uint64*)&a,
                         (Uint64*)&b,
                         (Uint64*)&c,
                         (Uint64*)&d,
                         basePoint);

                ConditionalSwap(e, g, swap);
                ConditionalSwap(f, h, swap);

                a = e;
                b = f;
                c = g;
                d = h;
                byte <<= 1;
            }
        }

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(resultx), a);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(resultz), b);
    }

}} // namespace alcp::ec::zen3
