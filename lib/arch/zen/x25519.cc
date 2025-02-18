/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/ec.hh"
#include "alcp/ec/ecdh.hh"

namespace alcp::ec { namespace zen {
#include "../../ec/x25519.cc.inc"
    static inline void LoadConditional(Uint64* a, Uint64* b, Uint64 iswap)
    {
        const Uint64 swap_64 = -iswap;
        Uint64       x;

        x  = *a ^ *b;
        x  = swap_64 & x;
        *a = *a ^ x;
    }

    static inline void LoadPrecomputed(Uint64       x[4],
                                       Uint64       y[4],
                                       Uint64       z[4],
                                       const Uint64 point[3][4],
                                       Uint64       iswap)
    {

        Uint64 pt_x[4], pt_y[4], pt_z[4];

        utils::CopyQWord(pt_x, point[0], 32);
        utils::CopyQWord(pt_y, point[1], 32);
        utils::CopyQWord(pt_z, point[2], 32);

        UNROLL_4
        for (int i = 0; i < 4; i++) {

            LoadConditional(&x[i], &pt_x[i], iswap);
            LoadConditional(&y[i], &pt_y[i], iswap);
            LoadConditional(&z[i], &pt_z[i], iswap);
        }
    }

    static inline void FetchIntermediateMul(Int8              i,
                                            Int8              j,
                                            PrecomputedPoint& point)
    {

        Uint64 negative_point_x[4], negative_point_y[4], negative_point_z[4];

        Uint64 x[4] = { 1, 0, 0, 0 };
        Uint64 y[4] = { 1, 0, 0, 0 };
        Uint64 z[4] = { 0 };

        const int abs_j = abs(j);

        UNROLL_16
        for (Uint8 k = 0; k < 16; k++) {
            LoadPrecomputed(
                x, y, z, &alcp::ec::cPrecomputedTable[i][k][0], abs_j == k + 1);
        }
        utils::CopyQWord(negative_point_x, y, 32);
        utils::CopyQWord(negative_point_y, x, 32);

        Uint64 temp[4] = { 0 };
        SubX25519((Uint64*)&negative_point_z, temp, (Uint64*)&z);

        Uint64 iswap = ((Uint8)j >> 7);

        UNROLL_4
        for (i = 0; i < 4; i++) {
            LoadConditional(&x[i], &negative_point_x[i], iswap);
            LoadConditional(&y[i], &negative_point_y[i], iswap);
            LoadConditional(&z[i], &negative_point_z[i], iswap);
        }

        utils::CopyQWord(point.m_x, x, 32);
        utils::CopyQWord(point.m_y, y, 32);
        utils::CopyQWord(point.m_z, z, 32);
    }

    static inline void ConditionalSwap(Uint64* a, Uint64* b, const Uint64 swap)
    {
        Uint64 temp;

        for (int i = 0; i < 4; i++) {
            temp = a[i] ^ b[i];
            temp = swap & temp;
            a[i] = a[i] ^ temp;
            b[i] = b[i] ^ temp;
        }
    }

    static inline void MontLadder(Uint64       resultx[4],
                                  Uint64       resultz[4],
                                  const Uint8* pScalar,
                                  const Uint64 basePoint[4])
    {
        Uint64 a[4] = { 1, 0, 0, 0 };
        Uint64 b[4] = { 0 };
        Uint64 c[4] = { 0 };
        Uint64 d[4] = { 1, 0, 0, 0 };

        Uint64 g[4];
        Uint64 h[4];
        Uint64 e[4];
        Uint64 f[4];

        utils::CopyQWord(c, basePoint, 32);

        unsigned i, j;

        for (i = 0; i < 32; ++i) {
            Uint8 byte = pScalar[31 - i];
            for (j = 0; j < 8; ++j) {
                const Uint64 bit = byte >> 7;

                const Uint64 swap = -bit;

                ConditionalSwap(a, c, swap);
                ConditionalSwap(b, d, swap);

                MontCore(e, f, g, h, a, b, c, d, basePoint);

                ConditionalSwap(e, g, swap);
                ConditionalSwap(f, h, swap);

                utils::CopyQWord(a, e, 32);
                utils::CopyQWord(b, f, 32);
                utils::CopyQWord(c, g, 32);
                utils::CopyQWord(d, h, 32);
                byte <<= 1;
            }
        }
        utils::CopyQWord(resultx, a, 32);
        utils::CopyQWord(resultz, b, 32);
    }

}} // namespace alcp::ec::zen
