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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include <cstdint>

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/error.h"

#include <immintrin.h>

namespace alcp::cipher { namespace aes {

    using namespace aesni;
    using namespace vaes;

    template<typename T>
    Uint64 ctrBlk(const T*       p_in_x,
                  T*             p_out_x,
                  Uint64         blocks,
                  Uint64         res,
                  const __m128i* pkey128,
                  Uint8*         pIv,
                  int            nRounds,
                  Uint8          factor)
    {
        T a1, a2, a3, a4;
        T b1, b2, b3, b4;
        T c1, c2, c3, c4, swap_ctr;
        T one_lo, one_x, two_x, three_x, four_x;

        ctrInit(
            &c1, pIv, &one_lo, &one_x, &two_x, &three_x, &four_x, &swap_ctr);

        Uint64 blockCount4 = 4 * factor;
        Uint64 blockCount2 = 2 * factor;
        Uint64 blockCount1 = factor;

        for (; blocks >= blockCount4; blocks -= blockCount4) {

            c2 = alcp_add_epi64(c1, one_x);
            c3 = alcp_add_epi64(c1, two_x);
            c4 = alcp_add_epi64(c1, three_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);
            a3 = alcp_loadu(p_in_x + 2);
            a4 = alcp_loadu(p_in_x + 3);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);
            b3 = alcp_shuffle_epi8(c3, swap_ctr);
            b4 = alcp_shuffle_epi8(c4, swap_ctr);

            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);
            a3 = alcp_xor(b3, a3);
            a4 = alcp_xor(b4, a4);

            // increment counter
            c1 = alcp_add_epi64(c1, four_x);

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);
            alcp_storeu(p_out_x + 2, a3);
            alcp_storeu(p_out_x + 3, a4);

            p_in_x += 4;
            p_out_x += 4;
        }

        for (; blocks >= blockCount2; blocks -= blockCount2) {
            c2 = alcp_add_epi64(c1, one_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);

            AesEncrypt(&b1, &b2, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);

            // increment counter
            c1 = alcp_add_epi64(c1, two_x);
            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);

            p_in_x += 2;
            p_out_x += 2;
        }

        for (; blocks >= blockCount1; blocks -= blockCount1) {
            a1 = alcp_loadu(p_in_x);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi64(c1, one_x);

            alcp_storeu(p_out_x, a1);

            p_in_x += 1;
            p_out_x += 1;
        }

        // residual block=1 when factor = 2, load and store only lower half.

        for (; blocks != 0; blocks--) {
            a1 = alcp_loadu_128(p_in_x);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi64(c1, one_lo);

            alcp_storeu_128(p_out_x, a1);
            p_in_x  = (T*)(((__uint128_t*)p_in_x) + 1);
            p_out_x = (T*)(((__uint128_t*)p_out_x) + 1);
        }

        if (res) {
            alcp_setzero(a1);
            std::copy((Uint8*)p_in_x, ((Uint8*)p_in_x) + res, (Uint8*)&a1);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi64(c1, one_lo);

            std::copy((Uint8*)&a1, ((Uint8*)&a1) + res, (Uint8*)p_out_x);
        }

#ifdef AES_MULTI_UPDATE
        // Store back IV
        c1 = alcp_shuffle_epi8(c1, swap_ctr);
        alcp_storeu_128(reinterpret_cast<T*>(pIv), c1);
#endif

        return blocks;
    }

}} // namespace alcp::cipher::aes
