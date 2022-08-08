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

#ifndef _CIPHER_AES_CTR_HH_
#define _CIPHER_AES_CTR_HH_ 2

#include <cstdint>

#include <immintrin.h>

#include "aesni.hh"
#include "alcp/error.h"
#include "cipher/aesni.hh"
#include "cipher/avx128.hh"
#include "cipher/avx128_gmul.hh"
#include "cipher/avx256.hh"
#ifdef USE_AVX512
#include "cipher/avx512.hh"
#endif
#include "cipher/vaes.hh"
#include "cipher/vaes_avx512.hh"
#include "error.hh"

namespace alcp::cipher { namespace aes {

    using namespace aesni;

    template<typename T>
    uint64_t gcmBlk(const T*       p_in_x,
                    T*             p_out_x,
                    uint64_t       blocks,
                    const __m128i* pkey128,
                    const uint8_t* pIv,
                    int            nRounds,
                    uint8_t        factor,
                    // gcm specific params
                    __m128i* pgHash_128,
                    __m128i  Hsubkey_128,
                    __m128i  iv_128,
                    __m128i  reverse_mask_128,
                    bool     isEncrypt,
                    int      remBytes)
    {
        T a1, a2, a3, a4;
        T b1, b2, b3, b4;
        T c1, c2, c3, c4, swap_ctr;
        T one_lo, one_x, two_x, three_x, four_x, eight_x;

        /* gcm init + Hash subkey init */
        gcmCryptInit(&c1,
                     iv_128,
                     &one_lo,
                     &one_x,
                     &two_x,
                     &three_x,
                     &four_x,
                     &eight_x,
                     &swap_ctr);

        __m128i Hsubkey_128_2, Hsubkey_128_3, Hsubkey_128_4;
        if (blocks >= 4) {
            gMul(Hsubkey_128, Hsubkey_128, &Hsubkey_128_2);
            gMul(Hsubkey_128_2, Hsubkey_128, &Hsubkey_128_3);
            gMul(Hsubkey_128_3, Hsubkey_128, &Hsubkey_128_4);
        }

        uint64_t blockCount4 = 4 * factor;
        uint64_t blockCount2 = 2 * factor;
        uint64_t blockCount1 = factor;

        for (; blocks >= blockCount4; blocks -= blockCount4) {
            // T ra1, ra2, ra3, ra4;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);
            a3 = alcp_loadu(p_in_x + 2);
            a4 = alcp_loadu(p_in_x + 3);

            if (isEncrypt == false) {
                gMulR(Hsubkey_128,
                      Hsubkey_128_2,
                      Hsubkey_128_3,
                      Hsubkey_128_4,
                      a4,
                      a3,
                      a2,
                      a1,
                      reverse_mask_128,
                      pgHash_128);
            }

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
            c1 = alcp_add_epi32(c1, four_x);

            if (isEncrypt == true) {
                gMulR(Hsubkey_128,
                      Hsubkey_128_2,
                      Hsubkey_128_3,
                      Hsubkey_128_4,
                      a4,
                      a3,
                      a2,
                      a1,
                      reverse_mask_128,
                      pgHash_128);
            }

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);
            alcp_storeu(p_out_x + 2, a3);
            alcp_storeu(p_out_x + 3, a4);

            p_in_x += 4;
            p_out_x += 4;
        }

        for (; blocks >= blockCount2; blocks -= blockCount2) {
            // T ra1, ra2;
            c2 = alcp_add_epi32(c1, one_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);

            if (isEncrypt == false) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
                gMulR(a2, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);

            AesEncrypt(&b1, &b2, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);

            // increment counter
            c1 = alcp_add_epi32(c1, two_x);

            if (isEncrypt == true) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
                gMulR(a2, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);

            p_in_x += 2;
            p_out_x += 2;
        }

        for (; blocks >= blockCount1; blocks -= blockCount1) {
            a1 = alcp_loadu(p_in_x);

            if (isEncrypt == false) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi32(c1, one_x);

            if (isEncrypt == true) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            alcp_storeu(p_out_x, a1);

            p_in_x += 1;
            p_out_x += 1;
        }

        // residual block=1 when factor = 2, load and store only lower half.
        for (; blocks != 0; blocks--) {
            a1 = alcp_loadu_128(p_in_x);

            if (isEncrypt == false) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi32(c1, one_lo);

            if (isEncrypt == true) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            alcp_storeu_128(p_out_x, a1);
            p_in_x  = (T*)(((__uint128_t*)p_in_x) + 1);
            p_out_x = (T*)(((__uint128_t*)p_out_x) + 1);
        }

        // remaining bytes
        if (remBytes) {
            __m128i a1; // remaining bytes handled with 128bit

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);

            const uint8_t* p_in  = reinterpret_cast<const uint8_t*>(p_in_x);
            uint8_t*       p_out = reinterpret_cast<uint8_t*>(&a1);

            int i = 0;
            for (; i < remBytes; i++) {
                p_out[i] = p_in[i];
            }
            for (; i < 16; i++) {
                p_out[i] = 0;
            }

            if (isEncrypt == false) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }

            a1 = alcp_xor(b1, a1);
            for (i = remBytes; i < 16; i++) {
                p_out[i] = 0;
            }

            uint8_t* p_store = reinterpret_cast<uint8_t*>(p_out_x);
            for (i = 0; i < remBytes; i++) {
                p_store[i] = p_out[i];
            }

            if (isEncrypt == true) {
                gMulR(a1, Hsubkey_128, reverse_mask_128, pgHash_128);
            }
        }
        return blocks;
    }

}} // namespace alcp::cipher::aes

#endif /* _CIPHER_AES_CTR_HH_ */