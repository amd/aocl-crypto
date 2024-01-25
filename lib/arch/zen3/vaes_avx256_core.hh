/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include <immintrin.h>

#include "alcp/error.h"

namespace alcp::cipher { namespace vaes {

    struct sKeys10Rounds
    {
        __m256i key_256_0;
        __m256i key_256_1;
        __m256i key_256_2;
        __m256i key_256_3;
        __m256i key_256_4;
        __m256i key_256_5;
        __m256i key_256_6;
        __m256i key_256_7;
        __m256i key_256_8;
        __m256i key_256_9;
        __m256i key_256_10;
    };

    struct sKeys12Rounds
    {
        __m256i key_256_0;
        __m256i key_256_1;
        __m256i key_256_2;
        __m256i key_256_3;
        __m256i key_256_4;
        __m256i key_256_5;
        __m256i key_256_6;
        __m256i key_256_7;
        __m256i key_256_8;
        __m256i key_256_9;
        __m256i key_256_10;
        __m256i key_256_11;
        __m256i key_256_12;
    };

    struct sKeys14Rounds
    {
        __m256i key_256_0;
        __m256i key_256_1;
        __m256i key_256_2;
        __m256i key_256_3;
        __m256i key_256_4;
        __m256i key_256_5;
        __m256i key_256_6;
        __m256i key_256_7;
        __m256i key_256_8;
        __m256i key_256_9;
        __m256i key_256_10;
        __m256i key_256_11;
        __m256i key_256_12;
        __m256i key_256_13;
        __m256i key_256_14;
    };

    struct sKeys
    {
        union
        {
            sKeys10Rounds keys10;
            sKeys12Rounds keys12;
            sKeys14Rounds keys14;
        } data;
        int numRounds;
    };

    static inline void alcp_load_key_ymm_10rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys10.key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        keys.data.keys10.key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        keys.data.keys10.key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        keys.data.keys10.key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        keys.data.keys10.key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        keys.data.keys10.key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        keys.data.keys10.key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        keys.data.keys10.key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        keys.data.keys10.key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        keys.data.keys10.key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        keys.data.keys10.key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
    }

    static inline void alcp_load_key_ymm_12rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys12.key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        keys.data.keys12.key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        keys.data.keys12.key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        keys.data.keys12.key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        keys.data.keys12.key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        keys.data.keys12.key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        keys.data.keys12.key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        keys.data.keys12.key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        keys.data.keys12.key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        keys.data.keys12.key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        keys.data.keys12.key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
        keys.data.keys12.key_256_11 = amd_mm256_broadcast_i64x2((pkey128 + 11));
        keys.data.keys12.key_256_12 = amd_mm256_broadcast_i64x2((pkey128 + 12));
    }

    static inline void alcp_load_key_ymm_14rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys14.key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        keys.data.keys14.key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        keys.data.keys14.key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        keys.data.keys14.key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        keys.data.keys14.key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        keys.data.keys14.key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        keys.data.keys14.key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        keys.data.keys14.key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        keys.data.keys14.key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        keys.data.keys14.key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        keys.data.keys14.key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
        keys.data.keys14.key_256_11 = amd_mm256_broadcast_i64x2((pkey128 + 11));
        keys.data.keys14.key_256_12 = amd_mm256_broadcast_i64x2((pkey128 + 12));
        keys.data.keys14.key_256_13 = amd_mm256_broadcast_i64x2((pkey128 + 13));
        keys.data.keys14.key_256_14 = amd_mm256_broadcast_i64x2((pkey128 + 14));
    }

    static inline void alcp_load_key_ymm(const __m128i pkey128[],
                                         __m256i&      key_256_0,
                                         __m256i&      key_256_1,
                                         __m256i&      key_256_2,
                                         __m256i&      key_256_3,
                                         __m256i&      key_256_4,
                                         __m256i&      key_256_5,
                                         __m256i&      key_256_6,
                                         __m256i&      key_256_7,
                                         __m256i&      key_256_8,
                                         __m256i&      key_256_9,
                                         __m256i&      key_256_10)
    {
        key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
    }

    static inline void alcp_load_key_ymm(const __m128i pkey128[],
                                         __m256i&      key_256_0,
                                         __m256i&      key_256_1,
                                         __m256i&      key_256_2,
                                         __m256i&      key_256_3,
                                         __m256i&      key_256_4,
                                         __m256i&      key_256_5,
                                         __m256i&      key_256_6,
                                         __m256i&      key_256_7,
                                         __m256i&      key_256_8,
                                         __m256i&      key_256_9,
                                         __m256i&      key_256_10,
                                         __m256i&      key_256_11,
                                         __m256i&      key_256_12)
    {
        key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
        key_256_11 = amd_mm256_broadcast_i64x2((pkey128 + 11));
        key_256_12 = amd_mm256_broadcast_i64x2((pkey128 + 12));
    }

    static inline void alcp_load_key_ymm(const __m128i pkey128[],
                                         __m256i&      key_256_0,
                                         __m256i&      key_256_1,
                                         __m256i&      key_256_2,
                                         __m256i&      key_256_3,
                                         __m256i&      key_256_4,
                                         __m256i&      key_256_5,
                                         __m256i&      key_256_6,
                                         __m256i&      key_256_7,
                                         __m256i&      key_256_8,
                                         __m256i&      key_256_9,
                                         __m256i&      key_256_10,
                                         __m256i&      key_256_11,
                                         __m256i&      key_256_12,
                                         __m256i&      key_256_13,
                                         __m256i&      key_256_14)
    {
        key_256_0  = amd_mm256_broadcast_i64x2(pkey128);
        key_256_1  = amd_mm256_broadcast_i64x2((pkey128 + 1));
        key_256_2  = amd_mm256_broadcast_i64x2((pkey128 + 2));
        key_256_3  = amd_mm256_broadcast_i64x2((pkey128 + 3));
        key_256_4  = amd_mm256_broadcast_i64x2((pkey128 + 4));
        key_256_5  = amd_mm256_broadcast_i64x2((pkey128 + 5));
        key_256_6  = amd_mm256_broadcast_i64x2((pkey128 + 6));
        key_256_7  = amd_mm256_broadcast_i64x2((pkey128 + 7));
        key_256_8  = amd_mm256_broadcast_i64x2((pkey128 + 8));
        key_256_9  = amd_mm256_broadcast_i64x2((pkey128 + 9));
        key_256_10 = amd_mm256_broadcast_i64x2((pkey128 + 10));
        key_256_11 = amd_mm256_broadcast_i64x2((pkey128 + 11));
        key_256_12 = amd_mm256_broadcast_i64x2((pkey128 + 12));
        key_256_13 = amd_mm256_broadcast_i64x2((pkey128 + 13));
        key_256_14 = amd_mm256_broadcast_i64x2((pkey128 + 14));
    }

    static inline void alcp_clear_keys_ymm_10rounds(sKeys& keys)
    {
        keys.data.keys10.key_256_0  = _mm256_setzero_si256();
        keys.data.keys10.key_256_1  = _mm256_setzero_si256();
        keys.data.keys10.key_256_2  = _mm256_setzero_si256();
        keys.data.keys10.key_256_3  = _mm256_setzero_si256();
        keys.data.keys10.key_256_4  = _mm256_setzero_si256();
        keys.data.keys10.key_256_5  = _mm256_setzero_si256();
        keys.data.keys10.key_256_6  = _mm256_setzero_si256();
        keys.data.keys10.key_256_7  = _mm256_setzero_si256();
        keys.data.keys10.key_256_8  = _mm256_setzero_si256();
        keys.data.keys10.key_256_9  = _mm256_setzero_si256();
        keys.data.keys10.key_256_10 = _mm256_setzero_si256();
    }

    static inline void alcp_clear_keys_ymm_12rounds(sKeys& keys)
    {
        keys.data.keys10.key_256_0  = _mm256_setzero_si256();
        keys.data.keys10.key_256_1  = _mm256_setzero_si256();
        keys.data.keys10.key_256_2  = _mm256_setzero_si256();
        keys.data.keys10.key_256_3  = _mm256_setzero_si256();
        keys.data.keys10.key_256_4  = _mm256_setzero_si256();
        keys.data.keys10.key_256_5  = _mm256_setzero_si256();
        keys.data.keys10.key_256_6  = _mm256_setzero_si256();
        keys.data.keys10.key_256_7  = _mm256_setzero_si256();
        keys.data.keys10.key_256_8  = _mm256_setzero_si256();
        keys.data.keys10.key_256_9  = _mm256_setzero_si256();
        keys.data.keys10.key_256_10 = _mm256_setzero_si256();
        keys.data.keys14.key_256_11 = _mm256_setzero_si256();
        keys.data.keys14.key_256_12 = _mm256_setzero_si256();
    }

    static inline void alcp_clear_keys_ymm_14rounds(sKeys& keys)
    {
        keys.data.keys10.key_256_0  = _mm256_setzero_si256();
        keys.data.keys10.key_256_1  = _mm256_setzero_si256();
        keys.data.keys10.key_256_2  = _mm256_setzero_si256();
        keys.data.keys10.key_256_3  = _mm256_setzero_si256();
        keys.data.keys10.key_256_4  = _mm256_setzero_si256();
        keys.data.keys10.key_256_5  = _mm256_setzero_si256();
        keys.data.keys10.key_256_6  = _mm256_setzero_si256();
        keys.data.keys10.key_256_7  = _mm256_setzero_si256();
        keys.data.keys10.key_256_8  = _mm256_setzero_si256();
        keys.data.keys10.key_256_9  = _mm256_setzero_si256();
        keys.data.keys10.key_256_10 = _mm256_setzero_si256();
        keys.data.keys14.key_256_11 = _mm256_setzero_si256();
        keys.data.keys14.key_256_12 = _mm256_setzero_si256();
        keys.data.keys14.key_256_13 = _mm256_setzero_si256();
        keys.data.keys14.key_256_14 = _mm256_setzero_si256();
    }

    /*
     * AesEncrypt
     */

    /* 4 x 256bit aesEnc */
    static inline void AesEncryptNoLoad_4x256Rounds10(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)

    {
        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        b = _mm256_xor_si256(b, keys.data.keys10.key_256_0);
        c = _mm256_xor_si256(c, keys.data.keys10.key_256_0);
        d = _mm256_xor_si256(d, keys.data.keys10.key_256_0);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_1);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_1);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_1);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_2);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_2);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_2);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_3);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_3);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_3);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_4);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_4);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_4);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_5);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_5);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_5);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_6);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_6);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_6);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_7);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_7);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_7);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_8);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_8);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_8);

        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_9);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_9);
        c = _mm256_aesenc_epi128(c, keys.data.keys10.key_256_9);
        d = _mm256_aesenc_epi128(d, keys.data.keys10.key_256_9);

        a = _mm256_aesenclast_epi128(a, keys.data.keys10.key_256_10);
        b = _mm256_aesenclast_epi128(b, keys.data.keys10.key_256_10);
        c = _mm256_aesenclast_epi128(c, keys.data.keys10.key_256_10);
        d = _mm256_aesenclast_epi128(d, keys.data.keys10.key_256_10);
    }

    static inline void AesEncryptNoLoad_2x256Rounds10(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)

    {
        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_9);
        a = _mm256_aesenclast_epi128(a, keys.data.keys10.key_256_10);

        b = _mm256_xor_si256(b, keys.data.keys10.key_256_0);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys10.key_256_9);
        b = _mm256_aesenclast_epi128(b, keys.data.keys10.key_256_10);
    }

    static inline void AesEncryptNoLoad_1x256Rounds10(__m256i&     a,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys10.key_256_9);
        a = _mm256_aesenclast_epi128(a, keys.data.keys10.key_256_10);
    }
    //} // namespace rounds10

    static inline void AesEncryptNoLoad_4x256Rounds12(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)

    {
        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesenclast_epi128(a, keys.data.keys12.key_256_12);

        b = _mm256_xor_si256(b, keys.data.keys12.key_256_0);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_9);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_10);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_11);
        b = _mm256_aesenclast_epi128(b, keys.data.keys12.key_256_12);

        c = _mm256_xor_si256(c, keys.data.keys12.key_256_0);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_1);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_2);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_3);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_4);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_5);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_6);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_7);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_8);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_9);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_10);
        c = _mm256_aesenc_epi128(c, keys.data.keys12.key_256_11);
        c = _mm256_aesenclast_epi128(c, keys.data.keys12.key_256_12);

        d = _mm256_xor_si256(d, keys.data.keys12.key_256_0);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_1);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_2);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_3);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_4);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_5);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_6);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_7);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_8);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_9);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_10);
        d = _mm256_aesenc_epi128(d, keys.data.keys12.key_256_11);
        d = _mm256_aesenclast_epi128(d, keys.data.keys12.key_256_12);
    }

    static inline void AesEncryptNoLoad_4x256Rounds14(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)

    {
        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesenclast_epi128(a, keys.data.keys14.key_256_14);

        b = _mm256_xor_si256(b, keys.data.keys14.key_256_0);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_9);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_10);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_11);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_12);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_13);
        b = _mm256_aesenclast_epi128(b, keys.data.keys14.key_256_14);

        c = _mm256_xor_si256(c, keys.data.keys14.key_256_0);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_1);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_2);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_3);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_4);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_5);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_6);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_7);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_8);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_9);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_10);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_11);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_12);
        c = _mm256_aesenc_epi128(c, keys.data.keys14.key_256_13);
        c = _mm256_aesenclast_epi128(c, keys.data.keys14.key_256_14);

        d = _mm256_xor_si256(d, keys.data.keys14.key_256_0);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_1);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_2);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_3);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_4);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_5);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_6);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_7);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_8);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_9);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_10);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_11);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_12);
        d = _mm256_aesenc_epi128(d, keys.data.keys14.key_256_13);
        d = _mm256_aesenclast_epi128(d, keys.data.keys14.key_256_14);
    }

    /* 2 x 256bit aesEnc */
    static inline void AesEncryptNoLoad_2x256Rounds12(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)
    {

        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesenclast_epi128(a, keys.data.keys12.key_256_12);

        b = _mm256_xor_si256(b, keys.data.keys12.key_256_0);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_9);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_10);
        b = _mm256_aesenc_epi128(b, keys.data.keys12.key_256_11);
        b = _mm256_aesenclast_epi128(b, keys.data.keys12.key_256_12);
    }

    static inline void AesEncryptNoLoad_2x256Rounds14(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)
    {

        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesenclast_epi128(a, keys.data.keys14.key_256_14);

        b = _mm256_xor_si256(b, keys.data.keys14.key_256_0);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_1);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_2);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_3);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_4);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_5);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_6);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_7);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_8);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_9);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_10);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_11);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_12);
        b = _mm256_aesenc_epi128(b, keys.data.keys14.key_256_13);
        b = _mm256_aesenclast_epi128(b, keys.data.keys14.key_256_14);
    }

    static inline void AesEncryptNoLoad_1x256Rounds12(__m256i&     a,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesenclast_epi128(a, keys.data.keys12.key_256_12);
    }

    static inline void AesEncryptNoLoad_1x256Rounds14(__m256i&     a,
                                                      const sKeys& keys)
    {

        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesenc_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesenclast_epi128(a, keys.data.keys14.key_256_14);
    }

    static inline void AesDecryptNoLoad_4x256Rounds10(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_9);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys10.key_256_10);

        b = _mm256_xor_si256(b, keys.data.keys10.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_9);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys10.key_256_10);

        c = _mm256_xor_si256(c, keys.data.keys10.key_256_0);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_1);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_2);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_3);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_4);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_5);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_6);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_7);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_8);
        c = _mm256_aesdec_epi128(c, keys.data.keys10.key_256_9);
        c = _mm256_aesdeclast_epi128(c, keys.data.keys10.key_256_10);

        d = _mm256_xor_si256(d, keys.data.keys10.key_256_0);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_1);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_2);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_3);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_4);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_5);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_6);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_7);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_8);
        d = _mm256_aesdec_epi128(d, keys.data.keys10.key_256_9);
        d = _mm256_aesdeclast_epi128(d, keys.data.keys10.key_256_10);
    }

    static inline void AesDecryptNoLoad_4x256Rounds12(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys12.key_256_12);

        b = _mm256_xor_si256(b, keys.data.keys12.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_9);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_10);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_11);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys12.key_256_12);

        c = _mm256_xor_si256(c, keys.data.keys12.key_256_0);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_1);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_2);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_3);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_4);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_5);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_6);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_7);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_8);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_9);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_10);
        c = _mm256_aesdec_epi128(c, keys.data.keys12.key_256_11);
        c = _mm256_aesdeclast_epi128(c, keys.data.keys12.key_256_12);

        d = _mm256_xor_si256(d, keys.data.keys12.key_256_0);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_1);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_2);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_3);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_4);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_5);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_6);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_7);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_8);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_9);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_10);
        d = _mm256_aesdec_epi128(d, keys.data.keys12.key_256_11);
        d = _mm256_aesdeclast_epi128(d, keys.data.keys12.key_256_12);
    }

    static inline void AesDecryptNoLoad_4x256Rounds14(
        __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys14.key_256_14);

        b = _mm256_xor_si256(b, keys.data.keys14.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_9);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_10);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_11);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_12);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_13);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys14.key_256_14);

        c = _mm256_xor_si256(c, keys.data.keys14.key_256_0);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_1);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_2);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_3);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_4);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_5);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_6);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_7);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_8);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_9);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_10);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_11);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_12);
        c = _mm256_aesdec_epi128(c, keys.data.keys14.key_256_13);
        c = _mm256_aesdeclast_epi128(c, keys.data.keys14.key_256_14);

        d = _mm256_xor_si256(d, keys.data.keys14.key_256_0);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_1);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_2);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_3);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_4);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_5);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_6);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_7);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_8);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_9);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_10);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_11);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_12);
        d = _mm256_aesdec_epi128(d, keys.data.keys14.key_256_13);
        d = _mm256_aesdeclast_epi128(d, keys.data.keys14.key_256_14);
    }

    /* 2 x 256bit aesDec */
    static inline void AesDecryptNoLoad_2x256Rounds10(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_9);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys10.key_256_10);

        b = _mm256_xor_si256(b, keys.data.keys10.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys10.key_256_9);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys10.key_256_10);
    }

    static inline void AesDecryptNoLoad_2x256Rounds12(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys12.key_256_12);

        b = _mm256_xor_si256(b, keys.data.keys12.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_9);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_10);
        b = _mm256_aesdec_epi128(b, keys.data.keys12.key_256_11);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys12.key_256_12);
    }

    static inline void AesDecryptNoLoad_2x256Rounds14(__m256i&     a,
                                                      __m256i&     b,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys14.key_256_14);

        b = _mm256_xor_si256(b, keys.data.keys14.key_256_0);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_1);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_2);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_3);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_4);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_5);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_6);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_7);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_8);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_9);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_10);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_11);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_12);
        b = _mm256_aesdec_epi128(b, keys.data.keys14.key_256_13);
        b = _mm256_aesdeclast_epi128(b, keys.data.keys14.key_256_14);
    }

    /* 1 x 256bit aesDec */
    static inline void AesDecryptNoLoad_1x256Rounds10(__m256i&     a,
                                                      const sKeys& keys)
    {

        a = _mm256_xor_si256(a, keys.data.keys10.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys10.key_256_9);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys10.key_256_10);
    }

    static inline void AesDecryptNoLoad_1x256Rounds12(__m256i&     a,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys12.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys12.key_256_11);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys12.key_256_12);
    }

    static inline void AesDecryptNoLoad_1x256Rounds14(__m256i&     a,
                                                      const sKeys& keys)
    {
        a = _mm256_xor_si256(a, keys.data.keys14.key_256_0);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_1);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_2);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_3);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_4);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_5);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_6);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_7);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_8);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_9);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_10);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_11);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_12);
        a = _mm256_aesdec_epi128(a, keys.data.keys14.key_256_13);
        a = _mm256_aesdeclast_epi128(a, keys.data.keys14.key_256_14);
    }

}} // namespace alcp::cipher::vaes
