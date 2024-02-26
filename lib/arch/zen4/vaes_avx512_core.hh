/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

namespace alcp::cipher { namespace vaes512 {

    struct sKeys10Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
    };

    struct sKeys12Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
        __m512i key_512_11;
        __m512i key_512_12;
    };

    struct sKeys14Rounds
    {
        __m512i key_512_0;
        __m512i key_512_1;
        __m512i key_512_2;
        __m512i key_512_3;
        __m512i key_512_4;
        __m512i key_512_5;
        __m512i key_512_6;
        __m512i key_512_7;
        __m512i key_512_8;
        __m512i key_512_9;
        __m512i key_512_10;
        __m512i key_512_11;
        __m512i key_512_12;
        __m512i key_512_13;
        __m512i key_512_14;
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

    static inline void alcp_load_key_zmm_10rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys10.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys10.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys10.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys10.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys10.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys10.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys10.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys10.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys10.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys10.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys10.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
    }

    static inline void alcp_load_key_zmm_12rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys12.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys12.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys12.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys12.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys12.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys12.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys12.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys12.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys12.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys12.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys12.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        keys.data.keys12.key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        keys.data.keys12.key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
    }

    static inline void alcp_load_key_zmm_14rounds(const __m128i pkey128[],
                                                  sKeys&        keys)
    {

        keys.data.keys14.key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        keys.data.keys14.key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        keys.data.keys14.key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        keys.data.keys14.key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        keys.data.keys14.key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        keys.data.keys14.key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        keys.data.keys14.key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        keys.data.keys14.key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        keys.data.keys14.key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        keys.data.keys14.key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        keys.data.keys14.key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        keys.data.keys14.key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        keys.data.keys14.key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
        keys.data.keys14.key_512_13 = _mm512_broadcast_i64x2(*(pkey128 + 13));
        keys.data.keys14.key_512_14 = _mm512_broadcast_i64x2(*(pkey128 + 14));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10,
                                         __m512i&      key_512_11,
                                         __m512i&      key_512_12)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
    }

    static inline void alcp_load_key_zmm(const __m128i pkey128[],
                                         __m512i&      key_512_0,
                                         __m512i&      key_512_1,
                                         __m512i&      key_512_2,
                                         __m512i&      key_512_3,
                                         __m512i&      key_512_4,
                                         __m512i&      key_512_5,
                                         __m512i&      key_512_6,
                                         __m512i&      key_512_7,
                                         __m512i&      key_512_8,
                                         __m512i&      key_512_9,
                                         __m512i&      key_512_10,
                                         __m512i&      key_512_11,
                                         __m512i&      key_512_12,
                                         __m512i&      key_512_13,
                                         __m512i&      key_512_14)
    {
        key_512_0  = _mm512_broadcast_i64x2(*pkey128);
        key_512_1  = _mm512_broadcast_i64x2(*(pkey128 + 1));
        key_512_2  = _mm512_broadcast_i64x2(*(pkey128 + 2));
        key_512_3  = _mm512_broadcast_i64x2(*(pkey128 + 3));
        key_512_4  = _mm512_broadcast_i64x2(*(pkey128 + 4));
        key_512_5  = _mm512_broadcast_i64x2(*(pkey128 + 5));
        key_512_6  = _mm512_broadcast_i64x2(*(pkey128 + 6));
        key_512_7  = _mm512_broadcast_i64x2(*(pkey128 + 7));
        key_512_8  = _mm512_broadcast_i64x2(*(pkey128 + 8));
        key_512_9  = _mm512_broadcast_i64x2(*(pkey128 + 9));
        key_512_10 = _mm512_broadcast_i64x2(*(pkey128 + 10));
        key_512_11 = _mm512_broadcast_i64x2(*(pkey128 + 11));
        key_512_12 = _mm512_broadcast_i64x2(*(pkey128 + 12));
        key_512_13 = _mm512_broadcast_i64x2(*(pkey128 + 13));
        key_512_14 = _mm512_broadcast_i64x2(*(pkey128 + 14));
    }

    static inline void alcp_clear_keys_zmm_10rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
    }

    static inline void alcp_clear_keys_zmm_12rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
        keys.data.keys14.key_512_11 = _mm512_setzero_si512();
        keys.data.keys14.key_512_12 = _mm512_setzero_si512();
    }

    static inline void alcp_clear_keys_zmm_14rounds(sKeys& keys)
    {
        keys.data.keys10.key_512_0  = _mm512_setzero_si512();
        keys.data.keys10.key_512_1  = _mm512_setzero_si512();
        keys.data.keys10.key_512_2  = _mm512_setzero_si512();
        keys.data.keys10.key_512_3  = _mm512_setzero_si512();
        keys.data.keys10.key_512_4  = _mm512_setzero_si512();
        keys.data.keys10.key_512_5  = _mm512_setzero_si512();
        keys.data.keys10.key_512_6  = _mm512_setzero_si512();
        keys.data.keys10.key_512_7  = _mm512_setzero_si512();
        keys.data.keys10.key_512_8  = _mm512_setzero_si512();
        keys.data.keys10.key_512_9  = _mm512_setzero_si512();
        keys.data.keys10.key_512_10 = _mm512_setzero_si512();
        keys.data.keys14.key_512_11 = _mm512_setzero_si512();
        keys.data.keys14.key_512_12 = _mm512_setzero_si512();
        keys.data.keys14.key_512_13 = _mm512_setzero_si512();
        keys.data.keys14.key_512_14 = _mm512_setzero_si512();
    }

    /*
     * AesEncrypt
     */

    /* 4 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_4x512Rounds10(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        c = _mm512_xor_si512(c, keys.data.keys10.key_512_0);
        d = _mm512_xor_si512(d, keys.data.keys10.key_512_0);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_1);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_1);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_1);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_2);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_2);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_2);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_3);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_3);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_3);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_4);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_4);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_4);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_5);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_5);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_5);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_6);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_6);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_6);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_7);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_7);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_7);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_8);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_8);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_8);

        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_9);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_9);
        c = _mm512_aesenc_epi128(c, keys.data.keys10.key_512_9);
        d = _mm512_aesenc_epi128(d, keys.data.keys10.key_512_9);

        a = _mm512_aesenclast_epi128(a, keys.data.keys10.key_512_10);
        b = _mm512_aesenclast_epi128(b, keys.data.keys10.key_512_10);
        c = _mm512_aesenclast_epi128(c, keys.data.keys10.key_512_10);
        d = _mm512_aesenclast_epi128(d, keys.data.keys10.key_512_10);
    }

    static inline void AesEncryptNoLoad_2x512Rounds10(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)

    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesenclast_epi128(a, keys.data.keys10.key_512_10);

        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys10.key_512_9);
        b = _mm512_aesenclast_epi128(b, keys.data.keys10.key_512_10);
    }

    static inline void AesEncryptNoLoad_1x512Rounds10(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesenclast_epi128(a, keys.data.keys10.key_512_10);
    }
    //} // namespace rounds10

    static inline void AesEncryptNoLoad_4x512Rounds12(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesenclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesenclast_epi128(b, keys.data.keys12.key_512_12);

        c = _mm512_xor_si512(c, keys.data.keys12.key_512_0);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_1);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_2);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_3);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_4);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_5);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_6);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_7);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_8);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_9);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_10);
        c = _mm512_aesenc_epi128(c, keys.data.keys12.key_512_11);
        c = _mm512_aesenclast_epi128(c, keys.data.keys12.key_512_12);

        d = _mm512_xor_si512(d, keys.data.keys12.key_512_0);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_1);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_2);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_3);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_4);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_5);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_6);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_7);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_8);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_9);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_10);
        d = _mm512_aesenc_epi128(d, keys.data.keys12.key_512_11);
        d = _mm512_aesenclast_epi128(d, keys.data.keys12.key_512_12);
    }

    static inline void AesEncryptNoLoad_4x512Rounds14(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)

    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesenclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesenclast_epi128(b, keys.data.keys14.key_512_14);

        c = _mm512_xor_si512(c, keys.data.keys14.key_512_0);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_1);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_2);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_3);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_4);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_5);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_6);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_7);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_8);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_9);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_10);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_11);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_12);
        c = _mm512_aesenc_epi128(c, keys.data.keys14.key_512_13);
        c = _mm512_aesenclast_epi128(c, keys.data.keys14.key_512_14);

        d = _mm512_xor_si512(d, keys.data.keys14.key_512_0);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_1);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_2);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_3);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_4);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_5);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_6);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_7);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_8);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_9);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_10);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_11);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_12);
        d = _mm512_aesenc_epi128(d, keys.data.keys14.key_512_13);
        d = _mm512_aesenclast_epi128(d, keys.data.keys14.key_512_14);
    }

    /* 2 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_2x512Rounds12(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {

        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesenclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesenc_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesenclast_epi128(b, keys.data.keys12.key_512_12);
    }

    static inline void AesEncryptNoLoad_2x512Rounds14(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {

        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesenclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesenc_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesenclast_epi128(b, keys.data.keys14.key_512_14);
    }

    static inline void AesEncryptNoLoad_1x512Rounds12(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesenclast_epi128(a, keys.data.keys12.key_512_12);
    }

    static inline void AesEncryptNoLoad_1x512Rounds14(__m512i&     a,
                                                      const sKeys& keys)
    {

        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesenc_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesenclast_epi128(a, keys.data.keys14.key_512_14);
    }

    static inline void AesDecryptNoLoad_4x512Rounds10(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);

        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_9);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys10.key_512_10);

        c = _mm512_xor_si512(c, keys.data.keys10.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys10.key_512_9);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys10.key_512_10);

        d = _mm512_xor_si512(d, keys.data.keys10.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys10.key_512_9);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_4x512Rounds12(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys12.key_512_12);

        c = _mm512_xor_si512(c, keys.data.keys12.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_9);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_10);
        c = _mm512_aesdec_epi128(c, keys.data.keys12.key_512_11);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys12.key_512_12);

        d = _mm512_xor_si512(d, keys.data.keys12.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_9);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_10);
        d = _mm512_aesdec_epi128(d, keys.data.keys12.key_512_11);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_4x512Rounds14(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys14.key_512_14);

        c = _mm512_xor_si512(c, keys.data.keys14.key_512_0);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_1);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_2);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_3);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_4);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_5);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_6);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_7);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_8);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_9);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_10);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_11);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_12);
        c = _mm512_aesdec_epi128(c, keys.data.keys14.key_512_13);
        c = _mm512_aesdeclast_epi128(c, keys.data.keys14.key_512_14);

        d = _mm512_xor_si512(d, keys.data.keys14.key_512_0);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_1);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_2);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_3);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_4);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_5);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_6);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_7);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_8);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_9);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_10);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_11);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_12);
        d = _mm512_aesdec_epi128(d, keys.data.keys14.key_512_13);
        d = _mm512_aesdeclast_epi128(d, keys.data.keys14.key_512_14);
    }

    /* 2 x 512bit aesDec */
    static inline void AesDecryptNoLoad_2x512Rounds10(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);

        b = _mm512_xor_si512(b, keys.data.keys10.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys10.key_512_9);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_2x512Rounds12(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);

        b = _mm512_xor_si512(b, keys.data.keys12.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys12.key_512_11);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_2x512Rounds14(__m512i&     a,
                                                      __m512i&     b,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);

        b = _mm512_xor_si512(b, keys.data.keys14.key_512_0);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_1);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_2);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_3);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_4);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_5);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_6);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_7);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_8);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_9);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_10);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_11);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_12);
        b = _mm512_aesdec_epi128(b, keys.data.keys14.key_512_13);
        b = _mm512_aesdeclast_epi128(b, keys.data.keys14.key_512_14);
    }

    /* 1 x 512bit aesDec */
    static inline void AesDecryptNoLoad_1x512Rounds10(__m512i&     a,
                                                      const sKeys& keys)
    {

        a = _mm512_xor_si512(a, keys.data.keys10.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys10.key_512_9);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys10.key_512_10);
    }

    static inline void AesDecryptNoLoad_1x512Rounds12(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys12.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys12.key_512_11);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys12.key_512_12);
    }

    static inline void AesDecryptNoLoad_1x512Rounds14(__m512i&     a,
                                                      const sKeys& keys)
    {
        a = _mm512_xor_si512(a, keys.data.keys14.key_512_0);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_1);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_2);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_3);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_4);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_5);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_6);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_7);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_8);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_9);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_10);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_11);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_12);
        a = _mm512_aesdec_epi128(a, keys.data.keys14.key_512_13);
        a = _mm512_aesdeclast_epi128(a, keys.data.keys14.key_512_14);
    }

}} // namespace alcp::cipher::vaes512
