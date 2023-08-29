
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
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys keys)

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

    static inline void AesEncryptNoLoad_2x512Rounds10(__m512i&    a,
                                                      __m512i&    b,
                                                      const sKeys keys)

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

    static inline void AesEncryptNoLoad_1x512Rounds10(__m512i&    a,
                                                      const sKeys keys)
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
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys keys)

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
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys keys)

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

/* kernel variations for certain algorithms, keysize and input block size ranges
 * in future, where other register usage is high */
#if 0 // experimental variations with load
    // reduce keys register usage
    static inline void AesEncrypt_4x512Rounds10(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);
        c    = _mm512_xor_si512(c, rkey);
        d    = _mm512_xor_si512(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
        c    = _mm512_aesenclast_epi128(c, rkey);
        d    = _mm512_aesenclast_epi128(d, rkey);
    }

    static inline void AesEncrypt_4x512Rounds12(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);
        c    = _mm512_xor_si512(c, rkey);
        d    = _mm512_xor_si512(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[11]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[12]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
        c    = _mm512_aesenclast_epi128(c, rkey);
        d    = _mm512_aesenclast_epi128(d, rkey);
    }

    static inline void AesEncrypt_4x512Rounds14(
        __m512i& a, __m512i& b, __m512i& c, __m512i& d, const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);
        c    = _mm512_xor_si512(c, rkey);
        d    = _mm512_xor_si512(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[11]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[12]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[13]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        c    = _mm512_aesenc_epi128(c, rkey);
        d    = _mm512_aesenc_epi128(d, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[14]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
        c    = _mm512_aesenclast_epi128(c, rkey);
        d    = _mm512_aesenclast_epi128(d, rkey);
    }

    static inline void AesEncrypt_2x512Rounds10(__m512i&       a,
                                                __m512i&       b,
                                                const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);
        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
    }

    static inline void AesEncrypt_2x512Rounds12(__m512i&       a,
                                                __m512i&       b,
                                                const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[11]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[12]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
    }

    static inline void AesEncrypt_2x512Rounds14(__m512i&       a,
                                                __m512i&       b,
                                                const __m128i* pKey)

    {
        __m512i rkey;
        rkey = _mm512_broadcast_i64x2(pKey[0]);
        a    = _mm512_xor_si512(a, rkey);
        b    = _mm512_xor_si512(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[1]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[2]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[3]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[4]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[5]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[6]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[7]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[8]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[9]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[10]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[11]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[12]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[13]);
        a    = _mm512_aesenc_epi128(a, rkey);
        b    = _mm512_aesenc_epi128(b, rkey);

        rkey = _mm512_broadcast_i64x2(pKey[14]);
        a    = _mm512_aesenclast_epi128(a, rkey);
        b    = _mm512_aesenclast_epi128(b, rkey);
    }
#endif

#if 0 // experimental fused gmul + aesenc

    // duplicate to be removed
    static inline void amd512xorLast128bitx(__m512i&       a,
                                            const __m128i& b_128)
    {
        // a3:a2:a1:(a0 xor b_128)
        __m512i b_512 = _mm512_zextsi128_si512(b_128);
        a             = _mm512_mask_xor_epi64(a, 3, a, b_512);
    }

    static inline void AesEncryptNoLoad_4x512Rounds10GMUL(
        __m512i&       a,
        __m512i&       b,
        __m512i&       c,
        __m512i&       d,
        const sKeys    keys,
        __m512i&       H1, // input + scratch register
        __m512i&       H2, // input + scratch register
        __m512i&       H3, // input + scratch register
        __m512i&       H4, // input + scratch register
        __m512i&       ta, // input + scratch register
        __m512i&       tb, // input + scratch register
        __m512i&       tc, // input + scratch register
        __m512i&       td, // input + scratch register
        const __m512i& reverse_mask_512,
        __m512i&       z0_512, // out
        __m512i&       z1_512, // out
        __m512i&       z2_512, // out
        const __m128i& res)

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

        // GMUL
        // reverseInput
        ta = _mm512_shuffle_epi8(ta, reverse_mask_512);
        amd512xorLast128bitx(ta, res);

        tb = _mm512_shuffle_epi8(tb, reverse_mask_512);
        tc = _mm512_shuffle_epi8(tc, reverse_mask_512);
        td = _mm512_shuffle_epi8(td, reverse_mask_512);

        __m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;

        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H4, 8); // high of H4
        at4 = _mm512_bsrli_epi128(ta, 8); // high of a

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H4);
        at4 = _mm512_xor_si512(at4, ta);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        z0_512 = _mm512_clmulepi64_epi128(H4, ta, 0x00);

        // compute x1y1
        z2_512 = _mm512_clmulepi64_epi128(H4, ta, 0x11);

        z1_512 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        //////////////////////////////////////////////////////// part 2
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H3, 8); // high of H3
        at4 = _mm512_bsrli_epi128(tb, 8); // high of b

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H3);
        at4 = _mm512_xor_si512(at4, tb);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H3, tb, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H3, tb, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

        /////////////////////////////////////////////////////////// part 3
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H2, 8); // high of H2
        at4 = _mm512_bsrli_epi128(tc, 8); // high of c

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H2);
        at4 = _mm512_xor_si512(at4, tc);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H2, tc, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H2, tc, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

        /////////////////////////////////////////////////////////// part 4
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H1, 8); // high of H2
        at4 = _mm512_bsrli_epi128(td, 8); // high of d

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H1);
        at4 = _mm512_xor_si512(at4, td);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H1, td, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H1, td, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);
    }

    static inline void AesEncryptNoLoad_4x512Rounds12GMUL(
        __m512i&       a,
        __m512i&       b,
        __m512i&       c,
        __m512i&       d,
        const sKeys    keys,
        __m512i&       H1, // input + scratch register
        __m512i&       H2, // input + scratch register
        __m512i&       H3, // input + scratch register
        __m512i&       H4, // input + scratch register
        __m512i&       ta, // input + scratch register
        __m512i&       tb, // input + scratch register
        __m512i&       tc, // input + scratch register
        __m512i&       td, // input + scratch register
        const __m512i& reverse_mask_512,
        __m512i&       z0_512, // out
        __m512i&       z1_512, // out
        __m512i&       z2_512, // out
        const __m128i& res)

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

        // GMUL
        // reverseInput
        ta = _mm512_shuffle_epi8(ta, reverse_mask_512);
        amd512xorLast128bitx(ta, res);

        tb = _mm512_shuffle_epi8(tb, reverse_mask_512);
        tc = _mm512_shuffle_epi8(tc, reverse_mask_512);
        td = _mm512_shuffle_epi8(td, reverse_mask_512);

        __m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;
        //__m512i at1, at2, at3, at4;

        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H4, 8); // high of H4
        at4 = _mm512_bsrli_epi128(ta, 8); // high of a

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H4);
        at4 = _mm512_xor_si512(at4, ta);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        z0_512 = _mm512_clmulepi64_epi128(H4, ta, 0x00);

        // compute x1y1
        z2_512 = _mm512_clmulepi64_epi128(H4, ta, 0x11);

        z1_512 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        //////////////////////////////////////////////////////// part 2
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H3, 8); // high of H3
        at4 = _mm512_bsrli_epi128(tb, 8); // high of b

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H3);
        at4 = _mm512_xor_si512(at4, tb);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H3, tb, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H3, tb, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

        /////////////////////////////////////////////////////////// part 3
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H2, 8); // high of H2
        at4 = _mm512_bsrli_epi128(tc, 8); // high of c

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H2);
        at4 = _mm512_xor_si512(at4, tc);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H2, tc, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H2, tc, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

        /////////////////////////////////////////////////////////// part 4
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H1, 8); // high of H2
        at4 = _mm512_bsrli_epi128(td, 8); // high of d

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H1);
        at4 = _mm512_xor_si512(at4, td);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H1, td, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H1, td, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);
    }

    static inline void AesEncryptNoLoad_4x512Rounds14GMUL(
        __m512i&       a,    // input + output
        __m512i&       b,    // input + output
        __m512i&       c,    // input + output
        __m512i&       d,    // input + output
        const sKeys    keys, // const key
        __m512i&       H1,   // input + scratch register
        __m512i&       H2,   // input + scratch register
        __m512i&       H3,   // input + scratch register
        __m512i&       H4,   // input + scratch register
        __m512i&       ta,   // input + scratch register
        __m512i&       tb,   // input + scratch register
        __m512i&       tc,   // input + scratch register
        __m512i&       td,   // input + scratch register
        const __m512i& reverse_mask_512,
        __m512i&       z0_512, // out
        __m512i&       z1_512, // out
        __m512i&       z2_512, // out
        const __m128i& res)

    {

        // zmm registers count
        // 14 keys + 4 Hashsubkeys + 4 input + 4 input + 3 output  = 29
        //
        //
        //

        // GMUL: reverseInput
        ta = _mm512_shuffle_epi8(ta, reverse_mask_512);
        amd512xorLast128bitx(ta, res);

        tb = _mm512_shuffle_epi8(tb, reverse_mask_512);
        tc = _mm512_shuffle_epi8(tc, reverse_mask_512);
        td = _mm512_shuffle_epi8(td, reverse_mask_512);

        // GMUL: temp registers (to be reduced)
        __m512i at1, at2, at3, at4;

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

        // GMUL: part1
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H4, 8); // high of H4
        at4 = _mm512_bsrli_epi128(ta, 8); // high of a

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H4);
        at4 = _mm512_xor_si512(at4, ta);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        z0_512 = _mm512_clmulepi64_epi128(H4, ta, 0x00);

        // compute x1y1
        z2_512 = _mm512_clmulepi64_epi128(H4, ta, 0x11);

        z1_512 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

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

        //////////////////////////////////////////////////////// part 2
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H3, 8); // high of H3
        at4 = _mm512_bsrli_epi128(tb, 8); // high of b

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H3);
        at4 = _mm512_xor_si512(at4, tb);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H3, tb, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H3, tb, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

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

        /////////////////////////////////////////////////////////// part 3
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H2, 8); // high of H2
        at4 = _mm512_bsrli_epi128(tc, 8); // high of c

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H2);
        at4 = _mm512_xor_si512(at4, tc);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H2, tc, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H2, tc, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);

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

        /////////////////////////////////////////////////////////// part 4
        // z1 compute: extract all x1 and y1
        at3 = _mm512_bsrli_epi128(H1, 8); // high of H2
        at4 = _mm512_bsrli_epi128(td, 8); // high of d

        // z1 compute: (x1+x0) and (y1+y0)
        at3 = _mm512_xor_si512(at3, H1);
        at4 = _mm512_xor_si512(at4, td);

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        at1 = _mm512_clmulepi64_epi128(H1, td, 0x00);

        // compute x1y1
        at2 = _mm512_clmulepi64_epi128(H1, td, 0x11);

        at3 = _mm512_clmulepi64_epi128(at3, at4, 0x00);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(at1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(at2, z2_512);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(at3, z1_512);
    }
#endif

    /* 2 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_2x512Rounds12(__m512i&    a,
                                                      __m512i&    b,
                                                      const sKeys keys)
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

    static inline void AesEncryptNoLoad_2x512Rounds14(__m512i&    a,
                                                      __m512i&    b,
                                                      const sKeys keys)
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

    static inline void AesEncryptNoLoad_1x512Rounds12(__m512i&    a,
                                                      const sKeys keys)
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

    static inline void AesEncryptNoLoad_1x512Rounds14(__m512i&    a,
                                                      const sKeys keys)
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
