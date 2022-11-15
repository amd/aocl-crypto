#pragma once

#include <immintrin.h>

#include "alcp/error.h"

namespace alcp::cipher { namespace vaes512 {

    static inline void alcp_load_key_zmm(const __m128i* pkey128,
                                         __m512i&       key_512_0,
                                         __m512i&       key_512_1,
                                         __m512i&       key_512_2,
                                         __m512i&       key_512_3,
                                         __m512i&       key_512_4,
                                         __m512i&       key_512_5,
                                         __m512i&       key_512_6,
                                         __m512i&       key_512_7,
                                         __m512i&       key_512_8,
                                         __m512i&       key_512_9,
                                         __m512i&       key_512_10,
                                         __m512i&       key_512_11,
                                         __m512i&       key_512_12,
                                         __m512i&       key_512_13,
                                         __m512i&       key_512_14)
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

    /*
     * AesEncrypt
     */

    /* 4 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_4x512(__m512i& a,
                                              __m512i& b,
                                              __m512i& c,
                                              __m512i& d,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenclast_epi128(a, key_512_10);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenclast_epi128(b, key_512_10);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesenc_epi128(c, key_512_1);
            c = _mm512_aesenc_epi128(c, key_512_2);
            c = _mm512_aesenc_epi128(c, key_512_3);
            c = _mm512_aesenc_epi128(c, key_512_4);
            c = _mm512_aesenc_epi128(c, key_512_5);
            c = _mm512_aesenc_epi128(c, key_512_6);
            c = _mm512_aesenc_epi128(c, key_512_7);
            c = _mm512_aesenc_epi128(c, key_512_8);
            c = _mm512_aesenc_epi128(c, key_512_9);
            c = _mm512_aesenclast_epi128(c, key_512_10);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesenc_epi128(d, key_512_1);
            d = _mm512_aesenc_epi128(d, key_512_2);
            d = _mm512_aesenc_epi128(d, key_512_3);
            d = _mm512_aesenc_epi128(d, key_512_4);
            d = _mm512_aesenc_epi128(d, key_512_5);
            d = _mm512_aesenc_epi128(d, key_512_6);
            d = _mm512_aesenc_epi128(d, key_512_7);
            d = _mm512_aesenc_epi128(d, key_512_8);
            d = _mm512_aesenc_epi128(d, key_512_9);
            d = _mm512_aesenclast_epi128(d, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenclast_epi128(a, key_512_12);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenc_epi128(b, key_512_10);
            b = _mm512_aesenc_epi128(b, key_512_11);
            b = _mm512_aesenclast_epi128(b, key_512_12);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesenc_epi128(c, key_512_1);
            c = _mm512_aesenc_epi128(c, key_512_2);
            c = _mm512_aesenc_epi128(c, key_512_3);
            c = _mm512_aesenc_epi128(c, key_512_4);
            c = _mm512_aesenc_epi128(c, key_512_5);
            c = _mm512_aesenc_epi128(c, key_512_6);
            c = _mm512_aesenc_epi128(c, key_512_7);
            c = _mm512_aesenc_epi128(c, key_512_8);
            c = _mm512_aesenc_epi128(c, key_512_9);
            c = _mm512_aesenc_epi128(c, key_512_10);
            c = _mm512_aesenc_epi128(c, key_512_11);
            c = _mm512_aesenclast_epi128(c, key_512_12);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesenc_epi128(d, key_512_1);
            d = _mm512_aesenc_epi128(d, key_512_2);
            d = _mm512_aesenc_epi128(d, key_512_3);
            d = _mm512_aesenc_epi128(d, key_512_4);
            d = _mm512_aesenc_epi128(d, key_512_5);
            d = _mm512_aesenc_epi128(d, key_512_6);
            d = _mm512_aesenc_epi128(d, key_512_7);
            d = _mm512_aesenc_epi128(d, key_512_8);
            d = _mm512_aesenc_epi128(d, key_512_9);
            d = _mm512_aesenc_epi128(d, key_512_10);
            d = _mm512_aesenc_epi128(d, key_512_11);
            d = _mm512_aesenclast_epi128(d, key_512_12);
        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenc_epi128(a, key_512_12);
            a = _mm512_aesenc_epi128(a, key_512_13);
            a = _mm512_aesenclast_epi128(a, key_512_14);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenc_epi128(b, key_512_10);
            b = _mm512_aesenc_epi128(b, key_512_11);
            b = _mm512_aesenc_epi128(b, key_512_12);
            b = _mm512_aesenc_epi128(b, key_512_13);
            b = _mm512_aesenclast_epi128(b, key_512_14);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesenc_epi128(c, key_512_1);
            c = _mm512_aesenc_epi128(c, key_512_2);
            c = _mm512_aesenc_epi128(c, key_512_3);
            c = _mm512_aesenc_epi128(c, key_512_4);
            c = _mm512_aesenc_epi128(c, key_512_5);
            c = _mm512_aesenc_epi128(c, key_512_6);
            c = _mm512_aesenc_epi128(c, key_512_7);
            c = _mm512_aesenc_epi128(c, key_512_8);
            c = _mm512_aesenc_epi128(c, key_512_9);
            c = _mm512_aesenc_epi128(c, key_512_10);
            c = _mm512_aesenc_epi128(c, key_512_11);
            c = _mm512_aesenc_epi128(c, key_512_12);
            c = _mm512_aesenc_epi128(c, key_512_13);
            c = _mm512_aesenclast_epi128(c, key_512_14);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesenc_epi128(d, key_512_1);
            d = _mm512_aesenc_epi128(d, key_512_2);
            d = _mm512_aesenc_epi128(d, key_512_3);
            d = _mm512_aesenc_epi128(d, key_512_4);
            d = _mm512_aesenc_epi128(d, key_512_5);
            d = _mm512_aesenc_epi128(d, key_512_6);
            d = _mm512_aesenc_epi128(d, key_512_7);
            d = _mm512_aesenc_epi128(d, key_512_8);
            d = _mm512_aesenc_epi128(d, key_512_9);
            d = _mm512_aesenc_epi128(d, key_512_10);
            d = _mm512_aesenc_epi128(d, key_512_11);
            d = _mm512_aesenc_epi128(d, key_512_12);
            d = _mm512_aesenc_epi128(d, key_512_13);
            d = _mm512_aesenclast_epi128(d, key_512_14);
        }
    }

    /* 2 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_2x512(__m512i& a,
                                              __m512i& b,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenclast_epi128(a, key_512_10);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenclast_epi128(b, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenclast_epi128(a, key_512_12);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenc_epi128(b, key_512_10);
            b = _mm512_aesenc_epi128(b, key_512_11);
            b = _mm512_aesenclast_epi128(b, key_512_12);

        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenc_epi128(a, key_512_12);
            a = _mm512_aesenc_epi128(a, key_512_13);
            a = _mm512_aesenclast_epi128(a, key_512_14);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesenc_epi128(b, key_512_1);
            b = _mm512_aesenc_epi128(b, key_512_2);
            b = _mm512_aesenc_epi128(b, key_512_3);
            b = _mm512_aesenc_epi128(b, key_512_4);
            b = _mm512_aesenc_epi128(b, key_512_5);
            b = _mm512_aesenc_epi128(b, key_512_6);
            b = _mm512_aesenc_epi128(b, key_512_7);
            b = _mm512_aesenc_epi128(b, key_512_8);
            b = _mm512_aesenc_epi128(b, key_512_9);
            b = _mm512_aesenc_epi128(b, key_512_10);
            b = _mm512_aesenc_epi128(b, key_512_11);
            b = _mm512_aesenc_epi128(b, key_512_12);
            b = _mm512_aesenc_epi128(b, key_512_13);
            b = _mm512_aesenclast_epi128(b, key_512_14);
        }
    }

    /* 1 x 512bit aesEnc */
    static inline void AesEncryptNoLoad_1x512(__m512i& a,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenclast_epi128(a, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenclast_epi128(a, key_512_12);
        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesenc_epi128(a, key_512_1);
            a = _mm512_aesenc_epi128(a, key_512_2);
            a = _mm512_aesenc_epi128(a, key_512_3);
            a = _mm512_aesenc_epi128(a, key_512_4);
            a = _mm512_aesenc_epi128(a, key_512_5);
            a = _mm512_aesenc_epi128(a, key_512_6);
            a = _mm512_aesenc_epi128(a, key_512_7);
            a = _mm512_aesenc_epi128(a, key_512_8);
            a = _mm512_aesenc_epi128(a, key_512_9);
            a = _mm512_aesenc_epi128(a, key_512_10);
            a = _mm512_aesenc_epi128(a, key_512_11);
            a = _mm512_aesenc_epi128(a, key_512_12);
            a = _mm512_aesenc_epi128(a, key_512_13);
            a = _mm512_aesenclast_epi128(a, key_512_14);
        }
    }

    /*
     * AesDecrypt
     */

    /* 4 x 512bit aesDec */
    static inline void AesDecryptNoLoad_4x512(__m512i& a,
                                              __m512i& b,
                                              __m512i& c,
                                              __m512i& d,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdeclast_epi128(a, key_512_10);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdeclast_epi128(b, key_512_10);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesdec_epi128(c, key_512_1);
            c = _mm512_aesdec_epi128(c, key_512_2);
            c = _mm512_aesdec_epi128(c, key_512_3);
            c = _mm512_aesdec_epi128(c, key_512_4);
            c = _mm512_aesdec_epi128(c, key_512_5);
            c = _mm512_aesdec_epi128(c, key_512_6);
            c = _mm512_aesdec_epi128(c, key_512_7);
            c = _mm512_aesdec_epi128(c, key_512_8);
            c = _mm512_aesdec_epi128(c, key_512_9);
            c = _mm512_aesdeclast_epi128(c, key_512_10);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesdec_epi128(d, key_512_1);
            d = _mm512_aesdec_epi128(d, key_512_2);
            d = _mm512_aesdec_epi128(d, key_512_3);
            d = _mm512_aesdec_epi128(d, key_512_4);
            d = _mm512_aesdec_epi128(d, key_512_5);
            d = _mm512_aesdec_epi128(d, key_512_6);
            d = _mm512_aesdec_epi128(d, key_512_7);
            d = _mm512_aesdec_epi128(d, key_512_8);
            d = _mm512_aesdec_epi128(d, key_512_9);
            d = _mm512_aesdeclast_epi128(d, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdeclast_epi128(a, key_512_12);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdec_epi128(b, key_512_10);
            b = _mm512_aesdec_epi128(b, key_512_11);
            b = _mm512_aesdeclast_epi128(b, key_512_12);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesdec_epi128(c, key_512_1);
            c = _mm512_aesdec_epi128(c, key_512_2);
            c = _mm512_aesdec_epi128(c, key_512_3);
            c = _mm512_aesdec_epi128(c, key_512_4);
            c = _mm512_aesdec_epi128(c, key_512_5);
            c = _mm512_aesdec_epi128(c, key_512_6);
            c = _mm512_aesdec_epi128(c, key_512_7);
            c = _mm512_aesdec_epi128(c, key_512_8);
            c = _mm512_aesdec_epi128(c, key_512_9);
            c = _mm512_aesdec_epi128(c, key_512_10);
            c = _mm512_aesdec_epi128(c, key_512_11);
            c = _mm512_aesdeclast_epi128(c, key_512_12);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesdec_epi128(d, key_512_1);
            d = _mm512_aesdec_epi128(d, key_512_2);
            d = _mm512_aesdec_epi128(d, key_512_3);
            d = _mm512_aesdec_epi128(d, key_512_4);
            d = _mm512_aesdec_epi128(d, key_512_5);
            d = _mm512_aesdec_epi128(d, key_512_6);
            d = _mm512_aesdec_epi128(d, key_512_7);
            d = _mm512_aesdec_epi128(d, key_512_8);
            d = _mm512_aesdec_epi128(d, key_512_9);
            d = _mm512_aesdec_epi128(d, key_512_10);
            d = _mm512_aesdec_epi128(d, key_512_11);
            d = _mm512_aesdeclast_epi128(d, key_512_12);
        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdec_epi128(a, key_512_12);
            a = _mm512_aesdec_epi128(a, key_512_13);
            a = _mm512_aesdeclast_epi128(a, key_512_14);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdec_epi128(b, key_512_10);
            b = _mm512_aesdec_epi128(b, key_512_11);
            b = _mm512_aesdec_epi128(b, key_512_12);
            b = _mm512_aesdec_epi128(b, key_512_13);
            b = _mm512_aesdeclast_epi128(b, key_512_14);

            c = _mm512_xor_si512(c, key_512_0);
            c = _mm512_aesdec_epi128(c, key_512_1);
            c = _mm512_aesdec_epi128(c, key_512_2);
            c = _mm512_aesdec_epi128(c, key_512_3);
            c = _mm512_aesdec_epi128(c, key_512_4);
            c = _mm512_aesdec_epi128(c, key_512_5);
            c = _mm512_aesdec_epi128(c, key_512_6);
            c = _mm512_aesdec_epi128(c, key_512_7);
            c = _mm512_aesdec_epi128(c, key_512_8);
            c = _mm512_aesdec_epi128(c, key_512_9);
            c = _mm512_aesdec_epi128(c, key_512_10);
            c = _mm512_aesdec_epi128(c, key_512_11);
            c = _mm512_aesdec_epi128(c, key_512_12);
            c = _mm512_aesdec_epi128(c, key_512_13);
            c = _mm512_aesdeclast_epi128(c, key_512_14);

            d = _mm512_xor_si512(d, key_512_0);
            d = _mm512_aesdec_epi128(d, key_512_1);
            d = _mm512_aesdec_epi128(d, key_512_2);
            d = _mm512_aesdec_epi128(d, key_512_3);
            d = _mm512_aesdec_epi128(d, key_512_4);
            d = _mm512_aesdec_epi128(d, key_512_5);
            d = _mm512_aesdec_epi128(d, key_512_6);
            d = _mm512_aesdec_epi128(d, key_512_7);
            d = _mm512_aesdec_epi128(d, key_512_8);
            d = _mm512_aesdec_epi128(d, key_512_9);
            d = _mm512_aesdec_epi128(d, key_512_10);
            d = _mm512_aesdec_epi128(d, key_512_11);
            d = _mm512_aesdec_epi128(d, key_512_12);
            d = _mm512_aesdec_epi128(d, key_512_13);
            d = _mm512_aesdeclast_epi128(d, key_512_14);
        }
    }

    /* 2 x 512bit aesDec */
    static inline void AesDecryptNoLoad_2x512(__m512i& a,
                                              __m512i& b,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdeclast_epi128(a, key_512_10);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdeclast_epi128(b, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdeclast_epi128(a, key_512_12);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdec_epi128(b, key_512_10);
            b = _mm512_aesdec_epi128(b, key_512_11);
            b = _mm512_aesdeclast_epi128(b, key_512_12);

        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdec_epi128(a, key_512_12);
            a = _mm512_aesdec_epi128(a, key_512_13);
            a = _mm512_aesdeclast_epi128(a, key_512_14);

            b = _mm512_xor_si512(b, key_512_0);
            b = _mm512_aesdec_epi128(b, key_512_1);
            b = _mm512_aesdec_epi128(b, key_512_2);
            b = _mm512_aesdec_epi128(b, key_512_3);
            b = _mm512_aesdec_epi128(b, key_512_4);
            b = _mm512_aesdec_epi128(b, key_512_5);
            b = _mm512_aesdec_epi128(b, key_512_6);
            b = _mm512_aesdec_epi128(b, key_512_7);
            b = _mm512_aesdec_epi128(b, key_512_8);
            b = _mm512_aesdec_epi128(b, key_512_9);
            b = _mm512_aesdec_epi128(b, key_512_10);
            b = _mm512_aesdec_epi128(b, key_512_11);
            b = _mm512_aesdec_epi128(b, key_512_12);
            b = _mm512_aesdec_epi128(b, key_512_13);
            b = _mm512_aesdeclast_epi128(b, key_512_14);
        }
    }

    /* 1 x 512bit aesDec */
    static inline void AesDecryptNoLoad_1x512(__m512i& a,
                                              __m512i  key_512_0,
                                              __m512i  key_512_1,
                                              __m512i  key_512_2,
                                              __m512i  key_512_3,
                                              __m512i  key_512_4,
                                              __m512i  key_512_5,
                                              __m512i  key_512_6,
                                              __m512i  key_512_7,
                                              __m512i  key_512_8,
                                              __m512i  key_512_9,
                                              __m512i  key_512_10,
                                              __m512i  key_512_11,
                                              __m512i  key_512_12,
                                              __m512i  key_512_13,
                                              __m512i  key_512_14,
                                              int      nRounds)
    {
        if (nRounds == 10) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdeclast_epi128(a, key_512_10);
        } else if (nRounds == 12) {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdeclast_epi128(a, key_512_12);
        } else {
            a = _mm512_xor_si512(a, key_512_0);
            a = _mm512_aesdec_epi128(a, key_512_1);
            a = _mm512_aesdec_epi128(a, key_512_2);
            a = _mm512_aesdec_epi128(a, key_512_3);
            a = _mm512_aesdec_epi128(a, key_512_4);
            a = _mm512_aesdec_epi128(a, key_512_5);
            a = _mm512_aesdec_epi128(a, key_512_6);
            a = _mm512_aesdec_epi128(a, key_512_7);
            a = _mm512_aesdec_epi128(a, key_512_8);
            a = _mm512_aesdec_epi128(a, key_512_9);
            a = _mm512_aesdec_epi128(a, key_512_10);
            a = _mm512_aesdec_epi128(a, key_512_11);
            a = _mm512_aesdec_epi128(a, key_512_12);
            a = _mm512_aesdec_epi128(a, key_512_13);
            a = _mm512_aesdeclast_epi128(a, key_512_14);
        }
    }

}} // namespace alcp::cipher::vaes512