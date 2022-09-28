#pragma once

#include <immintrin.h>

#include "alcp/error.h"

namespace alcp::cipher { namespace aesni {

    /* Load all keys in xmm registers */
    static inline void alcp_load_key_xmm(const __m128i* pkey128,
                                         __m128i&       key_128_0,
                                         __m128i&       key_128_1,
                                         __m128i&       key_128_2,
                                         __m128i&       key_128_3,
                                         __m128i&       key_128_4,
                                         __m128i&       key_128_5,
                                         __m128i&       key_128_6,
                                         __m128i&       key_128_7,
                                         __m128i&       key_128_8,
                                         __m128i&       key_128_9,
                                         __m128i&       key_128_10,
                                         __m128i&       key_128_11,
                                         __m128i&       key_128_12,
                                         __m128i&       key_128_13,
                                         __m128i&       key_128_14)
    {
        key_128_0  = _mm_loadu_si128(pkey128);
        key_128_1  = _mm_loadu_si128(pkey128 + 1);
        key_128_2  = _mm_loadu_si128(pkey128 + 2);
        key_128_3  = _mm_loadu_si128(pkey128 + 3);
        key_128_4  = _mm_loadu_si128(pkey128 + 4);
        key_128_5  = _mm_loadu_si128(pkey128 + 5);
        key_128_6  = _mm_loadu_si128(pkey128 + 6);
        key_128_7  = _mm_loadu_si128(pkey128 + 7);
        key_128_8  = _mm_loadu_si128(pkey128 + 8);
        key_128_9  = _mm_loadu_si128(pkey128 + 9);
        key_128_10 = _mm_loadu_si128(pkey128 + 10);
        key_128_11 = _mm_loadu_si128(pkey128 + 11);
        key_128_12 = _mm_loadu_si128(pkey128 + 12);
        key_128_13 = _mm_loadu_si128(pkey128 + 13);
        key_128_14 = _mm_loadu_si128(pkey128 + 14);
    }

    /* Encrypt */
    /* 1 x 128bit aesEnc */
    // 10 rounds
    static inline void AesEncryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesenc_si128(a, key_128_1);
        a = _mm_aesenc_si128(a, key_128_2);
        a = _mm_aesenc_si128(a, key_128_3);
        a = _mm_aesenc_si128(a, key_128_4);
        a = _mm_aesenc_si128(a, key_128_5);
        a = _mm_aesenc_si128(a, key_128_6);
        a = _mm_aesenc_si128(a, key_128_7);
        a = _mm_aesenc_si128(a, key_128_8);
        a = _mm_aesenc_si128(a, key_128_9);
        a = _mm_aesenclast_si128(a, key_128_10);
    }

    // 12 rounds
    static inline void AesEncryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i  key_128_11,
                                        __m128i  key_128_12,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesenc_si128(a, key_128_1);
        a = _mm_aesenc_si128(a, key_128_2);
        a = _mm_aesenc_si128(a, key_128_3);
        a = _mm_aesenc_si128(a, key_128_4);
        a = _mm_aesenc_si128(a, key_128_5);
        a = _mm_aesenc_si128(a, key_128_6);
        a = _mm_aesenc_si128(a, key_128_7);
        a = _mm_aesenc_si128(a, key_128_8);
        a = _mm_aesenc_si128(a, key_128_9);
        a = _mm_aesenc_si128(a, key_128_10);
        a = _mm_aesenc_si128(a, key_128_11);
        a = _mm_aesenclast_si128(a, key_128_12);
    }

    // 14 rounds
    static inline void AesEncryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i  key_128_11,
                                        __m128i  key_128_12,
                                        __m128i  key_128_13,
                                        __m128i  key_128_14,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesenc_si128(a, key_128_1);
        a = _mm_aesenc_si128(a, key_128_2);
        a = _mm_aesenc_si128(a, key_128_3);
        a = _mm_aesenc_si128(a, key_128_4);
        a = _mm_aesenc_si128(a, key_128_5);
        a = _mm_aesenc_si128(a, key_128_6);
        a = _mm_aesenc_si128(a, key_128_7);
        a = _mm_aesenc_si128(a, key_128_8);
        a = _mm_aesenc_si128(a, key_128_9);
        a = _mm_aesenc_si128(a, key_128_10);
        a = _mm_aesenc_si128(a, key_128_11);
        a = _mm_aesenc_si128(a, key_128_12);
        a = _mm_aesenc_si128(a, key_128_13);
        a = _mm_aesenclast_si128(a, key_128_14);
    }
    /* Decrypt */

    /* 1 x 128bit aesDec */
    // 10 rounds
    static inline void AesDecryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesdec_si128(a, key_128_1);
        a = _mm_aesdec_si128(a, key_128_2);
        a = _mm_aesdec_si128(a, key_128_3);
        a = _mm_aesdec_si128(a, key_128_4);
        a = _mm_aesdec_si128(a, key_128_5);
        a = _mm_aesdec_si128(a, key_128_6);
        a = _mm_aesdec_si128(a, key_128_7);
        a = _mm_aesdec_si128(a, key_128_8);
        a = _mm_aesdec_si128(a, key_128_9);
        a = _mm_aesdeclast_si128(a, key_128_10);
    }

    // 12 rounds
    static inline void AesDecryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i  key_128_11,
                                        __m128i  key_128_12,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesdec_si128(a, key_128_1);
        a = _mm_aesdec_si128(a, key_128_2);
        a = _mm_aesdec_si128(a, key_128_3);
        a = _mm_aesdec_si128(a, key_128_4);
        a = _mm_aesdec_si128(a, key_128_5);
        a = _mm_aesdec_si128(a, key_128_6);
        a = _mm_aesdec_si128(a, key_128_7);
        a = _mm_aesdec_si128(a, key_128_8);
        a = _mm_aesdec_si128(a, key_128_9);
        a = _mm_aesdec_si128(a, key_128_10);
        a = _mm_aesdec_si128(a, key_128_11);
        a = _mm_aesdeclast_si128(a, key_128_12);
    }

    // 14 rounds
    static inline void AesDecryptNoLoad(__m128i  key_128_0,
                                        __m128i  key_128_1,
                                        __m128i  key_128_2,
                                        __m128i  key_128_3,
                                        __m128i  key_128_4,
                                        __m128i  key_128_5,
                                        __m128i  key_128_6,
                                        __m128i  key_128_7,
                                        __m128i  key_128_8,
                                        __m128i  key_128_9,
                                        __m128i  key_128_10,
                                        __m128i  key_128_11,
                                        __m128i  key_128_12,
                                        __m128i  key_128_13,
                                        __m128i  key_128_14,
                                        __m128i& a)
    {
        a = _mm_xor_si128(a, key_128_0);
        a = _mm_aesdec_si128(a, key_128_1);
        a = _mm_aesdec_si128(a, key_128_2);
        a = _mm_aesdec_si128(a, key_128_3);
        a = _mm_aesdec_si128(a, key_128_4);
        a = _mm_aesdec_si128(a, key_128_5);
        a = _mm_aesdec_si128(a, key_128_6);
        a = _mm_aesdec_si128(a, key_128_7);
        a = _mm_aesdec_si128(a, key_128_8);
        a = _mm_aesdec_si128(a, key_128_9);
        a = _mm_aesdec_si128(a, key_128_10);
        a = _mm_aesdec_si128(a, key_128_11);
        a = _mm_aesdec_si128(a, key_128_12);
        a = _mm_aesdec_si128(a, key_128_13);
        a = _mm_aesdeclast_si128(a, key_128_14);
    }

}} // namespace alcp::cipher::aesni