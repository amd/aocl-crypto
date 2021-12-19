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

#ifndef _CIPHER_VAES_HH
#define _CIPHER_VAES_HH 2

#pragma GCC target("aes,sse2,avx,avx2,vaes,fma")
#include <immintrin.h>

#include "alcp/error.h"

namespace alcp::cipher { namespace vaes {
    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    static inline __m256i amd_mm256_broadcast_i64x2(const __m128i* rKey)
    {
        const uint64_t* key64 = (const uint64_t*)rKey;
        return _mm256_set_epi64x(key64[1], key64[0], key64[1], key64[0]);
    }

    /* One block at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  const __m128i* rKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);

        rKey0 = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);
            b0    = _mm256_aesenc_epi128(b0, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
        }

        b0    = _mm256_aesenc_epi128(b0, rKey1);
        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* Two blocks at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  const __m128i* rKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* Three blocks at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  const __m128i* rKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);
        b2 = _mm256_aesenc_epi128(b2, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    /* 4 blocks at a time */
    static inline void AESEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  __m256i*       blk3,
                                  const __m128i* rKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);
        __m256i rKey1 = amd_mm256_broadcast_i64x2(&rKey[1]);

        __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
        __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
        rKey0      = amd_mm256_broadcast_i64x2(&rKey[2]);

        for (nr = 1, rKey++; nr < nRounds; nr += 2, rKey += 2) {
            b0    = _mm256_aesenc_epi128(b0, rKey1);
            b1    = _mm256_aesenc_epi128(b1, rKey1);
            b2    = _mm256_aesenc_epi128(b2, rKey1);
            b3    = _mm256_aesenc_epi128(b3, rKey1);
            rKey1 = amd_mm256_broadcast_i64x2(&rKey[2]);

            b0    = _mm256_aesenc_epi128(b0, rKey0);
            b1    = _mm256_aesenc_epi128(b1, rKey0);
            b2    = _mm256_aesenc_epi128(b2, rKey0);
            b3    = _mm256_aesenc_epi128(b3, rKey0);
            rKey0 = amd_mm256_broadcast_i64x2(&rKey[3]);
        }

        b0 = _mm256_aesenc_epi128(b0, rKey1);
        b1 = _mm256_aesenc_epi128(b1, rKey1);
        b2 = _mm256_aesenc_epi128(b2, rKey1);
        b3 = _mm256_aesenc_epi128(b3, rKey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rKey0);
        *blk3 = _mm256_aesenclast_epi128(b3, rKey0);

        rKey0 = _mm256_setzero_si256();
        rKey1 = _mm256_setzero_si256();
    }

    namespace experimantal {
        static inline void AESEncrypt(__m256i*       blk0,
                                      __m256i*       blk1,
                                      __m256i*       blk2,
                                      __m256i*       blk3,
                                      const __m128i* rKey, /* Round keys */
                                      int            nRounds)
        {
            int nr;

            __m256i rKey0 = amd_mm256_broadcast_i64x2(&rKey[0]);

            __m256i b0 = _mm256_xor_si256(*blk0, rKey0);
            __m256i b1 = _mm256_xor_si256(*blk1, rKey0);
            __m256i b2 = _mm256_xor_si256(*blk2, rKey0);
            __m256i b3 = _mm256_xor_si256(*blk3, rKey0);
            rKey0      = amd_mm256_broadcast_i64x2(&rKey[1]);

            for (nr = 1, rKey++; nr < nRounds; nr++, rKey++) {
                b0    = _mm256_aesenc_epi128(b0, rKey0);
                b1    = _mm256_aesenc_epi128(b1, rKey0);
                b2    = _mm256_aesenc_epi128(b2, rKey0);
                b3    = _mm256_aesenc_epi128(b3, rKey0);
                rKey0 = amd_mm256_broadcast_i64x2(&rKey[2]);
            }

            *blk0 = _mm256_aesenclast_epi128(b0, rKey0);
            *blk1 = _mm256_aesenclast_epi128(b1, rKey0);
            *blk2 = _mm256_aesenclast_epi128(b2, rKey0);
            *blk3 = _mm256_aesenclast_epi128(b3, rKey0);

            rKey0 = _mm256_setzero_si256();
        }
    } // namespace experimantal
}}    // namespace alcp::cipher::vaes

#endif /* _CIPHER_VAES_HH */
