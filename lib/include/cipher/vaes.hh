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

#include <immintrin.h>

#include "alcp/error.h"

namespace alcp::cipher { namespace vaes {

    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey,
                           int            nRounds);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCbc(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptCfb(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    // ctr APIs for vaes
    void ctrInit(__m256i*       c1,
                 const uint8_t* pIv,
                 __m256i*       onelo,
                 __m256i*       one_x,
                 __m256i*       two_x,
                 __m256i*       three_x,
                 __m256i*       four_x,
                 __m256i*       eight_x,
                 __m256i*       swap_ctr);

    uint64_t ctrProcess(const __m256i* p_in_x,
                        __m256i*       p_out_x,
                        uint64_t       blocks,
                        const __m128i* pkey128,
                        const uint8_t* pIv,
                        int            nRounds);

    void gMulR(__m512i  H1,
               __m512i  H2,
               __m512i  H3,
               __m512i  H4,
               __m512i  a,
               __m512i  b,
               __m512i  c,
               __m512i  d,
               __m512i  reverse_mask_512,
               __m128i* res);

    void gMulR(__m512i  H1,
               __m512i  H2,
               __m512i  H3,
               __m512i  H4,
               __m512i  H5,
               __m512i  H6,
               __m512i  a,
               __m512i  b,
               __m512i  c,
               __m512i  d,
               __m512i  e,
               __m512i  f,
               __m512i  reverse_mask_512,
               __m128i* res);

    void gMulR(__m512i  H_512,
               __m512i  abcd_512,
               __m512i  reverse_mask_512,
               __m128i* res);

    alc_error_t CryptGcm(const uint8_t* pPlainText,
                         uint8_t*       pCipherText,
                         uint64_t       len,
                         const uint8_t* pKey,
                         int            nRounds,
                         const uint8_t* pIv,
                         __m128i*       pgHash,
                         __m128i        Hsubkey_128,
                         __m128i        iv_128,
                         __m128i        reverse_mask_128,
                         bool           isEncrypt);

    static inline void amd_mm256_broadcast_i64x2(const __m128i* rKey,
                                                 __m256i*       dst)
    {
        const uint64_t* key64 = (const uint64_t*)rKey;
        *dst = _mm256_set_epi64x(key64[1], key64[0], key64[1], key64[0]);
    }

    // Encrypt Begins here
    /* 1 x 2 block at a time */
    static inline void AesEncrypt(__m256i*       blk0,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesenc_epi128(b0, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);
            b0 = _mm256_aesenc_epi128(b0, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0    = _mm256_aesenc_epi128(b0, rkey1);
        *blk0 = _mm256_aesenclast_epi128(b0, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 2 x 2 blocks at a time */
    static inline void AesEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesenc_epi128(b0, rkey1);
            b1 = _mm256_aesenc_epi128(b1, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesenc_epi128(b0, rkey0);
            b1 = _mm256_aesenc_epi128(b1, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesenc_epi128(b0, rkey1);
        b1 = _mm256_aesenc_epi128(b1, rkey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 3 x 2 blocks at a time */
    static inline void AesEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey0);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesenc_epi128(b0, rkey1);
            b1 = _mm256_aesenc_epi128(b1, rkey1);
            b2 = _mm256_aesenc_epi128(b2, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesenc_epi128(b0, rkey0);
            b1 = _mm256_aesenc_epi128(b1, rkey0);
            b2 = _mm256_aesenc_epi128(b2, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesenc_epi128(b0, rkey1);
        b1 = _mm256_aesenc_epi128(b1, rkey1);
        b2 = _mm256_aesenc_epi128(b2, rkey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rkey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 4 x 2 blocks at a time */
    static inline void AesEncrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  __m256i*       blk3,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int     nr;
        __m256i rkey0, rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rkey0);
        __m256i b3 = _mm256_xor_si256(*blk3, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesenc_epi128(b0, rkey1);
            b1 = _mm256_aesenc_epi128(b1, rkey1);
            b2 = _mm256_aesenc_epi128(b2, rkey1);
            b3 = _mm256_aesenc_epi128(b3, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesenc_epi128(b0, rkey0);
            b1 = _mm256_aesenc_epi128(b1, rkey0);
            b2 = _mm256_aesenc_epi128(b2, rkey0);
            b3 = _mm256_aesenc_epi128(b3, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesenc_epi128(b0, rkey1);
        b1 = _mm256_aesenc_epi128(b1, rkey1);
        b2 = _mm256_aesenc_epi128(b2, rkey1);
        b3 = _mm256_aesenc_epi128(b3, rkey1);

        *blk0 = _mm256_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesenclast_epi128(b1, rkey0);
        *blk2 = _mm256_aesenclast_epi128(b2, rkey0);
        *blk3 = _mm256_aesenclast_epi128(b3, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    // Decrypt begins here

    /* 1 x 2 block at a time */
    static inline void AesDecrypt(__m256i*       blk0,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesdec_epi128(b0, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);
            b0 = _mm256_aesdec_epi128(b0, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0    = _mm256_aesdec_epi128(b0, rkey1);
        *blk0 = _mm256_aesdeclast_epi128(b0, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 2 x 2 blocks at a time */
    static inline void AesDecrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesdec_epi128(b0, rkey1);
            b1 = _mm256_aesdec_epi128(b1, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesdec_epi128(b0, rkey0);
            b1 = _mm256_aesdec_epi128(b1, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesdec_epi128(b0, rkey1);
        b1 = _mm256_aesdec_epi128(b1, rkey1);

        *blk0 = _mm256_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesdeclast_epi128(b1, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 3 x 2 blocks at a time */
    static inline void AesDecrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m256i rkey0;
        __m256i rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey0);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesdec_epi128(b0, rkey1);
            b1 = _mm256_aesdec_epi128(b1, rkey1);
            b2 = _mm256_aesdec_epi128(b2, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesdec_epi128(b0, rkey0);
            b1 = _mm256_aesdec_epi128(b1, rkey0);
            b2 = _mm256_aesdec_epi128(b2, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesdec_epi128(b0, rkey1);
        b1 = _mm256_aesdec_epi128(b1, rkey1);
        b2 = _mm256_aesdec_epi128(b2, rkey1);

        *blk0 = _mm256_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesdeclast_epi128(b1, rkey0);
        *blk2 = _mm256_aesdeclast_epi128(b2, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    /* 4 x 2  blocks at a time */
    static inline void AesDecrypt(__m256i*       blk0,
                                  __m256i*       blk1,
                                  __m256i*       blk2,
                                  __m256i*       blk3,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int     nr;
        __m256i rkey0, rkey1;

        amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);
        amd_mm256_broadcast_i64x2(&pKey[1], &rkey1);

        __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
        __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
        __m256i b2 = _mm256_xor_si256(*blk2, rkey0);
        __m256i b3 = _mm256_xor_si256(*blk3, rkey0);

        amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm256_aesdec_epi128(b0, rkey1);
            b1 = _mm256_aesdec_epi128(b1, rkey1);
            b2 = _mm256_aesdec_epi128(b2, rkey1);
            b3 = _mm256_aesdec_epi128(b3, rkey1);
            amd_mm256_broadcast_i64x2(&pKey[2], &rkey1);

            b0 = _mm256_aesdec_epi128(b0, rkey0);
            b1 = _mm256_aesdec_epi128(b1, rkey0);
            b2 = _mm256_aesdec_epi128(b2, rkey0);
            b3 = _mm256_aesdec_epi128(b3, rkey0);
            amd_mm256_broadcast_i64x2(&pKey[3], &rkey0);
        }

        b0 = _mm256_aesdec_epi128(b0, rkey1);
        b1 = _mm256_aesdec_epi128(b1, rkey1);
        b2 = _mm256_aesdec_epi128(b2, rkey1);
        b3 = _mm256_aesdec_epi128(b3, rkey1);

        *blk0 = _mm256_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm256_aesdeclast_epi128(b1, rkey0);
        *blk2 = _mm256_aesdeclast_epi128(b2, rkey0);
        *blk3 = _mm256_aesdeclast_epi128(b3, rkey0);

        rkey0 = _mm256_setzero_si256();
        rkey1 = _mm256_setzero_si256();
    }

    namespace experimantal {
        static inline void AesEncrypt(__m256i*       blk0,
                                      __m256i*       blk1,
                                      __m256i*       blk2,
                                      __m256i*       blk3,
                                      const __m128i* pKey, /* Round keys */
                                      int            nRounds)
        {
            int nr;

            __m256i rkey0;

            amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);

            __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
            __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
            __m256i b2 = _mm256_xor_si256(*blk2, rkey0);
            __m256i b3 = _mm256_xor_si256(*blk3, rkey0);

            amd_mm256_broadcast_i64x2(&pKey[1], &rkey0);

            for (nr = 1, pKey++; nr < nRounds; nr++, pKey++) {
                b0 = _mm256_aesenc_epi128(b0, rkey0);
                b1 = _mm256_aesenc_epi128(b1, rkey0);
                b2 = _mm256_aesenc_epi128(b2, rkey0);
                b3 = _mm256_aesenc_epi128(b3, rkey0);

                amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);
            }

            *blk0 = _mm256_aesenclast_epi128(b0, rkey0);
            *blk1 = _mm256_aesenclast_epi128(b1, rkey0);
            *blk2 = _mm256_aesenclast_epi128(b2, rkey0);
            *blk3 = _mm256_aesenclast_epi128(b3, rkey0);

            rkey0 = _mm256_setzero_si256();
        }

        static inline void AesDecrypt(__m256i*       blk0,
                                      __m256i*       blk1,
                                      __m256i*       blk2,
                                      __m256i*       blk3,
                                      const __m128i* pKey, /* Round keys */
                                      int            nRounds)
        {
            int nr;

            __m256i rkey0;

            amd_mm256_broadcast_i64x2(&pKey[0], &rkey0);

            __m256i b0 = _mm256_xor_si256(*blk0, rkey0);
            __m256i b1 = _mm256_xor_si256(*blk1, rkey0);
            __m256i b2 = _mm256_xor_si256(*blk2, rkey0);
            __m256i b3 = _mm256_xor_si256(*blk3, rkey0);

            amd_mm256_broadcast_i64x2(&pKey[1], &rkey0);

            for (nr = 1, pKey++; nr < nRounds; nr++, pKey++) {
                b0 = _mm256_aesdec_epi128(b0, rkey0);
                b1 = _mm256_aesdec_epi128(b1, rkey0);
                b2 = _mm256_aesdec_epi128(b2, rkey0);
                b3 = _mm256_aesdec_epi128(b3, rkey0);

                amd_mm256_broadcast_i64x2(&pKey[2], &rkey0);
            }

            *blk0 = _mm256_aesdeclast_epi128(b0, rkey0);
            *blk1 = _mm256_aesdeclast_epi128(b1, rkey0);
            *blk2 = _mm256_aesdeclast_epi128(b2, rkey0);
            *blk3 = _mm256_aesdeclast_epi128(b3, rkey0);

            rkey0 = _mm256_setzero_si256();
        }
    } // namespace experimantal
}}    // namespace alcp::cipher::vaes

#endif /* _CIPHER_VAES_HH */
