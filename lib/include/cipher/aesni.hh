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

#ifndef _CIPHER_AESNI_HH
#define _CIPHER_AESNI_HH 2

#include <immintrin.h>

#include "alcp/error.h"

#include "aes.hh"

#include "utils/copy.hh"

namespace alcp::cipher { namespace aesni {
    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey,
                           int            nRounds);

    alc_error_t EncryptCbc(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
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

    alc_error_t EncryptOfb(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptOfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptCtr(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCtr(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
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

    alc_error_t EncryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptGcm(const uint8_t* pInput,
                           uint8_t*       pOutput,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t InitGcm(const uint8_t* pKey,
                        int            nRounds,
                        const uint8_t* pIv,
                        uint64_t       ivBytes,
                        __m128i*       pHsubKey_128,
                        __m128i*       ptag_128,
                        __m128i*       piv_128,
                        __m128i        reverse_mask_128);

    alc_error_t processAdditionalDataGcm(const uint8_t* pAdditionalData,
                                         uint64_t       additionalDataLen,
                                         __m128i*       pgHash_128,
                                         __m128i        hash_subKey_128,
                                         __m128i        reverse_mask_128);

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

    alc_error_t GetTagGcm(uint64_t len,
                          uint64_t adLength,
                          __m128i* pgHash_128,
                          __m128i* ptag128,
                          __m128i  Hsubkey_128,
                          __m128i  reverse_mask_128,
                          uint8_t* tag);

    // ctr APIs for aesni
    void ctrInit(__m128i*       c1,
                 const uint8_t* pIv,
                 __m128i*       one_lo,
                 __m128i*       one_x,
                 __m128i*       two_x,
                 __m128i*       three_x,
                 __m128i*       four_x,
                 __m128i*       eight_x,
                 __m128i*       swap_ctr);

    uint64_t ctrProcess(const __m128i* p_in_x,
                        __m128i*       p_out_x,
                        uint64_t       blocks,
                        const __m128i* pkey128,
                        const uint8_t* pIv,
                        int            nRounds);

    static inline void AesEncrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  __m128i*       pBlk2,
                                  __m128i*       pBlk3,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rkey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rkey0);
        __m128i b2 = _mm_xor_si128(*pBlk2, rkey0);
        __m128i b3 = _mm_xor_si128(*pBlk3, rkey0);

        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];

            b0 = _mm_aesenc_si128(b0, rkey0);
            b1 = _mm_aesenc_si128(b1, rkey0);
            b2 = _mm_aesenc_si128(b2, rkey0);
            b3 = _mm_aesenc_si128(b3, rkey0);

            pKey++;
        }

        rkey0 = pKey[0];

        *pBlk0 = _mm_aesenclast_si128(b0, rkey0);
        *pBlk1 = _mm_aesenclast_si128(b1, rkey0);
        *pBlk2 = _mm_aesenclast_si128(b2, rkey0);
        *pBlk3 = _mm_aesenclast_si128(b3, rkey0);

        rkey0 = _mm_setzero_si128();
    }

    static inline void AesEncrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rkey);
        __m128i b1 = _mm_xor_si128(*pBlk1, rkey);

        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            rkey = pKey[0];

            b0 = _mm_aesenc_si128(b0, rkey);
            b1 = _mm_aesenc_si128(b1, rkey);

            pKey++;
        }

        rkey = pKey[0];

        *pBlk0 = _mm_aesenclast_si128(b0, rkey);
        *pBlk1 = _mm_aesenclast_si128(b1, rkey);

        rkey = _mm_setzero_si128();
    }

    /**
     * \brief
     * \notes
     * \param    pBlk0   pointer to input block
     * \param    pKey    pointer to Key
     *                   Actual key is in pKey[0], and
     *                   Round keys are in pKey[1] onwards
     * \param    nRounds number of rounds to perform
     */
    static inline void AesEncrypt(__m128i*       pBlk0,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];
        __m128i b0    = _mm_xor_si128(*pBlk0, rkey0);

        pKey++;
        /* rounds 1-9 */
        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];
            b0    = _mm_aesenc_si128(b0, rkey0);
            pKey++;
        }

        /* last round, load last key */
        rkey0  = pKey[0];
        *pBlk0 = _mm_aesenclast_si128(b0, rkey0);

        /* clear rkey0 */
        rkey0 = _mm_setzero_si128();
    }

    /*
     * Decrypt functions
     */
    static inline void AesDecrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  __m128i*       pBlk2,
                                  __m128i*       pBlk3,
                                  __m128i*       pBlk4,
                                  __m128i*       pBlk5,
                                  __m128i*       pBlk6,
                                  __m128i*       pBlk7,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rkey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rkey0);
        __m128i b2 = _mm_xor_si128(*pBlk2, rkey0);
        __m128i b3 = _mm_xor_si128(*pBlk3, rkey0);
        __m128i b4 = _mm_xor_si128(*pBlk4, rkey0);
        __m128i b5 = _mm_xor_si128(*pBlk5, rkey0);
        __m128i b6 = _mm_xor_si128(*pBlk6, rkey0);
        __m128i b7 = _mm_xor_si128(*pBlk7, rkey0);

        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];

            b0 = _mm_aesdec_si128(b0, rkey0);
            b1 = _mm_aesdec_si128(b1, rkey0);
            b2 = _mm_aesdec_si128(b2, rkey0);
            b3 = _mm_aesdec_si128(b3, rkey0);
            b4 = _mm_aesdec_si128(b4, rkey0);
            b5 = _mm_aesdec_si128(b5, rkey0);
            b6 = _mm_aesdec_si128(b6, rkey0);
            b7 = _mm_aesdec_si128(b7, rkey0);

            pKey++;
        }

        rkey0 = pKey[0];

        *pBlk0 = _mm_aesdeclast_si128(b0, rkey0);
        *pBlk1 = _mm_aesdeclast_si128(b1, rkey0);
        *pBlk2 = _mm_aesdeclast_si128(b2, rkey0);
        *pBlk3 = _mm_aesdeclast_si128(b3, rkey0);
        *pBlk4 = _mm_aesdeclast_si128(b4, rkey0);
        *pBlk5 = _mm_aesdeclast_si128(b5, rkey0);
        *pBlk6 = _mm_aesdeclast_si128(b6, rkey0);
        *pBlk7 = _mm_aesdeclast_si128(b7, rkey0);

        rkey0 = _mm_setzero_si128();
    }

    static inline void AesDecrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  __m128i*       pBlk2,
                                  __m128i*       pBlk3,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rkey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rkey0);
        __m128i b2 = _mm_xor_si128(*pBlk2, rkey0);
        __m128i b3 = _mm_xor_si128(*pBlk3, rkey0);

        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];

            b0 = _mm_aesdec_si128(b0, rkey0);
            b1 = _mm_aesdec_si128(b1, rkey0);
            b2 = _mm_aesdec_si128(b2, rkey0);
            b3 = _mm_aesdec_si128(b3, rkey0);

            pKey++;
        }

        rkey0 = pKey[0];

        *pBlk0 = _mm_aesdeclast_si128(b0, rkey0);
        *pBlk1 = _mm_aesdeclast_si128(b1, rkey0);
        *pBlk2 = _mm_aesdeclast_si128(b2, rkey0);
        *pBlk3 = _mm_aesdeclast_si128(b3, rkey0);

        rkey0 = _mm_setzero_si128();
    }

    static inline void AesDecrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rkey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rkey0);

        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];

            b0 = _mm_aesdec_si128(b0, rkey0);
            b1 = _mm_aesdec_si128(b1, rkey0);

            pKey++;
        }

        rkey0 = pKey[0];

        *pBlk0 = _mm_aesdeclast_si128(b0, rkey0);
        *pBlk1 = _mm_aesdeclast_si128(b1, rkey0);

        rkey0 = _mm_setzero_si128();
    }

    /**
     * \brief
     * \notes
     * \param    pBlk0   pointer to input block
     * \param    pKey    pointer to Key
     *                   Actual key is in pKey[0], and
     *                   Round keys are in pKey[1] onwards
     * \param    nRounds number of rounds to perform
     */
    static inline void AesDecrypt(__m128i*       pBlk0,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rkey0 = pKey[0];
        __m128i b0    = _mm_xor_si128(*pBlk0, rkey0);

        pKey++;
        /* rounds 1-9 */
        for (nr = 1; nr < nRounds; nr++) {
            rkey0 = pKey[0];
            b0    = _mm_aesdec_si128(b0, rkey0);
            pKey++;
        }

        /* last round, load last key */
        rkey0  = pKey[0];
        *pBlk0 = _mm_aesdeclast_si128(b0, rkey0);

        /* clear rkey0 */
        rkey0 = _mm_setzero_si128();
    }
}} // namespace alcp::cipher::aesni

#endif /* _CIPHER_AESNI_HH */
