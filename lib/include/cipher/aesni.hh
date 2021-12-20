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

#pragma GCC target("aes,sse2,avx,avx2,fma")
#include <immintrin.h>

#include "alcp/error.h"

#include "aes.hh"

namespace alcp::cipher { namespace aesni {
    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    static inline void AesEncrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  __m128i*       pBlk2,
                                  __m128i*       pBlk3,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rKey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rKey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rKey0);
        __m128i b2 = _mm_xor_si128(*pBlk2, rKey0);
        __m128i b3 = _mm_xor_si128(*pBlk3, rKey0);

        rKey0 = pKey[1];
        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            b0    = _mm_aesenc_si128(b0, rKey0);
            b1    = _mm_aesenc_si128(b1, rKey0);
            b2    = _mm_aesenc_si128(b2, rKey0);
            b3    = _mm_aesenc_si128(b3, rKey0);
            rKey0 = pKey[1];
            pKey++;
        }

        b0 = _mm_aesenc_si128(b0, rKey0);
        b1 = _mm_aesenc_si128(b1, rKey0);
        b2 = _mm_aesenc_si128(b2, rKey0);
        b3 = _mm_aesenc_si128(b3, rKey0);

        *pBlk0 = _mm_aesenclast_si128(b0, rKey0);
        *pBlk1 = _mm_aesenclast_si128(b1, rKey0);
        *pBlk2 = _mm_aesenclast_si128(b2, rKey0);
        *pBlk3 = _mm_aesenclast_si128(b3, rKey0);

        rKey0 = _mm_setzero_si128();
    }

    static inline void AesEncrypt(__m128i*       pBlk0,
                                  __m128i*       pBlk1,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rKey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rKey0);
        __m128i b1 = _mm_xor_si128(*pBlk1, rKey0);

        rKey0 = pKey[1];
        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            b0    = _mm_aesenc_si128(b0, rKey0);
            b1    = _mm_aesenc_si128(b1, rKey0);
            rKey0 = pKey[1];
            pKey++;
        }

        b0 = _mm_aesenc_si128(b0, rKey0);
        b1 = _mm_aesenc_si128(b1, rKey0);

        *pBlk0 = _mm_aesenclast_si128(b0, rKey0);
        *pBlk1 = _mm_aesenclast_si128(b1, rKey0);

        rKey0 = _mm_setzero_si128();
    }

    static inline void AesEncrypt(__m128i*       pBlk0,
                                  const __m128i* pKey,
                                  int            nRounds)
    {
        int     nr;
        __m128i rKey0 = pKey[0];

        __m128i b0 = _mm_xor_si128(*pBlk0, rKey0);

        rKey0 = pKey[1];
        pKey++;

        for (nr = 1; nr < nRounds; nr++) {
            b0    = _mm_aesenc_si128(b0, rKey0);
            rKey0 = pKey[1];
            pKey++;
        }

        b0 = _mm_aesenc_si128(b0, rKey0);

        *pBlk0 = _mm_aesenclast_si128(b0, rKey0);

        rKey0 = _mm_setzero_si128();
    }

}} // namespace alcp::cipher::aesni

#endif /* _CIPHER_AESNI_HH */
