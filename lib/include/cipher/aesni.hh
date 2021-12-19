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
    {}

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        alc_error_t err    = ALC_ERROR_NONE;
        uint64_t*   pIv64  = (uint64_t*)pIv;
        __m128i*    pCt128 = (__m128i*)pCipherText;
        __m128i*    pPt128 = (__m128i*)pPlainText;

        __m128i IV = _mm_loadu_si128((const __m128i*)pIv);

        uint64_t blocks = len / Rijndael::eBytes128;

        for (; blocks > 4; blocks -= 4) {
            __m128i blk0 = _mm_loadu_si128(pCt128);
            __m128i blk1 = _mm_loadu_si128(pCt128 + 1);
            __m128i blk2 = _mm_loadu_si128(pCt128 + 2);
            __m128i blk3 = _mm_loadu_si128(pCt128 + 3);
        }
    }
}} // namespace alcp::cipher::aesni

#endif /* _CIPHER_AESNI_HH */
