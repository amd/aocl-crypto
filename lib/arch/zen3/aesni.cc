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

#include <cstdint>

#include <immintrin.h>

#include "cipher/aesni.hh"
#include "error.hh"
#include "misc/notimplemented.hh"

namespace alcp::cipher { namespace aesni {

    static inline __m128i __aes128keyassist(__m128i tmp0, __m128i tmp1)
    {
        __m128i tmp = _mm_slli_si128(tmp0, 0x4);
        tmp0        = _mm_xor_si128(tmp0, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        tmp0 = _mm_xor_si128(tmp0, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        tmp0 = _mm_xor_si128(tmp0, tmp);

        /* [1, 2, 3, 4] -> [4, 4, 4, 4] */
        tmp1 = _mm_shuffle_epi32(tmp1, 0xff);

        tmp = _mm_xor_si128(tmp0, tmp1);

        return tmp;
    }

    static inline __m128i __aes192keyassist(__m128i tmp0, __m128i tmp1)
    {
        NotImplemented();
        return tmp1;
    }

    static inline __m256i __aes256keyassist(__m256i tmp0, __m256i tmp1)
    {
        NotImplemented();
        return tmp1;
    }

    static inline void ExpandDecryptKeys(uint8_t*       pDecKey,
                                         const uint8_t* pEncKey,
                                         int            nr)
    {
        __m128i* pDec128 = (__m128i*)pDecKey;
        __m128i* pEnc128 = (__m128i*)pEncKey;

        pDec128[nr] = pEnc128[nr];

        for (int i = nr - 1; i > 0; i--) {
            pDec128[i] = _mm_aesimc_si128(pEnc128[i]);
        }

        pDec128[0] = pEnc128[0];
    }

    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey)
    {
        __m128i  tmp[2];
        __m128i* pRoundKey = (__m128i*)pEncKey;

        tmp[0]       = _mm_loadu_si128((__m128i*)pUserKey);
        pRoundKey[0] = tmp[0];

        /**
         * Something similar to following,
         * but 'aeskeygenassist_si128' needs a constant integer
         * for (int i = 1; i <= 10; i++) {
         *     const int j  = i;
         *     tmp[0]       = _mm_aeskeygenassist_si128(tmp[0], 0x1 << j);
         *     tmp[1]       = __aes128keyassist(tmp[0], tmp[1]);
         *     pRoundKey[i] = tmp[0];
         * }
         */
        pRoundKey[1] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[1], 0x1));
        pRoundKey[2] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[2], 0x2));
        pRoundKey[3] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[3], 0x4));
        pRoundKey[4] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[4], 0x8));
        pRoundKey[5] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[5], 0x10));
        pRoundKey[6] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[6], 0x20));
        pRoundKey[7] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[7], 0x40));
        pRoundKey[8] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[8], 0x80));
        pRoundKey[9] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[9], 0x1b));
        pRoundKey[10] = __aes128keyassist(
            pRoundKey[1], _mm_aeskeygenassist_si128(pRoundKey[10], 0x36));

        aesni::ExpandDecryptKeys(pDecKey, pEncKey, 10);

        return ALC_ERROR_NONE;
    }

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        alc_error_t err     = ALC_ERROR_NONE;
        auto        pKey128 = reinterpret_cast<const __m128i*>(pKey);
        auto        pCt128  = reinterpret_cast<const __m128i*>(pCipherText);
        auto        pPt128  = reinterpret_cast<__m128i*>(pPlainText);

        __m128i  IV     = _mm_loadu_si128((const __m128i*)pIv);
        __m128i* pIv128 = (__m128i*)&IV;

        uint64_t blocks = len / Rijndael::eBytes128;

        for (; blocks > 4; blocks -= 4) {
            __m128i blk0 = _mm_loadu_si128(pIv128);
            __m128i blk1 = _mm_loadu_si128(pCt128);
            __m128i blk2 = _mm_loadu_si128(pCt128 + 1);
            __m128i blk3 = _mm_loadu_si128(pCt128 + 2);

            aesni::AesEncrypt(&blk0, &blk1, &blk2, &blk3, pKey128, nRounds);

            IV = blk1;

            blk0 = _mm_xor_si128(blk0, pPt128[0]);
            blk1 = _mm_xor_si128(blk0, pPt128[1]);
            blk2 = _mm_xor_si128(blk0, pPt128[2]);
            blk3 = _mm_xor_si128(blk0, pPt128[3]);

            _mm_storeu_si128(pPt128, blk0);
            _mm_storeu_si128(pPt128 + 1, blk1);
            _mm_storeu_si128(pPt128 + 2, blk2);
            _mm_storeu_si128(pPt128 + 3, blk3);

            pCt128 += 4;
            pPt128 += 4;
            blocks -= 4;
        }

        if (blocks > 2) {
            __m128i blk0 = _mm_loadu_si128(pIv128);
            __m128i blk1 = _mm_loadu_si128(pCt128);

            aesni::AesEncrypt(&blk0, &blk1, pKey128, nRounds);

            IV = blk1;

            blk0 = _mm_xor_si128(blk0, pPt128[0]);
            blk1 = _mm_xor_si128(blk0, pPt128[1]);

            _mm_storeu_si128(pPt128, blk0);
            _mm_storeu_si128(pPt128 + 1, blk1);

            pCt128 += 2;
            pPt128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            /* Still one block left */
            __m128i blk0 = _mm_loadu_si128(pIv128);

            aesni::AesEncrypt(&blk0, pKey128, nRounds);

            blk0 = _mm_xor_si128(blk0, pPt128[0]);

            _mm_storeu_si128(pPt128, blk0);

            pCt128 += 2;
            pPt128 += 2;
            blocks -= 2;
        }

        return err;
    }
}} // namespace alcp::cipher::aesni
