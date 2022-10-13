/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

namespace alcp::cipher { namespace aesni {

    alc_error_t DecryptCfb(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        alc_error_t err       = ALC_ERROR_NONE;
        auto        p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto        p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto        p_dest128 = reinterpret_cast<__m128i*>(pDest);

        __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);

        uint64_t blocks = len / Rijndael::cBlockSize;

        for (; blocks >= 4; blocks -= 4) {
            __m128i blk0 = iv128;
            __m128i blk1 = _mm_loadu_si128(&p_src128[0]);
            __m128i blk2 = _mm_loadu_si128(&p_src128[1]);
            __m128i blk3 = _mm_loadu_si128(&p_src128[2]);

            aesni::AesEncrypt(&blk0, &blk1, &blk2, &blk3, p_key128, nRounds);

            blk0 = _mm_xor_si128(blk0, p_src128[0]);
            blk1 = _mm_xor_si128(blk1, p_src128[1]);
            blk2 = _mm_xor_si128(blk2, p_src128[2]);
            blk3 = _mm_xor_si128(blk3, p_src128[3]);

            iv128 = p_src128[3];

            _mm_storeu_si128(&p_dest128[0], blk0);
            _mm_storeu_si128(&p_dest128[1], blk1);
            _mm_storeu_si128(&p_dest128[2], blk2);
            _mm_storeu_si128(&p_dest128[3], blk3);

            p_src128 += 4;
            p_dest128 += 4;
        }

        if (blocks >= 2) {
            __m128i blk0 = iv128;
            __m128i blk1 = _mm_loadu_si128(&p_src128[0]);

            aesni::AesEncrypt(&blk0, &blk1, p_key128, nRounds);

            blk0 = _mm_xor_si128(blk0, p_src128[0]);
            blk1 = _mm_xor_si128(blk1, p_src128[1]);

            iv128 = p_src128[1];

            _mm_storeu_si128(&p_dest128[0], blk0);
            _mm_storeu_si128(&p_dest128[1], blk1);

            p_src128 += 2;
            p_dest128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            /* Still one block left */
            __m128i blk = iv128;

            aesni::AesEncrypt(&blk, p_key128, nRounds);

            blk = _mm_xor_si128(blk, p_src128[0]);

            _mm_storeu_si128(p_dest128, blk);

            blocks--;
        }

        assert(blocks == 0);

        return err;
    }

    alc_error_t EncryptCfb(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        auto p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128 = reinterpret_cast<__m128i*>(pDest);

        __m128i  iv128  = _mm_loadu_si128((const __m128i*)pIv);
        uint64_t blocks = len / Rijndael::cBlockSize;

        while (blocks >= 4) {
            __m128i tmpblk = iv128;

            for (int i = 0; i < 4; i++) {
                __m128i srcblk = _mm_loadu_si128(&p_src128[i]);

                aesni::AesEncrypt(&tmpblk, p_key128, nRounds);
                tmpblk = _mm_xor_si128(tmpblk, srcblk);

                /* TODO: Store blocks using ERMS/FSRM or similar */
                _mm_storeu_si128(&p_dest128[i], tmpblk);
            }

            iv128 = tmpblk;

            p_src128 += 4;
            p_dest128 += 4;
            blocks -= 4;
        }

        if (blocks >= 2) {
            __m128i tmpblk = iv128;

            for (int i = 0; i < 2; i++) {
                __m128i srcblk = _mm_loadu_si128(&p_src128[i]);

                AesEncrypt(&tmpblk, p_key128, nRounds);
                tmpblk = _mm_xor_si128(tmpblk, srcblk);

                /* TODO: Store blocks using ERMS/FSRM or similar */
                _mm_storeu_si128(&p_dest128[i], tmpblk);
            }

            iv128 = tmpblk;

            p_src128 += 2;
            p_dest128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            __m128i tmpblk = iv128;
            __m128i srcblk = _mm_loadu_si128(p_src128);

            aesni::AesEncrypt(&tmpblk, p_key128, nRounds);
            tmpblk = _mm_xor_si128(tmpblk, srcblk);

            /* TODO: Store blocks using ERMS/FSRM or similar */
            _mm_storeu_si128(p_dest128, tmpblk);

            blocks--;
        }

        assert(blocks == 0);

        return ALC_ERROR_NONE;
    }
}} // namespace alcp::cipher::aesni
