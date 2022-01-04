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

namespace alcp::cipher {
namespace aesni {

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
        auto p_dec128 = reinterpret_cast<__m128i*>(pDecKey);
        auto p_enc128 = reinterpret_cast<const __m128i*>(pEncKey);

        p_dec128[nr] = p_enc128[nr];

        for (int i = nr - 1; i > 0; i--) {
            p_dec128[i] = _mm_aesimc_si128(p_enc128[i]);
        }

        p_dec128[0] = p_enc128[0];
    }

    alc_error_t ExpandKeys256(const uint8_t* pUserKey,
                              uint8_t*       pEncKey,
                              uint8_t*       pDecKey)
    {
        NotImplemented();
        return ALC_ERROR_NONE;
    }

    alc_error_t ExpandKeys192(const uint8_t* pUserKey,
                              uint8_t*       pEncKey,
                              uint8_t*       pDecKey)
    {
        NotImplemented();
        return ALC_ERROR_NONE;
    }

    alc_error_t ExpandKeys128(const uint8_t* pUserKey,
                              uint8_t*       pEncKey,
                              uint8_t*       pDecKey)
    {
        __m128i  tmp[2];
        __m128i* p_round_key = reinterpret_cast<__m128i*>(pEncKey);

        tmp[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
        p_round_key[0] = tmp[0];

        /**
         * Something similar to following,
         * but 'aeskeygenassist_si128' needs a constant integer
         * for (int i = 1; i <= 10; i++) {
         *     const int j  = i;
         *     tmp[0]       = _mm_aeskeygenassist_si128(tmp[0], 0x1 << j);
         *     tmp[1]       = __aes128keyassist(tmp[0], tmp[1]);
         *     p_round_key[i] = tmp[0];
         * }
         */
        p_round_key[1] = __aes128keyassist(
            p_round_key[0], _mm_aeskeygenassist_si128(p_round_key[0], 0x1));
        p_round_key[2] = __aes128keyassist(
            p_round_key[1], _mm_aeskeygenassist_si128(p_round_key[1], 0x2));
        p_round_key[3] = __aes128keyassist(
            p_round_key[2], _mm_aeskeygenassist_si128(p_round_key[2], 0x4));
        p_round_key[4] = __aes128keyassist(
            p_round_key[3], _mm_aeskeygenassist_si128(p_round_key[3], 0x8));
        p_round_key[5] = __aes128keyassist(
            p_round_key[4], _mm_aeskeygenassist_si128(p_round_key[4], 0x10));
        p_round_key[6] = __aes128keyassist(
            p_round_key[5], _mm_aeskeygenassist_si128(p_round_key[5], 0x20));
        p_round_key[7] = __aes128keyassist(
            p_round_key[6], _mm_aeskeygenassist_si128(p_round_key[6], 0x40));
        p_round_key[8] = __aes128keyassist(
            p_round_key[7], _mm_aeskeygenassist_si128(p_round_key[7], 0x80));
        p_round_key[9] = __aes128keyassist(
            p_round_key[8], _mm_aeskeygenassist_si128(p_round_key[8], 0x1b));
        p_round_key[10] = __aes128keyassist(
            p_round_key[9], _mm_aeskeygenassist_si128(p_round_key[9], 0x36));

        aesni::ExpandDecryptKeys(pDecKey, pEncKey, 10);

        return ALC_ERROR_NONE;
    }

    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey,
                           int            nRounds)
    {
        switch (nRounds) {
            case 14:
                return ExpandKeys256(pUserKey, pEncKey, pDecKey);
                break;
            case 12:
                return ExpandKeys192(pUserKey, pEncKey, pDecKey);
                break;
            default:
                return ExpandKeys128(pUserKey, pEncKey, pDecKey);
        }
    }

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

        __m128i  iv128   = _mm_loadu_si128((const __m128i*)pIv);
        __m128i* p_iv128 = (__m128i*)&iv128;

        uint64_t blocks = len / Rijndael::eBytes128;

        for (; blocks >= 4; blocks -= 4) {
            __m128i blk0 = _mm_loadu_si128(p_iv128);
            __m128i blk1 = _mm_loadu_si128(p_src128);
            __m128i blk2 = _mm_loadu_si128(p_src128 + 1);
            __m128i blk3 = _mm_loadu_si128(p_src128 + 2);

            aesni::AesEncrypt(&blk0, &blk1, &blk2, &blk3, p_key128, nRounds);

            iv128 = blk1;

            blk0 = _mm_xor_si128(blk0, p_dest128[0]);
            blk1 = _mm_xor_si128(blk0, p_dest128[1]);
            blk2 = _mm_xor_si128(blk0, p_dest128[2]);
            blk3 = _mm_xor_si128(blk0, p_dest128[3]);

            _mm_storeu_si128(p_dest128, blk0);
            _mm_storeu_si128(p_dest128 + 1, blk1);
            _mm_storeu_si128(p_dest128 + 2, blk2);
            _mm_storeu_si128(p_dest128 + 3, blk3);

            p_src128 += 4;
            p_dest128 += 4;
            blocks -= 4;
        }

        if (blocks >= 2) {
            __m128i blk0 = _mm_loadu_si128(p_iv128);
            __m128i blk1 = _mm_loadu_si128(p_src128);

            aesni::AesEncrypt(&blk0, &blk1, p_key128, nRounds);

            iv128 = blk1;

            blk0 = _mm_xor_si128(blk0, p_dest128[0]);
            blk1 = _mm_xor_si128(blk0, p_dest128[1]);

            _mm_storeu_si128(p_dest128, blk0);
            _mm_storeu_si128(p_dest128 + 1, blk1);

            p_src128 += 2;
            p_dest128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            /* Still one block left */
            __m128i blk0 = _mm_loadu_si128(p_iv128);

            aesni::AesEncrypt(&blk0, p_key128, nRounds);

            blk0 = _mm_xor_si128(blk0, p_src128[0]);

            _mm_storeu_si128(p_dest128, blk0);
        }

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
        uint64_t blocks = len / Rijndael::eBytes128;

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
} // namespace aesni

namespace vaes {
    void ExpandKeys(const uint8_t* pUserKey,
                    uint8_t*       pEncKey,
                    uint8_t*       pDecKey,
                    int            nRounds)
    {
        NotImplemented();
    }
} // namespace vaes

} // namespace alcp::cipher
