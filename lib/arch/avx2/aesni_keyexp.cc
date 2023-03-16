/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/cipher/aesni.hh"

#include <immintrin.h>

using namespace alcp::base;

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

    static inline void ExpandDecryptKeys(Uint8*       pDecKey,
                                         const Uint8* pEncKey,
                                         int          nr)
    {
        auto p_dec128 = reinterpret_cast<__m128i*>(pDecKey);
        auto p_enc128 = reinterpret_cast<const __m128i*>(pEncKey);

        p_dec128[nr] = p_enc128[0];
        int j        = 1;

        for (int i = nr - 1; i > 0; i--) {
            p_dec128[i] = _mm_aesimc_si128(p_enc128[j]);
            j++;
        }

        p_dec128[0] = p_enc128[nr];
    }

    static inline void __aes192keyassist(__m128i* tmp0,
                                         __m128i* tmp1,
                                         __m128i* tmp2)
    {
        __m128i tmp4;
        *tmp1 = _mm_shuffle_epi32(*tmp1, 0x55);

        tmp4  = _mm_slli_si128(*tmp0, 0x4);
        *tmp0 = _mm_xor_si128(*tmp0, tmp4);

        tmp4  = _mm_slli_si128(tmp4, 0x4);
        *tmp0 = _mm_xor_si128(*tmp0, tmp4);

        tmp4  = _mm_slli_si128(tmp4, 0x4);
        *tmp0 = _mm_xor_si128(*tmp0, tmp4);

        *tmp0 = _mm_xor_si128(*tmp0, *tmp1);

        *tmp1 = _mm_shuffle_epi32(*tmp0, 0xff);

        tmp4  = _mm_slli_si128(*tmp2, 0x4);
        *tmp2 = _mm_xor_si128(*tmp2, tmp4);

        *tmp2 = _mm_xor_si128(*tmp2, *tmp1);
    }

    static inline void __aes256keyassist_1(__m128i* tmp1, __m128i* tmp2)
    {
        *tmp2 = _mm_shuffle_epi32(*tmp2, 0xff);

        __m128i tmp3 = _mm_slli_si128(*tmp1, 0x4);
        *tmp1        = _mm_xor_si128(*tmp1, tmp3);

        tmp3  = _mm_slli_si128(tmp3, 0x4);
        *tmp1 = _mm_xor_si128(*tmp1, tmp3);

        tmp3  = _mm_slli_si128(tmp3, 0x4);
        *tmp1 = _mm_xor_si128(*tmp1, tmp3);
        *tmp1 = _mm_xor_si128(*tmp1, *tmp2);
    }

    static inline void __aes256keyassist_2(__m128i* tmp1, __m128i* tmp3)
    {
        __m128i tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x0);
        __m128i tmp0 = _mm_shuffle_epi32(tmp4, 0xaa);

        tmp4 = _mm_slli_si128(*tmp3, 0x4);

        *tmp3 = _mm_xor_si128(*tmp3, tmp4);
        tmp4  = _mm_slli_si128(tmp4, 0x4);

        *tmp3 = _mm_xor_si128(*tmp3, tmp4);
        tmp4  = _mm_slli_si128(tmp4, 0x4);

        *tmp3 = _mm_xor_si128(*tmp3, tmp4);
        *tmp3 = _mm_xor_si128(*tmp3, tmp0);
    }

    /* keys256 is equivalent to 2x128 */
    Status ExpandKeys256(const Uint8* pUserKey, Uint8* pEncKey, Uint8* pDecKey)
    {
        __m128i  tmp[3];
        __m128i* p_round_key = reinterpret_cast<__m128i*>(pEncKey);

        tmp[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
        p_round_key[0] = tmp[0];

        tmp[2] =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey + 16));
        p_round_key[1] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x01);

        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[2] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[3] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x02);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[4] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[5] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x04);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[6] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[7] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x08);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[8] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[9] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x10);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[10] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[11] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x20);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[12] = tmp[0];
        __aes256keyassist_2(&tmp[0], &tmp[2]);
        p_round_key[13] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x40);
        __aes256keyassist_1(&tmp[0], &tmp[1]);
        p_round_key[14] = tmp[0];

        // aesni::ExpandDecryptKeys(pDecKey, pEncKey, 14);

        return StatusOk();
    }

    /*
     * @brief    Key Expansion for 192-bit keys, h/w assisted
     *
     * @notes    keys192 is equivalent to 2x128, [256:192] are ignored
     *
     * @param    pUserKey        Pointer to user supplied key
     * @param    pEncKey         Pointer to Round-key for encryption
     * @param    pDecKey         Pointer to Round-key for decryption
     *
     * @return   Status
     */
    Status ExpandKeys192(const Uint8* pUserKey, Uint8* pEncKey, Uint8* pDecKey)
    {

        __m128i  tmp[3];
        __m128i* p_round_key = reinterpret_cast<__m128i*>(pEncKey);

        tmp[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
        p_round_key[0] = tmp[0];

        tmp[2] = _mm_cvtsi64_si128(
            (reinterpret_cast<const Uint64*>(pUserKey + 16))[0]);

        p_round_key[1] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x1);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[1] = (__m128i)_mm_shuffle_pd(
            (__m128d)p_round_key[1], (__m128d)tmp[0], 0);

        p_round_key[2] =
            (__m128i)_mm_shuffle_pd((__m128d)tmp[0], (__m128d)tmp[2], 1);

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x2);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[3] = tmp[0];
        p_round_key[4] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x4);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[4] = (__m128i)_mm_shuffle_pd(
            (__m128d)p_round_key[4], (__m128d)tmp[0], 0);
        p_round_key[5] =
            (__m128i)_mm_shuffle_pd((__m128d)tmp[0], (__m128d)tmp[2], 1);

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x8);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[6] = tmp[0];
        p_round_key[7] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x10);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[7] = (__m128i)_mm_shuffle_pd(
            (__m128d)p_round_key[7], (__m128d)tmp[0], 0);
        p_round_key[8] =
            (__m128i)_mm_shuffle_pd((__m128d)tmp[0], (__m128d)tmp[2], 1);

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x20);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[9]  = tmp[0];
        p_round_key[10] = tmp[2];

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x40);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[10] = (__m128i)_mm_shuffle_pd(
            (__m128d)p_round_key[10], (__m128d)tmp[0], 0);
        p_round_key[11] =
            (__m128i)_mm_shuffle_pd((__m128d)tmp[0], (__m128d)tmp[2], 1);

        tmp[1] = _mm_aeskeygenassist_si128(tmp[2], 0x80);
        __aes192keyassist(&tmp[0], &tmp[1], &tmp[2]);
        p_round_key[12] = tmp[0];
        // p_round_key[13] = tmp[2];

        return StatusOk();
    }

    /*
     * @brief    Key Expansion for 128-bit keys, h/w assisted
     *
     * @notes
     *
     * @param    pUserKey        Pointer to user supplied key
     * @param    pEncKey         Pointer to Round-key for encryption
     * @param    pDecKey         Pointer to Round-key for decryption
     *
     * @return   Status
     */
    Status ExpandKeys128(const Uint8* pUserKey, Uint8* pEncKey, Uint8* pDecKey)
    {
        __m128i* p_round_key = reinterpret_cast<__m128i*>(pEncKey);

        p_round_key[0] =
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));

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

        return StatusOk();
    }

    alc_error_t ExpandKeys(const Uint8* pUserKey,
                           Uint8*       pEncKey,
                           Uint8*       pDecKey,
                           int          nRounds)
    {
        Status sts = StatusOk();

        switch (nRounds) {
            case 14:
                sts = ExpandKeys256(pUserKey, pEncKey, pDecKey);
                break;
            case 12:
                sts = ExpandKeys192(pUserKey, pEncKey, pDecKey);
                break;
            default:
                sts = ExpandKeys128(pUserKey, pEncKey, pDecKey);
                break;
        }

        if (sts.ok())
            aesni::ExpandDecryptKeys(pDecKey, pEncKey, nRounds);

        return (alc_error_t)sts.code();
    }

    alc_error_t ExpandTweakKeys(const Uint8* pUserKey,
                                Uint8*       pTweakKey,
                                int          nRounds)
    {
        Status sts = StatusOk();

        switch (nRounds) {
            case 14:
                sts = ExpandKeys256(pUserKey, pTweakKey, nullptr);
                break;
            case 12:
                sts = ExpandKeys192(pUserKey, pTweakKey, nullptr);
                break;
            default:
                sts = ExpandKeys128(pUserKey, pTweakKey, nullptr);
        }

        return (alc_error_t)sts.code();
    }
}} // namespace alcp::cipher::aesni
