/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <cstdint>

#pragma GCC target("aes,sse2,avx,avx2,vaes,fma")
#include <immintrin.h>

#include "error.hh"
#include "misc/notimplemented.hh"

namespace alcp::cipher {
namespace aesni {
    static inline __m128i __aes128keyassist(const __m128i tmp0,
                                            const __m128i tmp1)
    {
        NotImplemented();
        return tmp1;
    }

    static inline __m128i __aes192keyassist(const __m128i tmp0,
                                            const __m128i tmp1)
    {
        NotImplemented();
        return tmp1;
    }

    static inline __m256i __aes256keyassist(const __m256i tmp0,
                                            const __m256i tmp1)
    {
        NotImplemented();
        return tmp1;
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
#if 1
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
#endif
        return ALC_ERROR_NONE;
    }


} // namespace aesni

}
