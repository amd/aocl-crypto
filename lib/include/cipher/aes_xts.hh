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

#ifndef _CIPHER_AES_CTR_HH_
#define _CIPHER_AES_CTR_HH_ 2

#include <cstdint>
#include <immintrin.h>

#define GF_POLYNOMIAL 0x87

namespace alcp::cipher { namespace aes {

    static inline void MultiplyAplhaByTwo(__m128i& alpha)
    {
        unsigned long long res, carry;

        unsigned long long* tmp_tweak = (unsigned long long*)&alpha;

        res   = (((long long)tmp_tweak[1]) >> 63) & GF_POLYNOMIAL;
        carry = (((long long)tmp_tweak[0]) >> 63) & 1;

        tmp_tweak[0] = ((tmp_tweak[0]) << 1) ^ res;
        tmp_tweak[1] = ((tmp_tweak[1]) << 1) | carry;
    }

    static inline void init_alphax8(__m128i& alpha, __m128i* dst)
    {

        dst[0] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[1] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[2] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[3] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[4] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[5] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[6] = alpha;
        MultiplyAplhaByTwo(alpha);
        dst[7] = alpha;
    }

    /* Generate next 4 tweaks with 2^8 multiplier */
    static inline __m256i nextTweaks(__m256i tweak128x4)
    {

        const __m256i poly = _mm256_set_epi64x(0, 0x87, 0, 0x87);
        __m256i       nexttweak;

        // Shifting individual 128 bit to right by 15*8 bits
        __m256i highBytes = _mm256_bsrli_epi128(tweak128x4, 15);

        // Multiplying each 128 bit individually to 64 bit at even index of poly
        __m256i tmp = _mm256_clmulepi64_epi128(highBytes, poly, 0);

        // Shifting individual 128 bit to left by 1*8 bits
        nexttweak = _mm256_bslli_epi128(tweak128x4, 1);
        nexttweak = _mm256_xor_si256(nexttweak, tmp);

        return nexttweak;
    }

#ifdef USE_AVX512

    /* Generate next 4 tweaks with 2^8 multiplier */
    static inline __m512i nextTweaks(__m512i tweak128x4)
    {

        const __m512i poly =
            _mm512_set_epi64(0, 0x87, 0, 0x87, 0, 0x87, 0, 0x87);
        __m512i nexttweak;

        // Shifting individual 128 bit to right by 15*8 bits
        __m512i highBytes = _mm512_bsrli_epi128(tweak128x4, 15);

        // Multiplying each 128 bit individually to 64 bit at even index of poly
        __m512i tmp = _mm512_clmulepi64_epi128(highBytes, poly, 0);

        // Shifting individual 128 bit to left by 1*8 bits
        nexttweak = _mm512_bslli_epi128(tweak128x4, 1);
        nexttweak = _mm512_xor_si512(nexttweak, tmp);

        return nexttweak;
    }
#endif
}} // namespace alcp::cipher::aes

#endif /* _CIPHER_AES_CTR_HH_ */