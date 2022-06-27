/*
 * Copyright (C) 2021-2022, Advanced Micro Devices. All rights reserved.
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

#ifndef _CIPHER_AVX256_HH
#define _CIPHER_AVX256_HH 2

#include <immintrin.h>

namespace alcp::cipher { namespace vaes {

    // load functions
    static inline __m256i alcp_loadu(__m256i* ad)
    {
        return _mm256_loadu_si256(ad);
    }
    static inline __m256i alcp_loadu(const __m256i* ad)
    {
        return _mm256_loadu_si256(ad);
    }
    static inline __m256i alcp_loadu_128(__m256i* ad)
    {
        // Mask for loading and storing half register
        __m256i mask_lo = _mm256_set_epi64x(0, 0, 1UL << 63, 1UL << 63);
        return _mm256_maskload_epi64((long long*)ad, mask_lo);
    }
    static inline __m256i alcp_loadu_128(const __m256i* ad)
    {
        // Mask for loading and storing half register
        __m256i mask_lo = _mm256_set_epi64x(0, 0, 1UL << 63, 1UL << 63);
        return _mm256_maskload_epi64((long long*)ad, mask_lo);
    }

    // xor functions.
    static inline __m256i alcp_xor(__m256i a, __m256i b)
    {
        return _mm256_xor_si256(a, b);
    }

    // add functions.
    static inline __m256i alcp_set_epi32(
        int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7)
    {
        return _mm256_set_epi32(a0, a1, a2, a3, a4, a5, a6, a7);
    }

    // add functions.
    static inline __m256i alcp_add_epi32(__m256i a, __m256i b)
    {
        return _mm256_add_epi32(a, b);
    }

    // shuffle functions.
    static inline __m256i alcp_shuffle_epi8(__m256i a, __m256i b)
    {
        return _mm256_shuffle_epi8(a, b);
    }

    // store functions
    static inline void alcp_storeu(__m256i* ad, __m256i x)
    {
        _mm256_storeu_si256(ad, x);
    }

    static inline void alcp_storeu_128(__m256i* ad, __m256i x)
    {
        // Mask for loading and storing half register
        __m256i mask_lo = _mm256_set_epi64x(0, 0, 1UL << 63, 1UL << 63);
        _mm256_maskstore_epi64((long long*)ad, mask_lo, x);
    }

}} // namespace alcp::cipher::vaes

#endif /* _CIPHER_AVX256_HH */
