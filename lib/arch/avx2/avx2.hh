/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include <immintrin.h>

namespace alcp::cipher { namespace aesni {

    // load functions
    static inline __m128i alcp_loadu(__m128i* ad)
    {
        return _mm_loadu_si128(ad);
    }

    static inline __m128i alcp_loadu(const __m128i* ad)
    {
        return _mm_loadu_si128(ad);
    }

    static inline __m128i alcp_loadu_128(__m128i* ad)
    {
        // loadu_128 is same as alcp_loadu
        return _mm_loadu_si128(ad);
    }
    static inline __m128i alcp_loadu_128(const __m128i* ad)
    {
        // loadu_128 is same as alcp_loadu
        return _mm_loadu_si128(ad);
    }

    // xor functions.
    static inline __m128i alcp_xor(__m128i a, __m128i b)
    {
        return _mm_xor_si128(a, b);
    }

    // add functions.
    static inline __m128i alcp_set_epi32(int a0, int a1, int a2, int a3)
    {
        return _mm_set_epi32(a0, a1, a2, a3);
    }

    // add functions.
    static inline __m128i alcp_add_epi32(__m128i a, __m128i b)
    {
        return _mm_add_epi32(a, b);
    }

    static inline __m128i alcp_add_epi64(__m128i a, __m128i b)
    {
        return _mm_add_epi64(a, b);
    }

    // shuffle functions.
    static inline __m128i alcp_shuffle_epi8(__m128i a, __m128i b)
    {
        return _mm_shuffle_epi8(a, b);
    }

    // store functions
    static inline void alcp_storeu(__m128i* ad, __m128i x)
    {
        _mm_storeu_si128(ad, x);
    }

    static inline void alcp_storeu_128(__m128i* ad, __m128i x)
    {
        // storeu_128 is same as alcp_storeu
        _mm_storeu_si128(ad, x);
    }

}} // namespace alcp::cipher::aesni
