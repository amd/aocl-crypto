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
        __m256i mask_lo = _mm256_set_epi64x(0,
                                            0,
                                            static_cast<long long>(1UL) << 63,
                                            static_cast<long long>(1UL) << 63);
        return _mm256_maskload_epi64((long long*)ad, mask_lo);
    }

    static inline __m256i alcp_loadu_128(const __m256i* ad)
    {
        // Mask for loading and storing half register
        __m256i mask_lo = _mm256_set_epi64x(0,
                                            0,
                                            static_cast<long long>(1UL) << 63,
                                            static_cast<long long>(1UL) << 63);
        return _mm256_maskload_epi64((long long*)ad, mask_lo);
    }

    static inline void alcp_loadu_4values(
        const __m256i* ad, __m256i& a1, __m256i& a2, __m256i& a3, __m256i& a4)
    {
        a1 = _mm256_loadu_si256(ad);
        a2 = _mm256_loadu_si256(ad + 1);
        a3 = _mm256_loadu_si256(ad + 2);
        a4 = _mm256_loadu_si256(ad + 3);
    }

    static inline void alcp_loadu_4values(
        __m256i* ad, __m256i& a1, __m256i& a2, __m256i& a3, __m256i& a4)
    {
        a1 = _mm256_loadu_si256(ad);
        a2 = _mm256_loadu_si256(ad + 1);
        a3 = _mm256_loadu_si256(ad + 2);
        a4 = _mm256_loadu_si256(ad + 3);
    }

    // xor functions.
    static inline __m256i alcp_xor(__m256i a, __m256i b)
    {
        return _mm256_xor_si256(a, b);
    }

    static inline void alcp_xor_4values(__m256i  a1, // inputs A
                                        __m256i  a2,
                                        __m256i  a3,
                                        __m256i  a4,
                                        __m256i  b1, // inputs B
                                        __m256i  b2,
                                        __m256i  b3,
                                        __m256i  b4,
                                        __m256i& c1, // outputs C = A xor B
                                        __m256i& c2,
                                        __m256i& c3,
                                        __m256i& c4)
    {
        c1 = _mm256_xor_si256(a1, b1);
        c2 = _mm256_xor_si256(a2, b2);
        c3 = _mm256_xor_si256(a3, b3);
        c4 = _mm256_xor_si256(a4, b4);
    }

    static inline void alcp_xor_4values(
        __m256i  a1, // inputs A
        __m256i  a2,
        __m256i  a3,
        __m256i  a4,
        __m256i& b1, // inputs B and output A xor B
        __m256i& b2,
        __m256i& b3,
        __m256i& b4)
    {
        b1 = _mm256_xor_si256(a1, b1);
        b2 = _mm256_xor_si256(a2, b2);
        b3 = _mm256_xor_si256(a3, b3);
        b4 = _mm256_xor_si256(a4, b4);
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

    static inline void alcp_shuffle_epi8(
        const __m256i& in1, // inputs
        const __m256i& in2,
        const __m256i& in3,
        const __m256i& in4,
        const __m256i& swap_ctr, // swap control
        __m256i&       out1,     // outputs
        __m256i&       out2,
        __m256i&       out3,
        __m256i&       out4)
    {
        out1 = _mm256_shuffle_epi8(in1, swap_ctr);
        out2 = _mm256_shuffle_epi8(in2, swap_ctr);
        out3 = _mm256_shuffle_epi8(in3, swap_ctr);
        out4 = _mm256_shuffle_epi8(in4, swap_ctr);
    }

    // store functions
    static inline void alcp_storeu(__m256i* ad, __m256i x)
    {
        _mm256_storeu_si256(ad, x);
    }

    static inline void alcp_storeu_4values(
        __m256i* ad, __m256i a1, __m256i a2, __m256i a3, __m256i a4)
    {
        _mm256_storeu_si256(ad, a1);
        _mm256_storeu_si256(ad + 1, a2);
        _mm256_storeu_si256(ad + 2, a3);
        _mm256_storeu_si256(ad + 3, a4);
    }

    static inline void alcp_storeu_128(__m256i* ad, __m256i x)
    {
        // Mask for loading and storing half register
        __m256i mask_lo = _mm256_set_epi64x(0,
                                            0,
                                            static_cast<long long>(1UL) << 63,
                                            static_cast<long long>(1UL) << 63);
        _mm256_maskstore_epi64((long long*)ad, mask_lo, x);
    }

}} // namespace alcp::cipher::vaes
