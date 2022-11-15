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

#pragma once

#include <immintrin.h>
#include <stdint.h>

namespace alcp::cipher { namespace vaes512 {

    // load functions
    static inline __m512i alcp_loadu(__m512i* ad)
    {
        return _mm512_loadu_si512(ad);
    }
    static inline __m512i alcp_loadu(const __m512i* ad)
    {
        return _mm512_loadu_si512(ad);
    }
    static inline void alcp_loadu_4values(
        const __m512i* ad, __m512i& a1, __m512i& a2, __m512i& a3, __m512i& a4)
    {
        a1 = _mm512_loadu_si512(ad);
        a2 = _mm512_loadu_si512(ad + 1);
        a3 = _mm512_loadu_si512(ad + 2);
        a4 = _mm512_loadu_si512(ad + 3);
    }
    static inline void alcp_loadu_4values(
        __m512i* ad, __m512i& a1, __m512i& a2, __m512i& a3, __m512i& a4)
    {
        a1 = _mm512_loadu_si512(ad);
        a2 = _mm512_loadu_si512(ad + 1);
        a3 = _mm512_loadu_si512(ad + 2);
        a4 = _mm512_loadu_si512(ad + 3);
    }
    static inline __m512i alcp_loadu_128(__m512i* ad)
    {
        __m512i ret = _mm512_setr_epi64(
            ((uint64_t*)ad)[0], ((uint64_t*)ad)[1], 0, 0, 0, 0, 0, 0);
        return ret;
    }
    static inline __m512i alcp_loadu_128(const __m512i* ad)
    {
        __m512i ret = _mm512_setr_epi64(
            ((uint64_t*)ad)[0], ((uint64_t*)ad)[1], 0, 0, 0, 0, 0, 0);
        return ret;
    }

    // xor functions.
    static inline __m512i alcp_xor(__m512i a, __m512i b)
    {
        return _mm512_xor_si512(a, b);
    }

    static inline void alcp_xor_4values(__m512i  a1, // inputs A
                                        __m512i  a2,
                                        __m512i  a3,
                                        __m512i  a4,
                                        __m512i  b1, // inputs B
                                        __m512i  b2,
                                        __m512i  b3,
                                        __m512i  b4,
                                        __m512i& c1, // outputs C = A xor B
                                        __m512i& c2,
                                        __m512i& c3,
                                        __m512i& c4)
    {
        c1 = _mm512_xor_si512(a1, b1);
        c2 = _mm512_xor_si512(a2, b2);
        c3 = _mm512_xor_si512(a3, b3);
        c4 = _mm512_xor_si512(a4, b4);
    }

    // add functions.
    // clang-format off
    static inline __m512i alcp_set_epi32(
        int a0,  int a1,  int a2,  int a3,
        int a4,  int a5,  int a6,  int a7,
        int a8,  int a9,  int a10, int a11,
        int a12, int a13, int a14, int a15)
    {
        return _mm512_set_epi32(a0,  a1,  a2,  a3,
                                a4,  a5,  a6,  a7,
                                a8,  a9,  a10, a11,
                                a12, a13, a14, a15);
    }
    // clang-format on

    // add functions.
    static inline __m512i alcp_add_epi32(__m512i a, __m512i b)
    {
        return _mm512_add_epi32(a, b);
    }

    // shuffle functions.
    static inline __m512i alcp_shuffle_epi8(__m512i a, __m512i b)
    {
        return _mm512_shuffle_epi8(a, b);
    }

    static inline void alcp_shuffle_epi8(__m512i  in1, // inputs
                                         __m512i  in2,
                                         __m512i  in3,
                                         __m512i  in4,
                                         __m512i  swap_ctr, // swap control
                                         __m512i& out1,     // outputs
                                         __m512i& out2,
                                         __m512i& out3,
                                         __m512i& out4)
    {
        out1 = _mm512_shuffle_epi8(in1, swap_ctr);
        out2 = _mm512_shuffle_epi8(in2, swap_ctr);
        out3 = _mm512_shuffle_epi8(in3, swap_ctr);
        out4 = _mm512_shuffle_epi8(in4, swap_ctr);
    }

    // store functions
    static inline void alcp_storeu(__m512i* ad, __m512i x)
    {
        _mm512_storeu_si512(ad, x);
    }

    static inline void alcp_storeu_4values(
        __m512i* ad, __m512i a1, __m512i a2, __m512i a3, __m512i a4)
    {
        _mm512_storeu_si512(ad, a1);
        _mm512_storeu_si512(ad + 1, a2);
        _mm512_storeu_si512(ad + 2, a3);
        _mm512_storeu_si512(ad + 3, a4);
    }

    static inline void alcp_storeu_128(__m512i* ad, __m512i x)
    {
        ((uint64_t*)ad)[0] = x[0];
        ((uint64_t*)ad)[1] = x[1];
    }

}} // namespace alcp::cipher::vaes512
