/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"
/*
 *  Arithmetic operations needed for x25519.
 *  Data is packed in radix 51 format for carrless intermediate computation.
 */
static inline void
alcp_add_sub_x25519(const __m512i in1,
                    const __m512i in2,
                    const __m512i subConst_512,
                    __m512i&      out1,
                    __m512i&      out2)
{
    out1 = _mm512_add_epi64(in1, in2);

    __m512i temp = _mm512_add_epi64(in1, subConst_512);
    out2         = _mm512_sub_epi64(temp, in2);
}

static inline void
alcp_add_sub_x25519(__m512i& in1, __m512i& in2, const __m512i subConst_512)
{
    __m512i tempadd = _mm512_add_epi64(in1, in2);

    in1 = _mm512_add_epi64(in1, subConst_512);
    in2 = _mm512_sub_epi64(in1, in2);

    in1 = tempadd;
}

static inline void
alcp_add_sub_x25519(__m512i&      in1,
                    __m512i&      in2,
                    __m512i&      in3,
                    __m512i&      in4,
                    const __m512i subConst_512)
{
    __m512i temp1 = _mm512_add_epi64(in1, in2);
    __m512i temp3 = _mm512_add_epi64(in3, in4);

    in1 = _mm512_add_epi64(in1, subConst_512);
    in3 = _mm512_add_epi64(in3, subConst_512);

    in2 = _mm512_sub_epi64(in1, in2);
    in4 = _mm512_sub_epi64(in3, in4);

    in1 = temp1;
    in3 = temp3;
}

static inline void
alcp_sum_x25519(__m512i* output, __m512i in1, __m512i in2)
{
    *output = _mm512_add_epi64(in1, in2);
}

static inline void
alcp_difference_x25519(__m512i*      out,
                       const __m512i in1,
                       const __m512i in2,
                       const __m512i add_512)
{
    __m512i temp = _mm512_add_epi64(in1, add_512);
    *out         = _mm512_sub_epi64(temp, in2);
}

static inline void
alcp_swap_conditional(__m512i* a_512, __m512i* b_512, Uint64 iswap)
{
    const __m512i swap_512 = _mm512_set1_epi64(-iswap);
    __m512i       x_512;

    x_512  = _mm512_xor_epi64(*a_512, *b_512);
    x_512  = _mm512_and_epi64(swap_512, x_512);
    *a_512 = _mm512_xor_epi64(*a_512, x_512);
    *b_512 = _mm512_xor_epi64(*b_512, x_512);
}