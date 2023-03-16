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

#include "avx2.hh"

#include "alcp/cipher/aesni.hh" // template code in aes_ctr.hh needs aesni.hh

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ctr.hh"

#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher::aesni {

void
ctrInit(__m128i*     c1,
        const Uint8* pIv,
        __m128i*     one_lo,
        __m128i*     one_x,
        __m128i*     two_x,
        __m128i*     three_x,
        __m128i*     four_x,
        __m128i*     eight_x,
        __m128i*     swap_ctr)
{

    *one_x   = alcp_set_epi32(1, 0, 0, 0);
    *two_x   = alcp_set_epi32(2, 0, 0, 0);
    *three_x = alcp_set_epi32(3, 0, 0, 0);
    *four_x  = alcp_set_epi32(4, 0, 0, 0);
    one_lo   = one_x;

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    *swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    // nonce counter
    *c1 = alcp_loadu((__m128i*)pIv);
    *c1 = alcp_shuffle_epi8(*c1, *swap_ctr);
}

Uint64
ctrProcessAvx2(const Uint8*   p_in_x,
               Uint8*         p_out_x,
               Uint64         blocks,
               const __m128i* pkey128,
               const Uint8*   pIv,
               int            nRounds)
{
    auto p_in_128  = reinterpret_cast<const __m128i*>(p_in_x);
    auto p_out_128 = reinterpret_cast<__m128i*>(p_out_x);

    return alcp::cipher::aes::ctrBlk(
        p_in_128, p_out_128, blocks, pkey128, pIv, nRounds, 1);
}

} // namespace alcp::cipher::aesni
