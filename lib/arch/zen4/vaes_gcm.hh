/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include <cstdint>
#include <immintrin.h>

#include "alcp/types.hh"

#define PARALLEL_512_BLKS_4 4
#define MAX_NUM_512_BLKS    16 // 24

 /*_mm_prefetch accepts const void*` arguments for GCC / ICC 
whereas MSVC still expects `const char* ` */
#ifdef WIN32  
#define cast_to(ptr) ((const char*)ptr)
#else
#define cast_to(ptr) ((void*)ptr)
#endif

namespace alcp::cipher::vaes512 {

void inline gcmCryptInit(__m512i* c1,
                         __m128i  iv_128,
                         __m512i* one_lo,
                         __m512i* one_x,
                         __m512i* two_x,
                         __m512i* three_x,
                         __m512i* four_x,
                         __m512i* swap_ctr)
{

    *one_lo = alcp_set_epi32(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
    *one_x  = alcp_set_epi32(4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0);
    *two_x  = alcp_set_epi32(8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0);
    *three_x =
        alcp_set_epi32(12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0);
    *four_x =
        alcp_set_epi32(16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0);

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    *swap_ctr = _mm512_set_epi32(0x0c0d0e0f,
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100);
    // nonce counter
    *c1 = _mm512_broadcast_i64x2(iv_128);

    __m512i onehi =
        _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3);
    *c1 = alcp_add_epi32(*c1, onehi);
}

Uint64
gcmBlk_512_decRounds10(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_decRounds12(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_decRounds14(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_encRounds10(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_encRounds12(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_encRounds14(const __m512i* p_in_x,
                       __m512i*       p_out_x,
                       Uint64         blocks,
                       const __m128i* pkey128,
                       const Uint8*   pIv,
                       int            nRounds,
                       Uint8          factor,
                       // gcm specific params
                       __m128i* pgHash_128,
                       __m128i  Hsubkey_128,
                       __m128i  iv_128,
                       __m128i  reverse_mask_128,
                       int      remBytes,
                       Uint64*  pHashSubkeyTable);

Uint64
gcmBlk_512_enc(const __m512i* p_in_x,
               __m512i*       p_out_x,
               Uint64         blocks,
               const __m128i* pkey128,
               const Uint8*   pIv,
               int            nRounds,
               Uint8          factor,
               // gcm specific params
               __m128i* pgHash_128,
               __m128i  Hsubkey_128,
               __m128i  iv_128,
               __m128i  reverse_mask_128,
               int      remBytes,
               Uint64*  pHashSubkeyTable);

// dynamic Unrolling
int inline dynamicUnroll(Uint64 blocks, bool& do_4_unroll, bool& do_2_unroll)
{
    /* 64 (16*4) blocks per loop. Minimum 20 loops required to get
     * benefit of precomputing hash^x table.
     * 32 (16*2) blocks per loop needs minimum 4 loops to get benefit from
     * precomputing hash^x table.
     */

    // 16*num_unroll*MinloopCount
    auto constexpr threshold_4x512_4unroll = 16 * 4 * 20;
    auto constexpr threshold_4x512_2unroll = 16 * 2 * 2;
    int num_512_blks                       = 0;
    if (blocks >= threshold_4x512_4unroll) {
        num_512_blks = 4 * 4;
        do_4_unroll  = true;
    } else if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 4 * 2;
        do_2_unroll  = true;
    } else if (blocks >= 16) {
        num_512_blks = 4; // uses 4x512bit loop
    } else if (blocks >= 8) {
        num_512_blks = 2; // uses 2x512bit loop
    } else if (blocks >= 4) {
        num_512_blks = 1; // uses 1x512bit loop
    }

    if (num_512_blks > MAX_NUM_512_BLKS) {
        num_512_blks = MAX_NUM_512_BLKS;
    }
    return num_512_blks;
};

void inline computeHashSubKeys(int           num_512_blks,
                               __m128i       Hsubkey_128,
                               __m512i*      Hsubkey_512,
                               const __m256i const_factor_256)
{
    __m128i*      pH_512_128[MAX_NUM_512_BLKS];
    const Uint64* H1_64 = (const Uint64*)&Hsubkey_128;

    const __m512i const_factor_512 = _mm512_loadu_epi64(const_factor);
    pH_512_128[0]                  = (__m128i*)&Hsubkey_512[0];

    Hsubkey_512[0] = _mm512_set_epi64(H1_64[1], // 3
                                      H1_64[0], // 3
                                      0,        // 2
                                      0,        // 2
                                      0,        // 1
                                      0,        // 1
                                      0,        // 0
                                      0);       // 0

    gMul(Hsubkey_128, Hsubkey_128, &pH_512_128[0][2], const_factor_256);
    gMul(pH_512_128[0][2], Hsubkey_128, &pH_512_128[0][1], const_factor_256);
    gMul(pH_512_128[0][1], Hsubkey_128, &pH_512_128[0][0], const_factor_256);

    const Uint64* H4_64 = (const Uint64*)&pH_512_128[0][0];

    __m512i Hsubkey_4 = _mm512_set_epi64(H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0]);

    for (int i = 1; i < num_512_blks; i++) {
        gMulParallel4(
            &Hsubkey_512[i], Hsubkey_512[i - 1], Hsubkey_4, const_factor_512);
    }
}

} // namespace alcp::cipher::vaes512