/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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
#define MAX_NUM_512_BLKS    8 // 16 // 24

/*_mm_prefetch accepts const void*` arguments for GCC / ICC
whereas MSVC still expects `const char* ` */
#ifdef _WIN32
#define cast_to(ptr) ((const char*)ptr)
#else
#define cast_to(ptr) ((void*)ptr)
#endif

namespace alcp::cipher::vaes512 {

static inline void
printText(Uint32* I, Uint64 len, char* s)
{
    printf("\n %s ", s);
    for (int x = len - 1; x >= 0; x--) {
        printf(" %8x", *(I + x));
    }
}

// dynamic Unrolling
int inline dynamicUnroll(Uint64 blocks)
{
    /* 64 (16*4) blocks per loop. Minimum 20 loops required to get
     * benefit of precomputing hash^x table.
     * 32 (16*2) blocks per loop needs minimum 4 loops to get benefit from
     * precomputing hash^x table.
     */

    // 16*num_unroll*MinloopCount

    auto constexpr threshold_4x512_2unroll = 16 * 2 * 2;

#if 0
    int num_512_blks                       = 0;
    auto constexpr threshold_4x512_4unroll = 16 * 4 * 20;
    if (blocks >= threshold_4x512_4unroll) {
        num_512_blks = 16; // 16x4 = 64 blks
    } else if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 8; // 8x4 = 32 blks
    } else if (blocks >= 4) {
        num_512_blks = 1; // 1x4 = 4 blks
    }

    if (num_512_blks > MAX_NUM_512_BLKS) {
        num_512_blks = MAX_NUM_512_BLKS;
    }

#else // disable 64 blks kernel

    /*
     * Limited branches in choosing kernels improves overall performance for
     * different input blocksizes. This brings down overall backend stalls. This
     * effect needs to be verified when applications uses prodominantly single
     * block size for encrypt/decrypt.
     */
    int num_512_blks = 1;
    if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 8; // 8x4 = 32 blks
    }

#endif
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

    gMul(Hsubkey_128, Hsubkey_128, pH_512_128[0][2], const_factor_256);
    gMul(pH_512_128[0][2], Hsubkey_128, pH_512_128[0][1], const_factor_256);
    gMul(pH_512_128[0][1], Hsubkey_128, pH_512_128[0][0], const_factor_256);

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
            Hsubkey_512[i], Hsubkey_512[i - 1], Hsubkey_4, const_factor_512);
    }
}

void inline computeHashSubKeys(int           num_512_blks,
                               __m128i       Hsubkey_128,
                               __m512i*      Hsubkey_512,
                               const __m128i const_factor_128)
{
    __m128i*      pH_512_128;
    const Uint64* H1_64 = (const Uint64*)&Hsubkey_128;

    const __m512i const_factor_512 = _mm512_loadu_epi64(const_factor);
    pH_512_128                     = (__m128i*)Hsubkey_512;

    Hsubkey_512[0] = _mm512_set_epi64(H1_64[1], // 3
                                      H1_64[0], // 3
                                      0,        // 2
                                      0,        // 2
                                      0,        // 1
                                      0,        // 1
                                      0,        // 0
                                      0);       // 0
    // FIXME: load & store can be avoided!
    __m128i h_128_2 = _mm_loadu_si128(pH_512_128 + 2);
    __m128i h_128_1 = _mm_loadu_si128(pH_512_128 + 1);
    __m128i h_128_0 = _mm_loadu_si128(pH_512_128);

    gMul(Hsubkey_128, Hsubkey_128, h_128_2, const_factor_128);
    gMul(h_128_2, Hsubkey_128, h_128_1, const_factor_128);
    gMul(h_128_1, Hsubkey_128, h_128_0, const_factor_128);

    _mm_storeu_si128((pH_512_128 + 2), h_128_2);
    _mm_storeu_si128((pH_512_128 + 1), h_128_1);
    _mm_storeu_si128((pH_512_128), h_128_0);

    const Uint64* H4_64 = (const Uint64*)pH_512_128;

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
            Hsubkey_512[i], Hsubkey_512[i - 1], Hsubkey_4, const_factor_512);
    }
}

} // namespace alcp::cipher::vaes512