/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#define NUM_PARALLEL_ZMMS 4
#define MAX_NUM_512_BLKS  8

/*_mm_prefetch accepts const void*` arguments for GCC / ICC
whereas MSVC still expects `const char* ` */
#ifdef _WIN32
#define cast_to(ptr) ((const char*)ptr)
#else
#define cast_to(ptr) ((void*)ptr)
#endif

namespace alcp::cipher::vaes512 {

// dynamic Unrolling
int inline dynamicUnroll(Uint64 blocks)
{
    int num_512_blks = 0;

    // 4 blocks in 512 bit
    if (blocks >= 32) {
        num_512_blks = 8; // 8x4 = 32 blks = 32x128/8 = 512 bytes
    } else if (blocks >= 16) {
        num_512_blks = 4; // 4x4 blks = 256 bytes
    } else if (blocks >= 8) {
        num_512_blks = 2;
    } else if (blocks >= 4) {
        num_512_blks = 1;
    }

    return num_512_blks;
}

void inline computeHashSubKeys(int           num_512_blks,
                               __m128i       Hsubkey_128,
                               __m512i*      p512GcmCtxHashSubkeyTable,
                               __m512i*      pHashSubkeyTableLocal,
                               const __m128i const_factor_128)
{
    __m128i* pHashSubkeyTableLocal_128;

    const __m512i const_factor_512 = _mm512_set_epi64(0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1,
                                                      0xC200000000000000,
                                                      0x1);

    pHashSubkeyTableLocal_128 = (__m128i*)pHashSubkeyTableLocal;

    __m128i h_128_0, h_128_1, h_128_2;
    aesni::gMul(Hsubkey_128, Hsubkey_128, h_128_2, const_factor_128); // 2
    aesni::gMul(h_128_2, Hsubkey_128, h_128_1, const_factor_128);     // 1
    aesni::gMul(h_128_1, Hsubkey_128, h_128_0, const_factor_128);     // 0

    pHashSubkeyTableLocal_128[3] = Hsubkey_128;
    pHashSubkeyTableLocal_128[2] = h_128_2;
    pHashSubkeyTableLocal_128[1] = h_128_1;
    pHashSubkeyTableLocal_128[0] = h_128_0;

    // store to gcm ctx
    _mm512_storeu_si512(p512GcmCtxHashSubkeyTable, pHashSubkeyTableLocal[0]);
    p512GcmCtxHashSubkeyTable++;

    const Uint64* H4_64 = (const Uint64*)pHashSubkeyTableLocal_128;

    __m512i Hsubkey_4 = _mm512_set_epi64(H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0],
                                         H4_64[1],
                                         H4_64[0]);

    for (int i = 1; i < num_512_blks; i++) {
        gMulParallel4(pHashSubkeyTableLocal[i],
                      pHashSubkeyTableLocal[i - 1],
                      Hsubkey_4,
                      const_factor_512);

        // store to gcm ctx
        _mm512_storeu_si512(p512GcmCtxHashSubkeyTable,
                            pHashSubkeyTableLocal[i]);
        p512GcmCtxHashSubkeyTable++;
    }
}

void inline getPrecomputedTable(bool     isFirstUpdate,
                                __m512i* p512GcmCtxHashSubkeyTable,
                                __m512i* pHashSubkeyTableLocal,
                                int      num_512_blks,
                                alcp::cipher::GcmAuthData* gcmAuthData,
                                __m128i                    const_factor_128)
{

    if (isFirstUpdate
        || (num_512_blks > gcmAuthData->m_num_512blks_precomputed)) {
        computeHashSubKeys(num_512_blks,
                           gcmAuthData->m_hash_subKey_128,
                           p512GcmCtxHashSubkeyTable,
                           pHashSubkeyTableLocal,
                           const_factor_128);

        gcmAuthData->m_num_512blks_precomputed = num_512_blks;
    } else if (num_512_blks > 4) {
        for (int i = 0; i < num_512_blks; i += 4) {
            pHashSubkeyTableLocal[0] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable);
            pHashSubkeyTableLocal[1] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 1);
            pHashSubkeyTableLocal[2] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 2);
            pHashSubkeyTableLocal[3] =
                _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 3);

            pHashSubkeyTableLocal += 4;
            p512GcmCtxHashSubkeyTable += 4;
        }
    }
}

} // namespace alcp::cipher::vaes512