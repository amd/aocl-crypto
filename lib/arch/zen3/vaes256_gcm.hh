/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#define NUM_PARALLEL_YMMS 4
#define MAX_NUM_256_BLKS  8 // 16 // 24

/*_mm_prefetch accepts const void*` arguments for GCC / ICC
whereas MSVC still expects `const char* ` */
#ifdef _WIN32
#define cast_to(ptr) ((const char*)ptr)
#else
#define cast_to(ptr) ((void*)ptr)
#endif

namespace alcp::cipher::vaes {

// dynamic Unrolling
int inline dynamicUnroll(Uint64 blocks)
{
    auto constexpr threshold_4x256_2unroll = 4 * 2 * 2;

    /*
     * Limited branches in choosing kernels improves overall performance for
     * different input blocksizes. This brings down overall backend stalls. This
     * effect needs to be verified when applications uses prodominantly single
     * block size for encrypt/decrypt.
     */
    int num_256_blks = 0;

    if (blocks >= threshold_4x256_2unroll) {
        num_256_blks = 8; // 8x2 = 16 blks
    } else if (blocks >= 2) {
        num_256_blks = 1;
    }

    return num_256_blks;
}

static inline void
gMulParallel2(__m256i&      res,
              __m256i       H21_256,
              __m256i       H22_256,
              const __m256i const_factor_256)
{
    __m256i       z0_256, z1_256, z1L_256, z2_256;
    constexpr int cSwizzle = SWIZZLE(2, 3, 0, 1);

    computeKaratsubaComponents(H21_256, H22_256, z0_256, z1_256, z2_256);

    /* compute: z0 = x0y0
     *        z0 component of below equation:
     *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
     *
     *  compute: z2 = x1y1
     *        z2 component of below equation:
     *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
     */

    // z1 - zo -z2 = z1 xor z0 xor z2
    z1_256 = _mm256_xor_si256(z1_256, z0_256);
    z1_256 = _mm256_xor_si256(z1_256, z2_256);

    // z1Low64bit
    z1L_256 = _mm256_bslli_epi128(z1_256, 8);
    // z1High64bit
    z1_256 = _mm256_bsrli_epi128(z1_256, 8);

    // low 128bit CLMul result for 4 GHASH
    z0_256 = _mm256_xor_si256(z0_256, z1L_256);
    // high 128bit CLMul result for 4 GHASH
    z2_256 = _mm256_xor_si256(z2_256, z1_256);

    /* Modulo reduction of (high 128bit: low 128bit)  components to
     * 128bit Fast modulo reduction  Algorithm 4 in
     * https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
     *
     */
    // A1:A0 = X0 *  0xc200000000000000
    z1_256 = _mm256_clmulepi64_epi128(z0_256, const_factor_256, 0x10);
    // shuffle to X0:X1
    z0_256 = _mm256_shuffle_epi32(z0_256, cSwizzle);
    // B1:B0 = X0 + A1: X1 + A0
    z1_256 = _mm256_xor_si256(z1_256, z0_256);
    // C1:C0 = B0 *  0xc200000000000000
    z0_256 = _mm256_clmulepi64_epi128(z1_256, const_factor_256, 0x10);
    // shuffle to B0:B1
    z1_256 = _mm256_shuffle_epi32(z1_256, cSwizzle);

    // D1:D0 = B0 + C1: B1 + C0
    z0_256 = _mm256_xor_si256(z1_256, z0_256);
    // D1 + X3: D0 + X2
    res = _mm256_xor_si256(z2_256, z0_256);
}

void inline computeHashSubKeys(int           num_256_blks,
                               __m128i       Hsubkey_128,
                               __m256i*      pHashSubkeyTableLocal,
                               const __m128i const_factor_128)
{
    __m128i*      pHashSubkeyTableLocal_128;
    const Uint64* H1_64 = (const Uint64*)&Hsubkey_128;

    pHashSubkeyTableLocal_128 = (__m128i*)pHashSubkeyTableLocal;
    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    pHashSubkeyTableLocal[0] = _mm256_set_epi64x(H1_64[1], // 1
                                                 H1_64[0], // 1
                                                 0,        // 0
                                                 0);       // 0

    __m128i h_128_0;
    aesni::gMul(Hsubkey_128, Hsubkey_128, h_128_0, const_factor_128);

    _mm_storeu_si128((pHashSubkeyTableLocal_128), h_128_0);

    const Uint64* H2_64 = (const Uint64*)pHashSubkeyTableLocal_128;

    __m256i Hsubkey_2 =
        _mm256_set_epi64x(H2_64[1], H2_64[0], H2_64[1], H2_64[0]);

    for (int i = 1; i < num_256_blks; i++) {
        gMulParallel2(pHashSubkeyTableLocal[i],
                      pHashSubkeyTableLocal[i - 1],
                      Hsubkey_2,
                      const_factor_256);
    }
}

void inline getPrecomputedTable(bool     isFirstUpdate,
                                __m256i* pHsubkey_256_precomputed,
                                __m256i* pHsubkey_256,
                                int      num_256_blks,
                                alcp::cipher::GcmAuthData* gcm,
                                __m128i                    const_factor_128)
{

    if (isFirstUpdate || (num_256_blks > gcm->m_num_256blks_precomputed)) {

        computeHashSubKeys(num_256_blks,
                           gcm->m_hash_subKey_128,
                           pHsubkey_256,
                           const_factor_128);

        gcm->m_num_256blks_precomputed = num_256_blks;

        for (int i = 0; i < num_256_blks; i++) {
            __m256i temp = _mm256_loadu_si256(pHsubkey_256);
            _mm256_storeu_si256(pHsubkey_256_precomputed, temp);

            pHsubkey_256++;
            pHsubkey_256_precomputed++;
        }
    } else {
        for (int i = 0; i < num_256_blks; i++) {
            __m256i temp = _mm256_loadu_si256(pHsubkey_256_precomputed);
            _mm256_storeu_si256(pHsubkey_256, temp);

            pHsubkey_256++;
            pHsubkey_256_precomputed++;
        }
    }
}

} // namespace alcp::cipher::vaes
