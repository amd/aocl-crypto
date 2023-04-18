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

/*
 *
 * Galois Multiplicaiton we use below algorithms from "Intel carry-less
 * multiplication instruction in gcm mode"
 * https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
 *     1. Aggregated Reduction and
 *     2. ModuloReduction algorithms
 *     3. Avoiding bit-reflection by modifying precomputed HashKey table as per
 * below paper
 *          Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation
 * on Intel® Architecture Processors. Intel White Paper, August 2010.
 *
 *
 */

#include <cstdint>
#include <immintrin.h>

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/cipher/gmul.hh"
#include "avx512.hh"
#include "avx512_gmul.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"
#include "vaes_gcm.hh"

#include "alcp/types.hh"

namespace alcp::cipher::vaes512 {

/**
 FIXME: gcm decrypt functions has been duplicated for all three rounds. Below
three functions has same code expect for assigning different func ptrs.
 1. gcmBlk_512_decRounds10
 2. gcmBlk_512_decRounds12
 3. gcmBlk_512_decRounds14

Use of branching to assign funPtrs(fAesEncryptNoLoad_4x512,
fAesEncryptNoLoad_2x512, fAesEncryptNoLoad_1x512) results in poor performance.

Use of lambdas also results in marginal loss in performance.

 */
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
                       Uint64*  pHashSubkeyTable)
{
    __m512i swap_ctr, c1;
    __m512i one_lo, one_x, two_x, three_x, four_x, eight_x;

    void (*fAesEncryptNoLoad_4x512)(
        __m512i & a, __m512i & b, __m512i & c, __m512i & d, const sKeys keys);
    void (*fAesEncryptNoLoad_2x512)(__m512i & a, __m512i & b, const sKeys keys);
    void (*fAesEncryptNoLoad_1x512)(__m512i & a, const sKeys keys);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    /* gcm init + Hash subkey init */
    gcmCryptInit(&c1,
                 iv_128,
                 &one_lo,
                 &one_x,
                 &two_x,
                 &three_x,
                 &four_x,
                 &eight_x,
                 &swap_ctr);

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T1);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys, nRounds);

/* FIXME: conditional branching to assign funPtrs results in performance drop.
   Due to this problem code has been duplicated for all three rounds.

   Code duplication needs to be fixed without performance degradation.

*/
#if 1
    fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds10;
    fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds10;
    fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds10;
#else
    fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds10;
    fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds10;
    fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds10;
    if (nRounds == 12) {
        fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds12;
        fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds12;
        fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds12;
    } else if (nRounds == 14) {
        fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds14;
        fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds14;
        fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds14;
    }
#endif

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int  num_512_blks = 0;
    bool do_4_unroll  = false;
    bool do_2_unroll  = false;

    num_512_blks = dynamicUnroll(blocks, do_4_unroll, do_2_unroll);

#if LOCAL_TABLE // local table improves performance of large block size (>8192
                // bytes)
    __attribute__((aligned(64))) Uint64 hashSubkeyTable[MAX_NUM_512_BLKS * 8];
    __m512i* Hsubkey_512 = (__m512i*)&hashSubkeyTable;
#else
    __m512i* Hsubkey_512 = (__m512i*)pHashSubkeyTable;
#endif

    if (num_512_blks) {
        computeHashSubKeys(
            num_512_blks, Hsubkey_128, Hsubkey_512, const_factor_256);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;
    Uint64 blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    if (do_4_unroll) {
        Uint64 blockCount_4x512_4_unroll = 16 * 4;

        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i  z0_512, z1_512, z2_512;
            __m512i  z0_512_t, z1_512_t, z2_512_t;
            int      n            = 12;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }

    } else if (do_2_unroll) {
        Uint64 blockCount_4x512_2_unroll = 16 * 2;

        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {

            __m512i z0_512, z1_512, z2_512;
            __m512i z0_512_t, z1_512_t, z2_512_t;

            int      n            = 4; // numParallel_512blks * k;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            // first iteration gmul
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }
    }

    __m512i* pHsubkey_512 = Hsubkey_512;
    Hsubkey_512_0         = _mm512_loadu_si512(pHsubkey_512);

    // if (do_one_parallel) {
    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

        Hsubkey_512_1 = Hsubkey_512[1];
        Hsubkey_512_2 = Hsubkey_512[2];
        Hsubkey_512_3 = Hsubkey_512[3];

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              pgHash_128,
              const_factor_256);

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

        (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }
    //}

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        c2 = alcp_add_epi32(c1, one_x);
        // printf("\n blockCount_2x512");
        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);
        gMulR(
            Hsubkey_512_0, a2, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        (*fAesEncryptNoLoad_2x512)(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);
        // printf("\n blockCount_1x512");
        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        (*fAesEncryptNoLoad_1x512)(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only
    // lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);
    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }
    }

    // clear all keys stored in registers.
    alcp_clear_keys_zmm(keys, nRounds);
    return blocks;
}

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
                       Uint64*  pHashSubkeyTable)
{
    __m512i swap_ctr, c1;
    __m512i one_lo, one_x, two_x, three_x, four_x, eight_x;

    void (*fAesEncryptNoLoad_4x512)(
        __m512i & a, __m512i & b, __m512i & c, __m512i & d, const sKeys keys);
    void (*fAesEncryptNoLoad_2x512)(__m512i & a, __m512i & b, const sKeys keys);
    void (*fAesEncryptNoLoad_1x512)(__m512i & a, const sKeys keys);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    /* gcm init + Hash subkey init */
    gcmCryptInit(&c1,
                 iv_128,
                 &one_lo,
                 &one_x,
                 &two_x,
                 &three_x,
                 &four_x,
                 &eight_x,
                 &swap_ctr);

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T1);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys, nRounds);

    fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds12;
    fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds12;
    fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds12;

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int  num_512_blks = 0;
    bool do_4_unroll  = false;
    bool do_2_unroll  = false;

    num_512_blks = dynamicUnroll(blocks, do_4_unroll, do_2_unroll);

#if LOCAL_TABLE // local table improves performance of large block size (>8192
                // bytes)
    __attribute__((aligned(64))) Uint64 hashSubkeyTable[MAX_NUM_512_BLKS * 8];
    __m512i* Hsubkey_512 = (__m512i*)&hashSubkeyTable;
#else
    __m512i* Hsubkey_512 = (__m512i*)pHashSubkeyTable;
#endif

    if (num_512_blks) {
        computeHashSubKeys(
            num_512_blks, Hsubkey_128, Hsubkey_512, const_factor_256);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;
    Uint64 blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    if (do_4_unroll) {
        Uint64 blockCount_4x512_4_unroll = 16 * 4;

        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i  z0_512, z1_512, z2_512;
            __m512i  z0_512_t, z1_512_t, z2_512_t;
            int      n            = 12;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }

    } else if (do_2_unroll) {
        Uint64 blockCount_4x512_2_unroll = 16 * 2;

        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {

            __m512i z0_512, z1_512, z2_512;
            __m512i z0_512_t, z1_512_t, z2_512_t;

            int      n            = 4; // numParallel_512blks * k;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            // first iteration gmul
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }
    }

    __m512i* pHsubkey_512 = Hsubkey_512;
    Hsubkey_512_0         = _mm512_loadu_si512(pHsubkey_512);

    // if (do_one_parallel) {
    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

        Hsubkey_512_1 = Hsubkey_512[1];
        Hsubkey_512_2 = Hsubkey_512[2];
        Hsubkey_512_3 = Hsubkey_512[3];

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              pgHash_128,
              const_factor_256);

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

        (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }
    //}

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        c2 = alcp_add_epi32(c1, one_x);
        // printf("\n blockCount_2x512");
        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);
        gMulR(
            Hsubkey_512_0, a2, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        (*fAesEncryptNoLoad_2x512)(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);
        // printf("\n blockCount_1x512");
        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        (*fAesEncryptNoLoad_1x512)(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only
    // lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);
    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }
    }

    // clear all keys stored in registers.
    alcp_clear_keys_zmm(keys, nRounds);
    return blocks;
}

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
                       Uint64*  pHashSubkeyTable)
{
    __m512i swap_ctr, c1;
    __m512i one_lo, one_x, two_x, three_x, four_x, eight_x;

    void (*fAesEncryptNoLoad_4x512)(
        __m512i & a, __m512i & b, __m512i & c, __m512i & d, const sKeys keys);
    void (*fAesEncryptNoLoad_2x512)(__m512i & a, __m512i & b, const sKeys keys);
    void (*fAesEncryptNoLoad_1x512)(__m512i & a, const sKeys keys);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    /* gcm init + Hash subkey init */
    gcmCryptInit(&c1,
                 iv_128,
                 &one_lo,
                 &one_x,
                 &two_x,
                 &three_x,
                 &four_x,
                 &eight_x,
                 &swap_ctr);

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T1);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys, nRounds);

    fAesEncryptNoLoad_4x512 = AesEncryptNoLoad_4x512Rounds14;
    fAesEncryptNoLoad_2x512 = AesEncryptNoLoad_2x512Rounds14;
    fAesEncryptNoLoad_1x512 = AesEncryptNoLoad_1x512Rounds14;

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int  num_512_blks = 0;
    bool do_4_unroll  = false;
    bool do_2_unroll  = false;

    num_512_blks = dynamicUnroll(blocks, do_4_unroll, do_2_unroll);

#if LOCAL_TABLE // local table improves performance of large block size (>8192
                // bytes)
    __attribute__((aligned(64))) Uint64 hashSubkeyTable[MAX_NUM_512_BLKS * 8];
    __m512i* Hsubkey_512 = (__m512i*)&hashSubkeyTable;
#else
    __m512i* Hsubkey_512 = (__m512i*)pHashSubkeyTable;
#endif

    if (num_512_blks) {
        computeHashSubKeys(
            num_512_blks, Hsubkey_128, Hsubkey_512, const_factor_256);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;
    Uint64 blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    if (do_4_unroll) {
        Uint64 blockCount_4x512_4_unroll = 16 * 4;

        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i  z0_512, z1_512, z2_512;
            __m512i  z0_512_t, z1_512_t, z2_512_t;
            int      n            = 12;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }

    } else if (do_2_unroll) {
        Uint64 blockCount_4x512_2_unroll = 16 * 2;

        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {

            __m512i z0_512, z1_512, z2_512;
            __m512i z0_512_t, z1_512_t, z2_512_t;

            int      n            = 4; // numParallel_512blks * k;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

            // first iteration gmul
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128, const_factor_256);
        }
    }

    __m512i* pHsubkey_512 = Hsubkey_512;
    Hsubkey_512_0         = _mm512_loadu_si512(pHsubkey_512);

    // if (do_one_parallel) {
    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

        Hsubkey_512_1 = Hsubkey_512[1];
        Hsubkey_512_2 = Hsubkey_512[2];
        Hsubkey_512_3 = Hsubkey_512[3];

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              pgHash_128,
              const_factor_256);

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

        (*fAesEncryptNoLoad_4x512)(b1, b2, b3, b4, keys);

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }
    //}

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        c2 = alcp_add_epi32(c1, one_x);
        // printf("\n blockCount_2x512");
        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);
        gMulR(
            Hsubkey_512_0, a2, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        (*fAesEncryptNoLoad_2x512)(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);
        // printf("\n blockCount_1x512");
        gMulR(
            Hsubkey_512_0, a1, reverse_mask_512, pgHash_128, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        (*fAesEncryptNoLoad_1x512)(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only
    // lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);
    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }
    }

    // clear all keys stored in registers.
    alcp_clear_keys_zmm(keys, nRounds);
    return blocks;
}

} // namespace alcp::cipher::vaes512
