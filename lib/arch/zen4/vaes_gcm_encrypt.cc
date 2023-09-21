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
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/cipher/gmul.hh"
#include "avx512.hh"
#include "avx512_gmul.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"
#include "vaes_gcm.hh"

#include "alcp/types.hh"

//#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_8 _Pragma("GCC unroll 8")
#define UNROLL_4 _Pragma("GCC unroll 4")
#define UNROLL_2 _Pragma("GCC unroll 2")

namespace alcp::cipher::vaes512 {

// FIXME: Encrypt and Decrypt can be fused with a constexpr template argument
template<void AesEncNoLoad_4x512(
             __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
         void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
         void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
Uint64 inline gcmBlk_512_enc(const __m512i* p_in_x,
                             __m512i*       p_out_x,
                             Uint64         blocks,
                             const __m128i* pkey128,
                             const Uint8*   pIv,
                             int            nRounds,
                             Uint8          factor,
                             // gcm specific params
                             alcp::cipher::GcmAuthData* gcm,
                             __m128i                    reverse_mask_128,
                             int                        remBytes,
                             Uint64*                    pHashSubkeyTable)
{
    __m512i c1;

    /* gcm init + Hash subkey init */
    // Initalize GCM constants
    // Too big of memory to be put into static
    const __m512i one_x = alcp_set_epi32(
                      4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0),
                  two_x = alcp_set_epi32(
                      8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0),
                  four_x = alcp_set_epi32(
                      16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0),
                  swap_ctr = _mm512_set_epi32(0x0c0d0e0f,
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

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    c1 = _mm512_broadcast_i64x2(gcm->m_iv_128);

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T0);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys);

    {
        // Increment each counter to create proper parrallel counter
        __m512i onehi =
            _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3);
        c1 = alcp_add_epi32(c1, onehi);
    }

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int num_512_blks = 0;

    num_512_blks = dynamicUnroll(blocks);

#if LOCAL_TABLE // local table improves performance of large block size (>8192
                // bytes)
    //__attribute__((aligned(64))) Uint64 hashSubkeyTable[MAX_NUM_512_BLKS * 8];
    //__m512i* Hsubkey_512 = (__m512i*)&hashSubkeyTable;
    __m512i  hashSubkeyTable[MAX_NUM_512_BLKS];
    __m512i* Hsubkey_512 = hashSubkeyTable;

#else
    __m512i* Hsubkey_512 = (__m512i*)pHashSubkeyTable;
#endif

    // if (num_512_blks)
    {
        computeHashSubKeys(num_512_blks,
                           gcm->m_hash_subKey_128,
                           Hsubkey_512,
                           const_factor_128);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    c2 = alcp_add_epi32(c1, one_x);
    c3 = alcp_add_epi32(c1, two_x);
    c4 = alcp_add_epi32(c2, two_x);

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    __m512i gHash_512 = _mm512_zextsi128_si512(gcm->m_gHash_128);

#if 0
    // (16x512) 64 blks aesenc 64 blks gmul and 1 reduction
    if (num_512_blks == 16) {
        constexpr Uint64 blockCount_4x512_4_unroll = 16 * 4;

        UNROLL_8
        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {
            __m512i z0_512, z1_512, z2_512;

            int n = 12;

            __m512i* pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, // inputs B
                             b2,
                             b3,
                             b4,
                             a1, // outputs A = A xor B
                             a2,
                             a3,
                             a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_first(Hsubkey_512_0,
                                                      Hsubkey_512_1,
                                                      Hsubkey_512_2,
                                                      Hsubkey_512_3,
                                                      a1,
                                                      a2,
                                                      a3,
                                                      a4,
                                                      reverse_mask_512,
                                                      z0_512,
                                                      z1_512,
                                                      z2_512,
                                                      gHash_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);

            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // do reduction once
            getGhash(z0_512, z1_512, z2_512, gHash_512, const_factor_256);
        }
    } else
#endif

    if (num_512_blks >= 8) {
        constexpr Uint64 blockCount_4x512_2_unroll = 16 * 2;
        constexpr Uint64 blockCount_4x512_4_unroll = 16 * 4;

        /* (16x512)=64 blks aesenc, 64 blks gmul and 2 reduction
         * GcmEncrypt performs better, when 4 unroll and 2 reductions are done
         * for certain input blocksize range, which is choosen in dynamicUnroll
         * module.
         *
         * Similar unrolling in GcmDecrypt doesnt offer performance difference.
         * In GcmDecrypt only 32 blks dec, 32 blks gmul and 1 reduction is done.
         */
        UNROLL_2
        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i z0_512, z1_512, z2_512;

            __m512i* pHsubkey_512 = Hsubkey_512 + 4;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, // inputs B
                             b2,
                             b3,
                             b4,
                             a1, // outputs A = A xor B
                             a2,
                             a3,
                             a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            pHsubkey_512 = Hsubkey_512;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_first(Hsubkey_512_0,
                                                      Hsubkey_512_1,
                                                      Hsubkey_512_2,
                                                      Hsubkey_512_3,
                                                      a1,
                                                      a2,
                                                      a3,
                                                      a4,
                                                      reverse_mask_512,
                                                      z0_512,
                                                      z1_512,
                                                      z2_512,
                                                      gHash_512);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);

            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            pHsubkey_512 = Hsubkey_512 + 4;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            // first reduction
            getGhash(z0_512, z1_512, z2_512, gHash_512, const_factor_256);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            pHsubkey_512 = Hsubkey_512;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            get_aggregated_karatsuba_components_first(Hsubkey_512_0,
                                                      Hsubkey_512_1,
                                                      Hsubkey_512_2,
                                                      Hsubkey_512_3,
                                                      a1,
                                                      a2,
                                                      a3,
                                                      a4,
                                                      reverse_mask_512,
                                                      z0_512,
                                                      z1_512,
                                                      z2_512,
                                                      gHash_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // second reduction
            getGhash(z0_512, z1_512, z2_512, gHash_512, const_factor_256);
        }

        // UNROLL_8
        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {

            __m512i z0_512, z1_512, z2_512;

            __m512i* pHsubkey_512 = Hsubkey_512 + 4;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            pHsubkey_512 = Hsubkey_512;
            _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

            /* first iteration gmul */
            get_aggregated_karatsuba_components_first(Hsubkey_512_0,
                                                      Hsubkey_512_1,
                                                      Hsubkey_512_2,
                                                      Hsubkey_512_3,
                                                      a1,
                                                      a2,
                                                      a3,
                                                      a4,
                                                      reverse_mask_512,
                                                      z0_512,
                                                      z1_512,
                                                      z2_512,
                                                      gHash_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;

            alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);

            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            get_aggregated_karatsuba_components_not_first(Hsubkey_512_0,
                                                          Hsubkey_512_1,
                                                          Hsubkey_512_2,
                                                          Hsubkey_512_3,
                                                          a1,
                                                          a2,
                                                          a3,
                                                          a4,
                                                          reverse_mask_512,
                                                          z0_512,
                                                          z1_512,
                                                          z2_512);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            /* Performance variations observed while using const_factor_128 and
             * const_factor_256, this sections needs to be investigated
             * further. */
            // getGhash(z0_512, z1_512, z2_512, gcm->m_gHash_128,
            // const_factor_128);
            getGhash(z0_512, z1_512, z2_512, gHash_512, const_factor_256);
        }
    }

    //    gcm->m_gHash_128 = _mm512_castsi512_si128(gHash_512);

    /* Maintaining ghash in zmm didnt result in performance improvement.
     * This needs to be revisited again
     * gcm->m_gHash_128 = _mm512_castsi512_si128(gHash_512);
     */
    __m512i* pHsubkey_512 = Hsubkey_512;
    Hsubkey_512_0         = _mm512_loadu_si512(pHsubkey_512);

    // (4x512)=16 blks aesenc, 16 blks gmul and 4 reductions
    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
        p_in_x += 4;

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
        AesEncNoLoad_4x512(b1, b2, b3, b4, keys);
        alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, gHash_512, const_factor_256);
        gMulR(Hsubkey_512_0, a2, reverse_mask_512, gHash_512, const_factor_256);
        gMulR(Hsubkey_512_0, a3, reverse_mask_512, gHash_512, const_factor_256);
        gMulR(Hsubkey_512_0, a4, reverse_mask_512, gHash_512, const_factor_256);

        c1 = alcp_add_epi32(c1, four_x);
        c2 = alcp_add_epi32(c2, four_x);
        c3 = alcp_add_epi32(c3, four_x);
        c4 = alcp_add_epi32(c4, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
        p_out_x += 4;
    }

    UNROLL_4
    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {

        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);
        p_in_x += 1;

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncNoLoad_1x512(b1, keys);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);
        gMulR(Hsubkey_512_0, a1, reverse_mask_512, gHash_512, const_factor_256);

        alcp_storeu(p_out_x, a1);

        p_out_x += 1;
    }

    gcm->m_gHash_128 = _mm512_castsi512_si128(gHash_512);

    // residual block=1 when factor = 2, load and store only lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);

    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit

        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);

        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        __m128i ra1      = _mm_shuffle_epi8(a1, reverse_mask_128);
        gcm->m_gHash_128 = _mm_xor_si128(ra1, gcm->m_gHash_128);
        gMul(gcm->m_gHash_128,
             gcm->m_hash_subKey_128,
             gcm->m_gHash_128,
             const_factor_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);
        __m128i b1           = _mm_shuffle_epi8(c1_128, swap_ctr_128);

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

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }

        __m128i ra1      = _mm_shuffle_epi8(a1, reverse_mask_128);
        gcm->m_gHash_128 = _mm_xor_si128(ra1, gcm->m_gHash_128);
        gMul(gcm->m_gHash_128,
             gcm->m_hash_subKey_128,
             gcm->m_gHash_128,
             const_factor_128);
    }

    // clear all keys in registers.
    alcp_clear_keys_zmm(keys);

    // Extract the first counter
    gcm->m_iv_128 = c1_128;

    return blocks;
}

alc_error_t
encryptGcm128(const Uint8*               pInputText,  // ptr to inputText
              Uint8*                     pOutputText, // ptr to outputtext
              Uint64                     len,         // message length in bytes
              const Uint8*               pKey,        // ptr to Key
              const int                  nRounds,     // No. of rounds
              const Uint8*               pIv, // ptr to Initialization Vector
              alcp::cipher::GcmAuthData* gcm,
              __m128i                    reverse_mask_128,
              Uint64*                    pHashSubkeyTable)
{
    alc_error_t     err             = ALC_ERROR_NONE;
    constexpr Uint8 numBlksIn512bit = 4;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_enc< // AesEncrypt_4x512Rounds10,
                    // AesEncrypt_2x512Rounds10,
        AesEncryptNoLoad_4x512Rounds10,
        AesEncryptNoLoad_2x512Rounds10,
        AesEncryptNoLoad_1x512Rounds10,
        alcp_load_key_zmm_10rounds,
        alcp_clear_keys_zmm_10rounds>(p_in_512,
                                      p_out_512,
                                      blocks,
                                      pkey128,
                                      pIv,
                                      nRounds,
                                      numBlksIn512bit,
                                      // gcm specific params
                                      gcm,
                                      reverse_mask_128,
                                      remBytes,
                                      pHashSubkeyTable);

    return err;
}

alc_error_t
encryptGcm192(const Uint8*               pInputText,  // ptr to inputText
              Uint8*                     pOutputText, // ptr to outputtext
              Uint64                     len,         // message length in bytes
              const Uint8*               pKey,        // ptr to Key
              const int                  nRounds,     // No. of rounds
              const Uint8*               pIv, // ptr to Initialization Vector
              alcp::cipher::GcmAuthData* gcm,
              __m128i                    reverse_mask_128,
              Uint64*                    pHashSubkeyTable)
{
    alc_error_t     err             = ALC_ERROR_NONE;
    constexpr Uint8 numBlksIn512bit = 4;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_enc<AesEncryptNoLoad_4x512Rounds12,
                   AesEncryptNoLoad_2x512Rounds12,
                   AesEncryptNoLoad_1x512Rounds12,
                   alcp_load_key_zmm_12rounds,
                   alcp_clear_keys_zmm_12rounds>(p_in_512,
                                                 p_out_512,
                                                 blocks,
                                                 pkey128,
                                                 pIv,
                                                 nRounds,
                                                 numBlksIn512bit,
                                                 // gcm specific params
                                                 gcm,
                                                 reverse_mask_128,
                                                 remBytes,
                                                 pHashSubkeyTable);

    return err;
}

alc_error_t
encryptGcm256(const Uint8*               pInputText,  // ptr to inputText
              Uint8*                     pOutputText, // ptr to outputtext
              Uint64                     len,         // message length in bytes
              const Uint8*               pKey,        // ptr to Key
              const int                  nRounds,     // No. of rounds
              const Uint8*               pIv, // ptr to Initialization Vector
              alcp::cipher::GcmAuthData* gcm,
              __m128i                    reverse_mask_128,
              Uint64*                    pHashSubkeyTable)
{
    alc_error_t     err             = ALC_ERROR_NONE;
    constexpr Uint8 numBlksIn512bit = 4;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_enc<AesEncryptNoLoad_4x512Rounds14,
                   AesEncryptNoLoad_2x512Rounds14,
                   AesEncryptNoLoad_1x512Rounds14,
                   alcp_load_key_zmm_14rounds,
                   alcp_clear_keys_zmm_14rounds>(p_in_512,
                                                 p_out_512,
                                                 blocks,
                                                 pkey128,
                                                 pIv,
                                                 nRounds,
                                                 numBlksIn512bit,
                                                 // gcm specific params
                                                 gcm,
                                                 reverse_mask_128,
                                                 remBytes,
                                                 pHashSubkeyTable);

    return err;
}

} // namespace alcp::cipher::vaes512
