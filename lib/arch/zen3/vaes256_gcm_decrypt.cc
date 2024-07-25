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
#include "avx256.hh"
#include "avx256_gmul.hh"

#include "vaes.hh"
#include "vaes256_gcm.hh"

#include "vaes_avx256_core.hh"

#include "alcp/types.hh"

namespace alcp::cipher::vaes {

template<void AesEncNoLoad_4x256(
             __m256i& a, __m256i& b, __m256i& c, __m256i& d, const sKeys& keys),
         void AesEncNoLoad_2x256(__m256i& a, __m256i& b, const sKeys& keys),
         void AesEncNoLoad_1x256(__m256i& a, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
Uint64 inline gcmBlk_256_dec(const __m256i* p_in_x,
                             __m256i*       p_out_x,
                             Uint64         blocks,
                             bool           isFirstUpdate,
                             const __m128i* pkey128,
                             int            nRounds,
                             // gcm specific params
                             alc_gcm_local_data_t* gcmLocalData,
                             int                   remBytes,
                             Uint64*               pGcmCtxHashSubkeyTable)
{
    __m256i c1;

    /* gcm init + Hash subkey init */
    // Initalize GCM constants
    const __m256i one_x  = alcp_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);
    const __m256i two_x  = alcp_set_epi32(4, 0, 0, 0, 4, 0, 0, 0);
    const __m256i four_x = alcp_set_epi32(8, 0, 0, 0, 8, 0, 0, 0);

    // clang-format off
    const __m256i swap_ctr = _mm256_setr_epi8(  0,  1,  2,  3,  4,  5,  6,  7,
                                                8,  9, 10, 11, 15, 14, 13, 12, /* switching last 4 bytes */
                                                16, 17, 18, 19, 20, 21, 22, 23,
                                                24, 25, 26, 27, 31, 30, 29, 28); /* switching last 4 bytes */
    // clang-format on
    // nonce counter

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    amd_mm256_broadcast_i64x2(&gcmLocalData->m_counter_128, &c1);

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T0);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys);

    {
        // Increment each counter to create proper parrallel counter
        __m256i onehi = _mm256_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1);
        c1            = alcp_add_epi32(c1, onehi);
    }

    // clang-format off
    __m256i reverse_mask_256 =
            _mm256_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int             num_256_blks    = 0;
    constexpr Uint8 numBlksIn256bit = 2;

    num_256_blks = dynamicUnroll(blocks);

    __m256i* Hsubkey_256_precomputed = (__m256i*)pGcmCtxHashSubkeyTable;
    __m256i  hashSubkeyTableStack[MAX_NUM_256_BLKS] = {};
    __m256i* Hsubkey_256                            = hashSubkeyTableStack;

    if (num_256_blks) {
        getPrecomputedTable(isFirstUpdate,
                            Hsubkey_256_precomputed,
                            Hsubkey_256,
                            num_256_blks,
                            gcmLocalData,
                            const_factor_128);
    }

    Uint64  blockCount_1x256 = numBlksIn256bit;
    __m256i a1, b1;

    Uint64 blockCount_4x256 = 4 * numBlksIn256bit;

    __m256i a2, a3, a4;
    __m256i b2, b3, b4;
    __m256i c2, c3, c4;

    c2 = alcp_add_epi32(c1, one_x);
    c3 = alcp_add_epi32(c1, two_x);
    c4 = alcp_add_epi32(c2, two_x);

    __m256i Hsubkey_256_0, Hsubkey_256_1, Hsubkey_256_2, Hsubkey_256_3;
    __m256i gHash_256 = _mm256_zextsi128_si256(gcmLocalData->m_gHash_128);

    if (num_256_blks >= 8) {
        constexpr Uint64 blks_in_256bit = 2;

        constexpr Uint64 blockCount_4x256_2_unroll =
            NUM_PARALLEL_YMMS * blks_in_256bit * 2;

        // (8x256)=32 blks aesenc, 32 blks gmul and 1 reduction
        UNROLL_8
        for (; blocks >= blockCount_4x256_2_unroll;
             blocks -= blockCount_4x256_2_unroll) {

            __m256i z0_256, z1_256, z2_256;

            __m256i* pHsubkey_256 = Hsubkey_256 + 4;
            _mm_prefetch(cast_to(pHsubkey_256), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_loadu_4values(pHsubkey_256,
                               Hsubkey_256_0,
                               Hsubkey_256_1,
                               Hsubkey_256_2,
                               Hsubkey_256_3);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x256(b1, b2, b3, b4, keys);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += NUM_PARALLEL_YMMS;
            p_out_x += NUM_PARALLEL_YMMS;

            // 2nd
            pHsubkey_256 = Hsubkey_256;
            _mm_prefetch(cast_to(pHsubkey_256), _MM_HINT_T0);
            _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

            AesEncNoLoad_4x256(b1, b2, b3, b4, keys);

            /* first iteration gmul */
            get_aggregated_karatsuba_components_first(Hsubkey_256_0,
                                                      Hsubkey_256_1,
                                                      Hsubkey_256_2,
                                                      Hsubkey_256_3,
                                                      a1,
                                                      a2,
                                                      a3,
                                                      a4,
                                                      reverse_mask_256,
                                                      z0_256,
                                                      z1_256,
                                                      z2_256,
                                                      gHash_256);

            alcp_loadu_4values(pHsubkey_256,
                               Hsubkey_256_0,
                               Hsubkey_256_1,
                               Hsubkey_256_2,
                               Hsubkey_256_3);
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4);

            // increment counter
            c1 = alcp_add_epi32(c1, four_x);
            c2 = alcp_add_epi32(c2, four_x);
            c3 = alcp_add_epi32(c3, four_x);
            c4 = alcp_add_epi32(c4, four_x);

            get_aggregated_karatsuba_components_last(Hsubkey_256_0,
                                                     Hsubkey_256_1,
                                                     Hsubkey_256_2,
                                                     Hsubkey_256_3,
                                                     a1,
                                                     a2,
                                                     a3,
                                                     a4,
                                                     reverse_mask_256,
                                                     z0_256,
                                                     z1_256,
                                                     z2_256);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += NUM_PARALLEL_YMMS;
            p_out_x += NUM_PARALLEL_YMMS;

            // compute Ghash
            getGhash(z0_256, z1_256, z2_256, gHash_256, const_factor_256);
        }
    }

    __m256i* pHsubkey_256 = Hsubkey_256;
    Hsubkey_256_0         = _mm256_loadu_si256(pHsubkey_256);

    // (4x256) 16 blks aesenc, 16 blks gmul and 4 reductions
    for (; blocks >= blockCount_4x256; blocks -= blockCount_4x256) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
        p_in_x += 4;

        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
        AesEncNoLoad_4x256(b1, b2, b3, b4, keys);

        gMulR(Hsubkey_256_0, a1, reverse_mask_256, gHash_256, const_factor_256);
        gMulR(Hsubkey_256_0, a2, reverse_mask_256, gHash_256, const_factor_256);
        gMulR(Hsubkey_256_0, a3, reverse_mask_256, gHash_256, const_factor_256);
        gMulR(Hsubkey_256_0, a4, reverse_mask_256, gHash_256, const_factor_256);

        alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
        c1 = alcp_add_epi32(c1, four_x);
        c2 = alcp_add_epi32(c2, four_x);
        c3 = alcp_add_epi32(c3, four_x);
        c4 = alcp_add_epi32(c4, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
        p_out_x += 4;
    }

    UNROLL_4
    for (; blocks >= blockCount_1x256; blocks -= blockCount_1x256) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);

        gMulR(Hsubkey_256_0, a1, reverse_mask_256, gHash_256, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncNoLoad_1x256(b1, keys);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    gcmLocalData->m_gHash_128 = _mm256_castsi256_si128(gHash_256);

    /* residual block=1 when numBlksIn256bit = 2, load and store only
     lower half. */
    __m128i c1_128     = _mm256_castsi256_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);

    for (; blocks != 0; blocks--) {
        __m128i a1;
        __m128i swap_ctr_128 = _mm256_castsi256_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        __m128i ra1 = _mm_shuffle_epi8(a1, gcmLocalData->m_reverse_mask_128);
        gcmLocalData->m_gHash_128 =
            _mm_xor_si128(ra1, gcmLocalData->m_gHash_128);
        aesni::gMul(gcmLocalData->m_gHash_128,
                    gcmLocalData->m_hash_subKey_128,
                    gcmLocalData->m_gHash_128,
                    const_factor_128);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);

        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m256i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m256i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm256_castsi256_si128(swap_ctr);
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

        __m128i ra1 = _mm_shuffle_epi8(a1, gcmLocalData->m_reverse_mask_128);
        gcmLocalData->m_gHash_128 =
            _mm_xor_si128(ra1, gcmLocalData->m_gHash_128);
        aesni::gMul(gcmLocalData->m_gHash_128,
                    gcmLocalData->m_hash_subKey_128,
                    gcmLocalData->m_gHash_128,
                    const_factor_128);

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }
    }

    // clear all keys in registers.
    alcp_clear_keys_zmm(keys);

    // Extract the first counter
    gcmLocalData->m_counter_128 = c1_128;

    return blocks;
}

alc_error_t
decryptGcm128(const Uint8*          pInputText,  // ptr to inputText
              Uint8*                pOutputText, // ptr to outputtext
              Uint64                len,         // message length in bytes
              bool                  isFirstUpdate,
              const Uint8*          pKey,    // ptr to Key
              const int             nRounds, // No. of rounds
              alc_gcm_local_data_t* gcmLocalData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_256  = reinterpret_cast<const __m256i*>(pInputText);
    auto p_out_256 = reinterpret_cast<__m256i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_256_dec<AesEncryptNoLoad_4x256Rounds10,
                   AesEncryptNoLoad_2x256Rounds10,
                   AesEncryptNoLoad_1x256Rounds10,
                   alcp_load_key_ymm_10rounds,
                   alcp_clear_keys_ymm_10rounds>(p_in_256,
                                                 p_out_256,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 remBytes,
                                                 pGcmCtxHashSubkeyTable);

    return err;
}

alc_error_t
decryptGcm192(const Uint8*          pInputText,  // ptr to inputText
              Uint8*                pOutputText, // ptr to outputtext
              Uint64                len,         // message length in bytes
              bool                  isFirstUpdate,
              const Uint8*          pKey,    // ptr to Key
              const int             nRounds, // No. of rounds
              alc_gcm_local_data_t* gcmLocalData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_256  = reinterpret_cast<const __m256i*>(pInputText);
    auto p_out_256 = reinterpret_cast<__m256i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_256_dec<AesEncryptNoLoad_4x256Rounds12,
                   AesEncryptNoLoad_2x256Rounds12,
                   AesEncryptNoLoad_1x256Rounds12,
                   alcp_load_key_ymm_12rounds,
                   alcp_clear_keys_ymm_12rounds>(p_in_256,
                                                 p_out_256,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 remBytes,
                                                 pGcmCtxHashSubkeyTable);

    return err;
}

alc_error_t
decryptGcm256(const Uint8*          pInputText,  // ptr to inputText
              Uint8*                pOutputText, // ptr to outputtext
              Uint64                len,         // message length in bytes
              bool                  isFirstUpdate,
              const Uint8*          pKey,    // ptr to Key
              const int             nRounds, // No. of rounds
              alc_gcm_local_data_t* gcmLocalData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_256  = reinterpret_cast<const __m256i*>(pInputText);
    auto p_out_256 = reinterpret_cast<__m256i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_256_dec<AesEncryptNoLoad_4x256Rounds14,
                   AesEncryptNoLoad_2x256Rounds14,
                   AesEncryptNoLoad_1x256Rounds14,
                   alcp_load_key_ymm_14rounds,
                   alcp_clear_keys_ymm_14rounds>(p_in_256,
                                                 p_out_256,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 remBytes,
                                                 pGcmCtxHashSubkeyTable);

    return err;
}

} // namespace alcp::cipher::vaes
