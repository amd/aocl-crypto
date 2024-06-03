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

/*
 *
 * Galois Multiplication we use below algorithms from "Intel carry-less
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

#include "../avx512.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/cipher/gmul.hh"
#include "avx512_gmul.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"
#include "vaes_gcm.hh"

#include "alcp/types.hh"

namespace alcp::cipher::vaes512 {

template<void AesEncNoLoad_4x512(
             __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
         void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
         void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
Uint64 inline gcmBlk_512_dec(const __m512i* p_in_x,
                             __m512i*       p_out_x,
                             Uint64         blocks,
                             bool           isFirstUpdate,
                             const __m128i* pkey128,
                             int            nRounds,
                             // gcm specific params
                             alc_gcm_local_data_t* gcmLocalData,
                             alc_cipher_data_t*    cipherData,
                             int                   remBytes,
                             Uint64*               pGcmCtxHashSubkeyTable)
{
    __m512i c1{};

#if 0
    printf(" blocks %ld remBytes %d totalBytes %ld",
           blocks,
           remBytes,
           (blocks * 16) + remBytes);
#endif

    /* gcm init + Hash subkey init */
    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

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

    c1 = _mm512_broadcast_i64x2(gcmLocalData->m_counter_128);

    {
        // Increment each counter to create proper parallel counter
        __m512i onehi =
            _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3);
        c1 = alcp_add_epi32(c1, onehi);
    }

    _mm_prefetch(cast_to(pkey128), _MM_HINT_T0);

    sKeys keys{};
    alcp_load_key_zmm(pkey128, keys);

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int num_512_blks = dynamicUnroll(blocks);

    // Get Hash sub key table for GMUL
    __m512i* p512GcmCtxHashSubkeyTable = (__m512i*)pGcmCtxHashSubkeyTable;
    __m512i  hashSubkeyTableStack[MAX_NUM_512_BLKS];
    __m512i* pHashSubkeyTableLocal = hashSubkeyTableStack;
    if (num_512_blks) {
        getPrecomputedTable(isFirstUpdate,
                            p512GcmCtxHashSubkeyTable,
                            pHashSubkeyTableLocal,
                            num_512_blks,
                            gcmLocalData,
                            const_factor_128);
    }

    __m512i a1{}, b1{};

    constexpr Uint8  numBlksIn512bit  = 4;
    constexpr Uint64 blockCount_1x512 = numBlksIn512bit;
    constexpr Uint64 blockCount_2x512 = 2 * numBlksIn512bit;
    constexpr Uint64 blockCount_4x512 = 4 * numBlksIn512bit;
    constexpr Uint64 blockCount_8x512 = 8 * numBlksIn512bit;

    __m512i a2{}, a3{}, a4{};
    __m512i b2{}, b3{}, b4{};
    __m512i c2{}, c3{}, c4{};

    c2 = alcp_add_epi32(c1, one_x);
    c3 = alcp_add_epi32(c1, two_x);
    c4 = alcp_add_epi32(c2, two_x);

    __m512i Hsubkey_512_0{}, Hsubkey_512_1{}, Hsubkey_512_2{}, Hsubkey_512_3{};
    __m512i gHash_512 = _mm512_zextsi128_si512(gcmLocalData->m_gHash_128);

    // (8x512)=32 blks aesenc, 32 blks gmul and 1 reduction
    UNROLL_8
    for (; blocks >= blockCount_8x512; blocks -= blockCount_8x512) {

        __m512i z0_512, z1_512, z2_512;

        // 1st 4x512
        __m512i* pHsubkey_512 = pHashSubkeyTableLocal + 4;
        _mm_prefetch(cast_to(pHsubkey_512), _MM_HINT_T0);
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);

        alcp_loadu_4values(pHsubkey_512,
                           Hsubkey_512_0,
                           Hsubkey_512_1,
                           Hsubkey_512_2,
                           Hsubkey_512_3);

        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

        AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4);
        // increment counter
        c1 = alcp_add_epi32(c1, four_x);
        c2 = alcp_add_epi32(c2, four_x);
        c3 = alcp_add_epi32(c3, four_x);
        c4 = alcp_add_epi32(c4, four_x);

        alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

        p_in_x += NUM_PARALLEL_ZMMS;
        p_out_x += NUM_PARALLEL_ZMMS;

        // 2nd 4x512
        pHsubkey_512 = pHashSubkeyTableLocal;
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

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);
        c2 = alcp_add_epi32(c2, four_x);
        c3 = alcp_add_epi32(c3, four_x);
        c4 = alcp_add_epi32(c4, four_x);

        get_aggregated_karatsuba_components_last(Hsubkey_512_0,
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

        alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
        p_in_x += NUM_PARALLEL_ZMMS;
        p_out_x += NUM_PARALLEL_ZMMS;

        // compute Ghash
        getGhash(z0_512, z1_512, z2_512, gHash_512, const_factor_256);
    }

    Hsubkey_512_0 = _mm512_loadu_si512(p512GcmCtxHashSubkeyTable);

    // (4x512) 16 blks aesenc, 16 blks gmul and 1 reductions
    if (blocks >= blockCount_4x512) {

        Hsubkey_512_1 = _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 1);
        Hsubkey_512_2 = _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 2);
        Hsubkey_512_3 = _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 3);
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
        p_in_x += 4;

        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
        AesEncNoLoad_4x512(b1, b2, b3, b4, keys);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              gHash_512,
              const_factor_256);

        alcp_xor_4values(b1, b2, b3, b4, a1, a2, a3, a4);
        c1 = alcp_add_epi32(c1, four_x);
        c2 = alcp_add_epi32(c2, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
        p_out_x += 4;
        blocks -= blockCount_4x512;
    }

    // (2x512)=8 blks aesenc, 8 blks gmul and 1 reductions
    if (blocks >= blockCount_2x512) {
        Hsubkey_512_1 = _mm512_loadu_si512(p512GcmCtxHashSubkeyTable + 1);
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        alcp_loadu_2values(p_in_x, a1, a2);
        p_in_x += 2;

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, swap_ctr, b1, b2);
        AesEncNoLoad_2x512(b1, b2, keys);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              a1,
              a2,
              reverse_mask_512,
              gHash_512,
              const_factor_256);

        alcp_xor_2values(b1, b2, a1, a2);
        c1 = alcp_add_epi32(c1, two_x);

        alcp_storeu_2values(p_out_x, a1, a2);
        p_out_x += 2;
        blocks -= blockCount_2x512;
    }

    if (blocks >= blockCount_1x512) {
        _mm_prefetch(cast_to(p_in_x), _MM_HINT_T0);
        a1 = alcp_loadu(p_in_x);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, gHash_512, const_factor_256);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncNoLoad_1x512(b1, keys);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
        blocks -= blockCount_1x512;
    }

    gcmLocalData->m_gHash_128 = _mm512_castsi512_si128(gHash_512);
    __m128i c1_128            = _mm512_castsi512_si128(c1);

    /* residual block=1 when factor = 2, load and store only
     lower half. */
    //__m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);

    for (; blocks != 0; blocks--) {
        __m128i a1;
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

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
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1{}; // remaining bytes handled with 128bit
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
              alc_cipher_data_t*    cipherData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_dec<AesEncryptNoLoad_4x512Rounds10,
                   AesEncryptNoLoad_2x512Rounds10,
                   AesEncryptNoLoad_1x512Rounds10,
                   alcp_load_key_zmm_10rounds,
                   alcp_clear_keys_zmm_10rounds>(p_in_512,
                                                 p_out_512,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 cipherData,
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
              alc_cipher_data_t*    cipherData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_dec<AesEncryptNoLoad_4x512Rounds12,
                   AesEncryptNoLoad_2x512Rounds12,
                   AesEncryptNoLoad_1x512Rounds12,
                   alcp_load_key_zmm_12rounds,
                   alcp_clear_keys_zmm_12rounds>(p_in_512,
                                                 p_out_512,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 cipherData,
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
              alc_cipher_data_t*    cipherData,
              Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512_dec<AesEncryptNoLoad_4x512Rounds14,
                   AesEncryptNoLoad_2x512Rounds14,
                   AesEncryptNoLoad_1x512Rounds14,
                   alcp_load_key_zmm_14rounds,
                   alcp_clear_keys_zmm_14rounds>(p_in_512,
                                                 p_out_512,
                                                 blocks,
                                                 isFirstUpdate,
                                                 pkey128,
                                                 nRounds,
                                                 // gcm specific params
                                                 gcmLocalData,
                                                 cipherData,
                                                 remBytes,
                                                 pGcmCtxHashSubkeyTable);

    return err;
}

} // namespace alcp::cipher::vaes512
