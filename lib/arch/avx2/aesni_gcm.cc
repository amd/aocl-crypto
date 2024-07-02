/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/cipher/gmul.hh"

#include <immintrin.h>

namespace alcp::cipher::aesni {

alc_error_t
InitGcm(const Uint8* pKey,
        int          nRounds,
        const Uint8* pIv,
        Uint64       ivBytes,
        __m128i&     HsubKey_128,
        __m128i&     tag_128,
        __m128i&     iv_128,
        __m128i      reverse_mask_128)
{
    alc_error_t err     = ALC_ERROR_NONE;
    auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);
    auto        pIv128  = reinterpret_cast<const __m128i*>(pIv);

    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    __m128i swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    // Tag computation
    if ((ivBytes) == 12) {
        // iv
        utils::CopyBytes((Uint8*)&iv_128, pIv, 12);
        // T= 96 bit iv : 32bit counter
        tag_128 = _mm_insert_epi32(iv_128, 0x1000000, 3);
        AesEncrypt(tag_128, HsubKey_128, pkey128, nRounds);

        // Hash sub key reversed for gf multiplication.
        HsubKey_128 = _mm_shuffle_epi8(HsubKey_128, reverse_mask_128);

        // H<<1 mod p
        HashSubKeyLeftByOne(HsubKey_128);

        // printText((Uint32*)&iv_128, 4, "iv_128-1      ");

        // nonce counter
        iv_128 = _mm_insert_epi32(iv_128, 0x2000000, 3);
        iv_128 = _mm_shuffle_epi8(iv_128, swap_ctr);

        // printText((Uint32*)&iv_128, 4, "iv_128-3    ");
    } else {

        // pHsubKey_128 is already set to zero
        // Hash subkey generation.
        aesni::AesEncrypt(HsubKey_128, pkey128, nRounds);
        // Hash sub key reversed for gf multiplication.
        HsubKey_128 = _mm_shuffle_epi8(HsubKey_128, reverse_mask_128);

        // H<<1 mod p
        HashSubKeyLeftByOne(HsubKey_128);

        // gmul uses aesni method with hkey<<1 mod poly. to be verified
        int     ivBlocks = ivBytes / Rijndael::cBlockSize;
        int     remBytes = ivBytes - (ivBlocks * Rijndael::cBlockSize);
        __m128i a128;
        __m128i one_128 = _mm_set_epi32(1, 0, 0, 0);

        tag_128 = _mm_setzero_si128();
        for (; ivBlocks >= 1; ivBlocks--) {
            a128 = _mm_loadu_si128(pIv128);
            gMulR(
                a128, HsubKey_128, reverse_mask_128, tag_128, const_factor_128);
            pIv128++;
        }
        if (remBytes) {
            a128               = _mm_setzero_si128();
            const Uint8* p_in  = reinterpret_cast<const Uint8*>(pIv128);
            Uint8*       p_out = reinterpret_cast<Uint8*>(&a128);
            for (int i = 0; i < remBytes; i++) {
                p_out[i] = p_in[i];
            }
            gMulR(
                a128, HsubKey_128, reverse_mask_128, tag_128, const_factor_128);
        }

        a128 = _mm_setzero_si128();
        a128 = _mm_insert_epi64(a128, (ivBytes << 3), 0);
        a128 = _mm_insert_epi64(a128, 0, 1);

        tag_128 = _mm_xor_si128(a128, tag_128);
        gMul(tag_128, HsubKey_128, tag_128, const_factor_128);

        tag_128 = _mm_shuffle_epi8(tag_128, reverse_mask_128);
        iv_128  = tag_128;

        iv_128 = _mm_shuffle_epi8(iv_128, swap_ctr);
        iv_128 = _mm_add_epi32(iv_128, one_128);

        AesEncrypt(tag_128, pkey128, nRounds);
    }

    return err;
}

static Uint64
gcmBlk(const __m128i*        p_in_x,
       __m128i*              p_out_x,
       Uint64                blocks,
       const __m128i*        pkey128,
       int                   nRounds,
       alc_gcm_local_data_t* gcmLocalData,
       bool                  isEncrypt,
       int                   remBytes)
{
    __m128i a1{}, a2{}, a3{}, a4{}; // Block Registers
    __m128i b1{}, b2{}, b3{}, b4{}; // Scratch Registers
    __m128i c1{}, c2{}, c3{}, c4{}; // Counter Registers
    __m128i m_hash_subKey_128_2{}, m_hash_subKey_128_3{},
        m_hash_subKey_128_4{}; // Key Registers

    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    /* Initialization */

    // Static Constants, persistant over function calls
    static const __m128i
        swap_ctr =
            _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12),
        one_x = alcp_set_epi32(1, 0, 0, 0), two_x = alcp_set_epi32(2, 0, 0, 0),
        three_x = alcp_set_epi32(3, 0, 0, 0),
        four_x  = alcp_set_epi32(4, 0, 0, 0);

    c1 = gcmLocalData->m_counter_128;

    // Propagate Key properly for parrallel gmulr
    if (blocks >= 4) {
        gMul(gcmLocalData->m_hash_subKey_128,
             gcmLocalData->m_hash_subKey_128,
             m_hash_subKey_128_2,
             const_factor_128);
        gMul(m_hash_subKey_128_2,
             gcmLocalData->m_hash_subKey_128,
             m_hash_subKey_128_3,
             const_factor_128);
        gMul(m_hash_subKey_128_3,
             gcmLocalData->m_hash_subKey_128,
             m_hash_subKey_128_4,
             const_factor_128);
    }

    constexpr Uint64 blockCount4 = 4;
    constexpr Uint64 blockCount2 = 2;
    constexpr Uint64 blockCount1 = 1;

    for (; blocks >= blockCount4; blocks -= blockCount4) {

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        if (isEncrypt == false) {
            gMulR(gcmLocalData->m_hash_subKey_128,
                  m_hash_subKey_128_2,
                  m_hash_subKey_128_3,
                  m_hash_subKey_128_4,
                  a4,
                  a3,
                  a2,
                  a1,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        if (isEncrypt == true) {
            gMulR(gcmLocalData->m_hash_subKey_128,
                  m_hash_subKey_128_2,
                  m_hash_subKey_128_3,
                  m_hash_subKey_128_4,
                  a4,
                  a3,
                  a2,
                  a1,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount2; blocks -= blockCount2) {
        // T ra1, ra2;
        c2 = alcp_add_epi32(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        if (isEncrypt == false) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
            gMulR(a2,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        AesEncrypt(&b1, &b2, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        if (isEncrypt == true) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
            gMulR(a2,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount1; blocks -= blockCount1) {
        a1 = alcp_loadu(p_in_x);

        if (isEncrypt == false) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncrypt(&b1, pkey128, nRounds);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        if (isEncrypt == true) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    for (; blocks != 0; blocks--) {
        a1 = alcp_loadu_128(p_in_x);

        if (isEncrypt == false) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncrypt(&b1, pkey128, nRounds);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        if (isEncrypt == true) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        alcp_storeu_128(p_out_x, a1);
        p_in_x  = (__m128i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m128i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        if (isEncrypt == false) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }

        a1 = alcp_xor(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }

        if (isEncrypt == true) {
            gMulR(a1,
                  gcmLocalData->m_hash_subKey_128,
                  gcmLocalData->m_reverse_mask_128,
                  gcmLocalData->m_gHash_128,
                  const_factor_128);
        }
    }
    gcmLocalData->m_counter_128 = c1;
    return blocks;
}

alc_error_t
CryptGcm(const Uint8*          pInputText,  // ptr to inputText
         Uint8*                pOutputText, // ptr to outputtext
         Uint64                len,         // message length in bytes
         const Uint8*          pKey,        // ptr to Key
         int                   nRounds,     // No. of rounds
         alc_gcm_local_data_t* gcmLocalData,
         bool                  isEncrypt,
         Uint64*               pGcmCtxHashSubkeyTable)
{
    alc_error_t err      = ALC_ERROR_NONE;
    Uint64      blocks   = len / Rijndael::cBlockSize;
    int         remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk(p_in_128,
           p_out_128,
           blocks,
           pkey128,
           nRounds,
           // gcm specific params
           gcmLocalData,
           isEncrypt,
           remBytes);

    return err;
}

alc_error_t
processAdditionalDataGcm(const Uint8* pAdditionalData,
                         Uint64       additionalDataLen,
                         __m128i&     gHash_128,
                         __m128i      hash_subKey_128,
                         __m128i      reverse_mask_128)
{
    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    alc_error_t err = ALC_ERROR_NONE;
    if (additionalDataLen == 0) {
        return ALC_ERROR_NONE;
    }
    auto pAd128 = reinterpret_cast<const __m128i*>(pAdditionalData);

    // additional data hash.
    __m128i ad1;
    Uint64  adBlocks = additionalDataLen / Rijndael::cBlockSize;

    int ad_remBytes = additionalDataLen - (adBlocks * Rijndael::cBlockSize);
    for (; adBlocks >= 1; adBlocks--) {
        ad1 = _mm_loadu_si128(pAd128);
        gMulR(ad1,
              hash_subKey_128,
              reverse_mask_128,
              gHash_128,
              const_factor_128);
        pAd128++;
    }

    if (ad_remBytes) {
        const Uint8* p_in  = reinterpret_cast<const Uint8*>(pAd128);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&ad1);
        int          i     = 0;

        for (; i < ad_remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }
        gMulR(ad1,
              hash_subKey_128,
              reverse_mask_128,
              gHash_128,
              const_factor_128);
    }

    return err;
}

alc_error_t
GetTagGcm(Uint64   tagLen,
          Uint64   plaintextLen,
          Uint64   adLength,
          __m128i& gHash_128,
          __m128i& tag128,
          __m128i  Hsubkey_128,
          __m128i  reverse_mask_128,
          Uint8*   tag)
{
    alc_error_t   err              = ALC_ERROR_NONE;
    auto          p_tag_128        = reinterpret_cast<__m128i*>(tag);
    __m128i       a1               = _mm_set_epi32(0, 0, 0, 0);
    const __m128i const_factor_128 = _mm_set_epi64x(0xC200000000000000, 0x1);

    a1 = _mm_insert_epi64(a1, (plaintextLen << 3), 0);
    a1 = _mm_insert_epi64(a1, (adLength << 3), 1);

    gHash_128 = _mm_xor_si128(a1, gHash_128);
    gMul(gHash_128, Hsubkey_128, gHash_128, const_factor_128);

    gHash_128 = _mm_shuffle_epi8(gHash_128, reverse_mask_128);
    tag128    = _mm_xor_si128(gHash_128, tag128);

    if (tagLen == 16) {
        _mm_storeu_si128(p_tag_128, tag128);
    } else {
        Uint64       i     = 0;
        const Uint8* p_in  = reinterpret_cast<const Uint8*>(&tag128);
        Uint8*       p_out = reinterpret_cast<Uint8*>(tag);
        for (; i < tagLen; i++) {
            p_out[i] = p_in[i];
        }
    }
    return err;
}

} // namespace alcp::cipher::aesni
