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

#include "avx512.hh"
#include "avx512_gmul.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/cipher/gmul.hh"
#include "alcp/types.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"
#include "vaes_gcm.hh"

#include "alcp/types.hh"

namespace alcp::cipher::vaes512 {

/*
 * Bitreflection in galoisMultiplication is avoided by modifying the
 * hashKey to hashKey << 1 mod poly. Avoiding bitreflection on
 * galoisMultiplication improves performance of GHASH computation.
 *
 * Reference:
 * Vinodh Gopal et. al. Optimized Galois-Counter-Mode
 * Implementation on Intel® Architecture Processors. Intel White Paper, August
 * 2010.
 */

__m128i inline HashSubKeyLeftByOne(__m128i hashSubkey)
{
    __m128i res;
    /* Compute reflected hKey<<1 mod poly */
    __m128i a, b, c, d, cPoly;
    __m64   lo = _m_from_int64(0xC200000000000000);
    __m64   hi = _m_from_int64(0x1);
    b          = _mm_set_epi64(_m_from_int(0), _m_from_int(2));
    carrylessMul(hashSubkey, b, &c, &d); // hkey *2
    __m256i cd = _mm256_set_m128i(d, c);
    res        = _mm256_castsi256_si128(cd);

    a     = _mm_srai_epi32(hashSubkey, 31);
    a     = _mm_shuffle_epi32(a, _MM_PERM_DDDD);
    cPoly = _mm_set_epi64(lo, hi);
    a     = _mm_and_si128(a, cPoly);

    res = _mm_xor_epi64(res, a);

    return res;
}

alc_error_t
CryptGcm(const Uint8* pInputText,  // ptr to inputText
         Uint8*       pOutputText, // ptr to outputtext
         Uint64       len,         // message length in bytes
         const Uint8* pKey,        // ptr to Key
         const int    nRounds,     // No. of rounds
         const Uint8* pIv,         // ptr to Initialization Vector
         __m128i*     pgHash_128,
         __m128i      Hsubkey_128,
         __m128i      iv_128,
         __m128i      reverse_mask_128,
         bool         isEncrypt,
         Uint64*      pHashSubkeyTable)
{
    alc_error_t     err             = ALC_ERROR_NONE;
    constexpr Uint8 numBlksIn512bit = 4;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    if (isEncrypt) {
        if (nRounds == 10) {
            gcmBlk_512_encRounds10(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        } else if (nRounds == 12) {
            gcmBlk_512_encRounds12(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        } else if (nRounds == 14) {
            gcmBlk_512_encRounds14(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        }

    } else {
        if (nRounds == 10) {
            gcmBlk_512_decRounds10(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        } else if (nRounds == 12) {
            gcmBlk_512_decRounds12(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        } else if (nRounds == 14) {
            gcmBlk_512_decRounds14(p_in_512,
                                   p_out_512,
                                   blocks,
                                   pkey128,
                                   pIv,
                                   nRounds,
                                   numBlksIn512bit,
                                   // gcm specific params
                                   pgHash_128,
                                   Hsubkey_128,
                                   iv_128,
                                   reverse_mask_128,
                                   remBytes,
                                   pHashSubkeyTable);
        }
    }

    return err;
}

alc_error_t
processAdditionalDataGcm(const Uint8* pAdditionalData,
                         Uint64       additionalDataLen,
                         __m128i*     pgHash_128,
                         __m128i      hash_subKey_128,
                         __m128i      reverse_mask_128)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (additionalDataLen == 0) {
        return ALC_ERROR_NONE;
    }
    auto pAd128 = reinterpret_cast<const __m128i*>(pAdditionalData);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    // additional data hash.
    __m128i ad1;
    Uint64  adBlocks = additionalDataLen / Rijndael::cBlockSize;

    int ad_remBytes = additionalDataLen - (adBlocks * Rijndael::cBlockSize);

    for (; adBlocks >= 1; adBlocks--) {
        ad1 = _mm_loadu_si128(pAd128);
        gMulR(ad1,
              hash_subKey_128,
              reverse_mask_128,
              pgHash_128,
              const_factor_256);
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
              pgHash_128,
              const_factor_256);
    }

    return err;
}

alc_error_t
GetTagGcm(Uint64   tagLen,
          Uint64   plaintextLen,
          Uint64   adLength,
          __m128i* pgHash_128,
          __m128i* ptag128,
          __m128i  Hsubkey_128,
          __m128i  reverse_mask_128,
          Uint8*   tag)
{
    alc_error_t err       = ALC_ERROR_NONE;
    auto        p_tag_128 = reinterpret_cast<__m128i*>(tag);
    __m128i     a1        = _mm_set_epi32(0, 0, 0, 0);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    a1 = _mm_insert_epi64(a1, (plaintextLen << 3), 0);
    a1 = _mm_insert_epi64(a1, (adLength << 3), 1);

    *pgHash_128 = _mm_xor_si128(a1, *pgHash_128);
    gMul(*pgHash_128, Hsubkey_128, pgHash_128, const_factor_256);

    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
    *ptag128    = _mm_xor_si128(*pgHash_128, *ptag128);

    if (tagLen == 16) {
        _mm_storeu_si128(p_tag_128, *ptag128);
    } else {
        Uint64       i     = 0;
        const Uint8* p_in  = reinterpret_cast<const Uint8*>(ptag128);
        Uint8*       p_out = reinterpret_cast<Uint8*>(tag);
        for (; i < tagLen; i++) {
            p_out[i] = p_in[i];
        }
    }
    return err;
}

alc_error_t
InitGcm(const Uint8* pKey,
        int          nRounds,
        const Uint8* pIv,
        Uint64       ivBytes,
        __m128i*     pHsubKey_128,
        __m128i*     ptag_128,
        __m128i*     piv_128,
        __m128i      reverse_mask_128)
{
    alc_error_t err     = ALC_ERROR_NONE;
    auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);
    auto        pIv128  = reinterpret_cast<const __m128i*>(pIv);

    const __m256i const_factor_256 =
        _mm256_set_epi64x(0xC200000000000000, 0x1, 0xC200000000000000, 0x1);

    // pHsubKey_128 is already set to zero
    // Hash subkey generation.
    aesni::AesEncrypt(pHsubKey_128, pkey128, nRounds);
    // Hash sub key reversed for gf multiplication.
    *pHsubKey_128 = _mm_shuffle_epi8(*pHsubKey_128, reverse_mask_128);

    // H<<1 mod p
    *pHsubKey_128 = HashSubKeyLeftByOne(*pHsubKey_128);

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    __m128i swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    // Tag computation
    if ((ivBytes) == 12) {
        // iv
        utils::CopyBytes((Uint8*)piv_128, pIv, 12);
        // T= 96 bit iv : 32bit counter
        *ptag_128 = _mm_insert_epi32(*piv_128, 0x1000000, 3);
        aesni::AesEncrypt(ptag_128, pkey128, nRounds);

        // nonce counter
        *piv_128 = _mm_insert_epi32(*piv_128, 0x2000000, 3);
        *piv_128 = _mm_shuffle_epi8(*piv_128, swap_ctr);
    } else {
        // gmul uses aesni method with hkey<<1 mod poly. to be verified
        int     ivBlocks = ivBytes / Rijndael::cBlockSize;
        int     remBytes = ivBytes - (ivBlocks * Rijndael::cBlockSize);
        __m128i a128;
        __m128i one_128 = _mm_set_epi32(1, 0, 0, 0);

        *ptag_128 = _mm_setzero_si128();
        for (; ivBlocks >= 1; ivBlocks--) {
            a128 = _mm_loadu_si128(pIv128);
            gMulR(a128,
                  *pHsubKey_128,
                  reverse_mask_128,
                  ptag_128,
                  const_factor_256);
            pIv128++;
        }
        if (remBytes) {
            a128               = _mm_setzero_si128();
            const Uint8* p_in  = reinterpret_cast<const Uint8*>(pIv128);
            Uint8*       p_out = reinterpret_cast<Uint8*>(&a128);
            for (int i = 0; i < remBytes; i++) {
                p_out[i] = p_in[i];
            }
            gMulR(a128,
                  *pHsubKey_128,
                  reverse_mask_128,
                  ptag_128,
                  const_factor_256);
        }

        a128 = _mm_setzero_si128();
        a128 = _mm_insert_epi64(a128, (ivBytes << 3), 0);
        a128 = _mm_insert_epi64(a128, 0, 1);

        *ptag_128 = _mm_xor_si128(a128, *ptag_128);
        gMul(*ptag_128, *pHsubKey_128, ptag_128, const_factor_256);

        *ptag_128 = _mm_shuffle_epi8(*ptag_128, reverse_mask_128);
        *piv_128  = *ptag_128;

        *piv_128 = _mm_shuffle_epi8(*piv_128, swap_ctr);
        *piv_128 = _mm_add_epi32(*piv_128, one_128);

        aesni::AesEncrypt(ptag_128, pkey128, nRounds);
    }

    return err;
}

} // namespace alcp::cipher::vaes512
