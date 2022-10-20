/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

#include "cipher/aes.hh"
#include "cipher/aes_gcm.hh"
#include "cipher/aesni.hh"
#include "cipher/avx128_gmul.hh"

#include "error.hh"
#include "key.hh"

namespace alcp::cipher::aesni {

alc_error_t
InitGcm(const uint8_t* pKey,
        int            nRounds,
        const uint8_t* pIv,
        uint64_t       ivBytes,
        __m128i*       pHsubKey_128,
        __m128i*       ptag_128,
        __m128i*       piv_128,
        __m128i        reverse_mask_128)
{
    alc_error_t err     = ALC_ERROR_NONE;
    auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);
    auto        pIv128  = reinterpret_cast<const __m128i*>(pIv);
    // pHsubKey_128 is already set to zero
    // Hash subkey generation.
    aesni::AesEncrypt(pHsubKey_128, pkey128, nRounds);
    // Hash sub key reversed for gf multiplication.
    *pHsubKey_128 = _mm_shuffle_epi8(*pHsubKey_128, reverse_mask_128);

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    __m128i swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    // Tag computation
    if ((ivBytes) == 12) {
        // iv
        //*piv_128 = _mm_loadu_si128((__m128i*)pIv);
        utils::CopyBytes((Uint8*)piv_128, pIv, 12);
        // T= 96 bit iv : 32bit counter
        *ptag_128 = _mm_insert_epi32(*piv_128, 0x1000000, 3);
        aesni::AesEncrypt(ptag_128, pkey128, nRounds);

        // nonce counter
        *piv_128 = _mm_insert_epi32(*piv_128, 0x2000000, 3);
        *piv_128 = _mm_shuffle_epi8(*piv_128, swap_ctr);
    } else {
        int     ivBlocks = ivBytes / Rijndael::cBlockSize;
        int     remBytes = ivBytes - (ivBlocks * Rijndael::cBlockSize);
        __m128i a128;
        __m128i one_128 = _mm_set_epi32(1, 0, 0, 0);

        *ptag_128 = _mm_setzero_si128();
        for (; ivBlocks >= 1; ivBlocks--) {
            a128 = _mm_loadu_si128(pIv128);
            gMulR(a128, *pHsubKey_128, reverse_mask_128, ptag_128);
            pIv128++;
        }
        if (remBytes) {
            a128                 = _mm_setzero_si128();
            const uint8_t* p_in  = pIv;
            uint8_t*       p_out = reinterpret_cast<uint8_t*>(&a128);
            for (int i = 0; i < remBytes; i++) {
                p_out[i] = p_in[i];
            }
            gMulR(a128, *pHsubKey_128, reverse_mask_128, ptag_128);
        }

        a128 = _mm_setzero_si128();
        a128 = _mm_insert_epi64(a128, (ivBytes << 3), 0);
        a128 = _mm_insert_epi64(a128, 0, 1);

        *ptag_128 = _mm_xor_si128(a128, *ptag_128);
        gMul(*ptag_128, *pHsubKey_128, ptag_128);

        *ptag_128 = _mm_shuffle_epi8(*ptag_128, reverse_mask_128);
        *piv_128  = *ptag_128;

        *piv_128 = _mm_shuffle_epi8(*piv_128, swap_ctr);
        *piv_128 = _mm_add_epi32(*piv_128, one_128);

        aesni::AesEncrypt(ptag_128, pkey128, nRounds);
    }

    return err;
}

void
gcmCryptInit(__m128i* c1,
             __m128i  iv_128,
             __m128i* one_lo,
             __m128i* one_x,
             __m128i* two_x,
             __m128i* three_x,
             __m128i* four_x,
             __m128i* eight_x,
             __m128i* swap_ctr)
{

    *one_x   = alcp_set_epi32(1, 0, 0, 0);
    *two_x   = alcp_set_epi32(2, 0, 0, 0);
    *three_x = alcp_set_epi32(3, 0, 0, 0);
    *four_x  = alcp_set_epi32(4, 0, 0, 0);
    one_lo   = one_x;

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    *swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    // nonce counter
    *c1 = iv_128;
}

alc_error_t
CryptGcm(const uint8_t* pInputText,  // ptr to inputText
         uint8_t*       pOutputText, // ptr to outputtext
         uint64_t       len,         // message length in bytes
         const uint8_t* pKey,        // ptr to Key
         int            nRounds,     // No. of rounds
         const uint8_t* pIv,         // ptr to Initialization Vector
         __m128i*       pgHash_128,
         __m128i        Hsubkey_128,
         __m128i        iv_128,
         __m128i        reverse_mask_128,
         bool           isEncrypt)
{
    alc_error_t err      = ALC_ERROR_NONE;
    uint64_t    blocks   = len / Rijndael::cBlockSize;
    int         remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    alcp::cipher::aes::gcmBlk(p_in_128,
                              p_out_128,
                              blocks,
                              pkey128,
                              pIv,
                              nRounds,
                              1, // factor*128
                              // gcm specific params
                              pgHash_128,
                              Hsubkey_128,
                              iv_128,
                              reverse_mask_128,
                              isEncrypt,
                              remBytes);

    return err;
}

alc_error_t
processAdditionalDataGcm(const uint8_t* pAdditionalData,
                         uint64_t       additionalDataLen,
                         __m128i*       pgHash_128,
                         __m128i        hash_subKey_128,
                         __m128i        reverse_mask_128)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (additionalDataLen == 0) {
        return ALC_ERROR_NONE;
    }
    auto pAd128 = reinterpret_cast<const __m128i*>(pAdditionalData);

    // additional data hash.
    __m128i ad1;
    int     adBlocks = additionalDataLen / Rijndael::cBlockSize;

    int ad_remBytes = additionalDataLen - (adBlocks * Rijndael::cBlockSize);

    for (; adBlocks >= 1; adBlocks--) {
        ad1 = _mm_loadu_si128(pAd128);
        gMulR(ad1, hash_subKey_128, reverse_mask_128, pgHash_128);
        pAd128++;
    }

    if (ad_remBytes) {
        const uint8_t* p_in  = reinterpret_cast<const uint8_t*>(pAd128);
        uint8_t*       p_out = reinterpret_cast<uint8_t*>(&ad1);
        int            i     = 0;

        for (; i < ad_remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }
        gMulR(ad1, hash_subKey_128, reverse_mask_128, pgHash_128);
    }

    return err;
}

alc_error_t
GetTagGcm(uint64_t tagLen,
          uint64_t plaintextLen,
          uint64_t adLength,
          __m128i* pgHash_128,
          __m128i* ptag128,
          __m128i  Hsubkey_128,
          __m128i  reverse_mask_128,
          uint8_t* tag)
{
    alc_error_t err       = ALC_ERROR_NONE;
    auto        p_tag_128 = reinterpret_cast<__m128i*>(tag);
    __m128i     a1        = _mm_set_epi32(0, 0, 0, 0);

    a1 = _mm_insert_epi64(a1, (plaintextLen << 3), 0);
    a1 = _mm_insert_epi64(a1, (adLength << 3), 1);

    *pgHash_128 = _mm_xor_si128(a1, *pgHash_128);
    gMul(*pgHash_128, Hsubkey_128, pgHash_128);

    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
    *ptag128    = _mm_xor_si128(*pgHash_128, *ptag128);

    if (tagLen == 16) {
        _mm_storeu_si128(p_tag_128, *ptag128);
    } else {
        uint64_t       i     = 0;
        const uint8_t* p_in  = reinterpret_cast<const uint8_t*>(ptag128);
        uint8_t*       p_out = reinterpret_cast<uint8_t*>(tag);
        for (; i < tagLen; i++) {
            p_out[i] = p_in[i];
        }
    }
    return err;
}

} // namespace alcp::cipher::aesni
