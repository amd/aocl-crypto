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

#include "aesni_macros.hh"
#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "error.hh"
#include "key.hh"

namespace alcp::cipher::aesni {

static void
gMul(__m128i a, __m128i hash_subKey_128, __m128i* res)
{
    // tbd
}

alc_error_t
EncryptInitGcm(const uint8_t* pKey,    // ptr to Key
               int            nRounds, // No. of rounds
               const uint8_t* pIv,     // ptr to Initialization Vector
               uint64_t       ivBytes,
               __m128i*       pgHash_128,
               __m128i*       phash_subKey_128,
               __m128i*       ptag_128,
               __m128i        reverse_mask_128)
{
    alc_error_t err     = ALC_ERROR_NONE;
    auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

    // ghash0 and parital Tag Aesenc
    *pgHash_128       = _mm_setzero_si128();
    *phash_subKey_128 = _mm_setzero_si128();

    if ((ivBytes * 8) == 96) {
        // iv
        *ptag_128 = _mm_loadu_si128((__m128i*)pIv);
        // T= iv || 32bit counter
        *ptag_128 = _mm_insert_epi32(*ptag_128, 0x1000000, 3);

        // compute Hash subkey and aesEnc for Tag in parallel.
        aesni::AesEncrypt(phash_subKey_128, ptag_128, pkey128, nRounds);
    } else {
        printf("\n iv length!=96bit not supported ");
        return ALC_ERROR_NOT_SUPPORTED;
    }

    // Hash sub key reversed for gf multiplication.
    *phash_subKey_128 = _mm_shuffle_epi8(*phash_subKey_128, reverse_mask_128);

    return err;
}

alc_error_t
EncryptGcm(const uint8_t* pPlainText,  // ptr to plaintext
           uint8_t*       pCipherText, // ptr to ciphertext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv,         // ptr to Initialization Vector
           __m128i*       pgHash,
           __m128i        Hsubkey_128,
           __m128i        reverse_mask_128)
{
    alc_error_t err      = ALC_ERROR_NONE;
    uint64_t    blocks   = len / Rijndael::cBlockSize;
    int         remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_128  = reinterpret_cast<const __m128i*>(pPlainText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pCipherText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    __m128i a1, a2, a3, a4;
    __m128i ctr1, ctr2, ctr3, ctr4, swap_ctr;
    __m128i b1, b2, b3, b4;

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);
    // nonce counter
    ctr1 = _mm_loadu_si128((__m128i*)pIv);
    ctr1 =
        _mm_insert_epi32(ctr1, 0x2000000, 3); // ctr1.m128i_i32[3] = 0x2000000;
    __m128i one_128   = _mm_set_epi32(1, 0, 0, 0);
    __m128i two_128   = _mm_set_epi32(2, 0, 0, 0);
    __m128i three_128 = _mm_set_epi32(3, 0, 0, 0);
    __m128i four_128  = _mm_set_epi32(4, 0, 0, 0);
    ctr1              = _mm_shuffle_epi8(ctr1, swap_ctr);

    for (; blocks >= 4; blocks -= 4) {
        ctr2 = _mm_add_epi32(ctr1, one_128);
        ctr3 = _mm_add_epi32(ctr1, two_128);
        ctr4 = _mm_add_epi32(ctr1, three_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = _mm_loadu_si128(p_in_128 + 3);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(ctr1, swap_ctr);
        b2 = _mm_shuffle_epi8(ctr2, swap_ctr);
        b3 = _mm_shuffle_epi8(ctr3, swap_ctr);
        b4 = _mm_shuffle_epi8(ctr4, swap_ctr);

        aesni::AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

        a1 = _mm_xor_si128(b1, a1);
        a2 = _mm_xor_si128(b2, a2);
        a3 = _mm_xor_si128(b3, a3);
        a4 = _mm_xor_si128(b4, a4);

        // increment counter
        ctr1 = _mm_add_epi32(ctr1, four_128);

        __m128i ra = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash    = _mm_xor_si128(ra, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        ra      = _mm_shuffle_epi8(a2, reverse_mask_128);
        *pgHash = _mm_xor_si128(ra, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        ra      = _mm_shuffle_epi8(a3, reverse_mask_128);
        *pgHash = _mm_xor_si128(ra, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        ra      = _mm_shuffle_epi8(a4, reverse_mask_128);
        *pgHash = _mm_xor_si128(ra, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);
        _mm_storeu_si128(p_out_128 + 2, a3);
        _mm_storeu_si128(p_out_128 + 3, a4);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        ctr2 = _mm_add_epi32(ctr1, one_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(ctr1, swap_ctr);
        b2 = _mm_shuffle_epi8(ctr2, swap_ctr);

        aesni::AesEncrypt(&b1, &b2, pkey128, nRounds);

        a1 = _mm_xor_si128(b1, a1);
        a2 = _mm_xor_si128(b2, a2);

        // increment counter
        ctr1 = _mm_add_epi32(ctr1, two_128);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash     = _mm_xor_si128(ra1, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        __m128i ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
        *pgHash     = _mm_xor_si128(ra2, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        a1 = _mm_loadu_si128(p_in_128);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(ctr1, swap_ctr);
        aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        ctr1 = _mm_add_epi32(ctr1, one_128);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash     = _mm_xor_si128(ra1, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);

        _mm_storeu_si128(p_out_128, a1);

        p_in_128++;
        p_out_128++;
    }

    if (remBytes) {
        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(ctr1, swap_ctr);
        aesni::AesEncrypt(&b1, pkey128, nRounds);

        unsigned char* p_in  = (unsigned char*)p_in_128;
        unsigned char* p_out = (unsigned char*)&a1;
        int            i     = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i]; // a1.m128i_i8[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0; // a1.m128i_i8[i] = 0;
        }
        a1 = _mm_xor_si128(b1, a1);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash     = _mm_xor_si128(ra1, *pgHash);
        gMul(*pgHash, Hsubkey_128, pgHash);
    }
    *pgHash = _mm_shuffle_epi8(*pgHash, reverse_mask_128);
    return err;
}

alc_error_t
processAdditionalDataGcm(const uint8_t* pAdditionalData,
                         uint64_t       additionalDataLen,
                         __m128i*       pgHash_128,
                         __m128i        hash_subKey_128,
                         __m128i        reverse_mask_128)
{
    alc_error_t err    = ALC_ERROR_NONE;
    auto        pAd128 = reinterpret_cast<const __m128i*>(pAdditionalData);

    // additional data hash.
    __m128i ad1;
    int     adBlocks = additionalDataLen / AES_BLOCK_SIZE(128);

    // assumption is padding of ad taking care outside
    // and ad_remBytes = 0
    // int ad_remBytes = additionalDataLen - (adBlocks * AES_BLOCK_SIZE(128));

    for (; adBlocks >= 1; adBlocks--) {
        ad1 = _mm_loadu_si128(pAd128);
        ad1 = _mm_shuffle_epi8(ad1, reverse_mask_128);

        // xor with gh0.
        *pgHash_128 = _mm_xor_si128(ad1, *pgHash_128);
        gMul(*pgHash_128, hash_subKey_128, pgHash_128);

        pAd128++;
    }
    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);

    return err;
}

alc_error_t
GetTagGcm(uint64_t len,
          uint64_t adLength,
          __m128i* pgHash_128,
          __m128i* ptag128,
          __m128i  Hsubkey_128,
          uint8_t* tag)
{
    alc_error_t err       = ALC_ERROR_NONE;
    auto        p_tag_128 = reinterpret_cast<__m128i*>(tag);
    __m128i     reverse_mask =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i a1 = _mm_set_epi32(0, 0, 0, 0);

    a1 = _mm_insert_epi64(a1, (len << 3), 0);
    a1 = _mm_insert_epi64(a1, (adLength << 3), 1);
    a1 = _mm_shuffle_epi8(a1, reverse_mask);

    *pgHash_128 = _mm_xor_si128(a1, *pgHash_128);
    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask);
    gMul(*pgHash_128, Hsubkey_128, pgHash_128);

    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask);
    *ptag128    = _mm_xor_si128(*pgHash_128, *ptag128);
    _mm_storeu_si128(p_tag_128, *ptag128);

    return err;
}
/*
alc_error_t
DecryptGcm(const uint8_t* pCipherText, // ptr to ciphertext
           uint8_t*       pPlainText,  // ptr to plaintext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;

    return err;
}*/

} // namespace alcp::cipher::aesni
