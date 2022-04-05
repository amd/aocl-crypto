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
carrylessMul(__m128i a, __m128i b, __m128i* c, __m128i* d)
{
    __m128i e, f;
    /* carryless multiplication of a1:a0 * b1:b0 */
    *c = _mm_clmulepi64_si128(a, b, 0x00); // C1:C0 = a0*b0
    *d = _mm_clmulepi64_si128(a, b, 0x11); // D1:D0 = a1*b1
    e  = _mm_clmulepi64_si128(a, b, 0x10); // E1:E0 = a0*b1
    f  = _mm_clmulepi64_si128(a, b, 0x01); // F1:F0 = a1*b0
    /*
     * compute D1  :  D0+E1+F1 : C1+E0+F0: C0
     */
    e = _mm_xor_si128(e, f);  // E1+F1 : E0+F0
    f = _mm_slli_si128(e, 8); // E0+F0:0
    e = _mm_srli_si128(e, 8); // 0:E1+F1

    /* d : c = D1 : D0+E1+F1 : C1+E0+F1 : C0 */
    *c = _mm_xor_si128(*c, f); // C1+(E0+F1):C0
    *d = _mm_xor_si128(*d, e); // D1:D0+(E1+F1)
}

/* Reduction  */
static void
redMod(__m128i c, __m128i d, __m128i* res)
{
    // to be implemented
}

static void
gMul(__m128i a, __m128i b, __m128i* res)
{
    __m128i c, d;
    carrylessMul(a, b, &c, &d);
    redMod(c, d, res);
}

alc_error_t
EncryptInitGcm(const uint8_t* pKey,
               int            nRounds,
               const uint8_t* pIv,
               uint64_t       ivBytes,
               __m128i*       phash_subKey_128,
               __m128i*       ptag_128,
               __m128i        reverse_mask_128)
{
    alc_error_t err     = ALC_ERROR_NONE;
    auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

    // Hash subkey generation.
    aesni::AesEncrypt(phash_subKey_128, pkey128, nRounds);
    // Hash sub key reversed for gf multiplication.
    *phash_subKey_128 = _mm_shuffle_epi8(*phash_subKey_128, reverse_mask_128);

    // Tag computation
    if ((ivBytes) == 12) {
        // iv
        *ptag_128 = _mm_loadu_si128((__m128i*)pIv);
        // T= 96 bit iv : 32bit counter
        *ptag_128 = _mm_insert_epi32(*ptag_128, 0x1000000, 3);
        aesni::AesEncrypt(ptag_128, pkey128, nRounds);
    } else {
        printf("\n iv length!=12bytes (or 96bits) not supported ");
        return ALC_ERROR_NOT_SUPPORTED;
    }

    return err;
}

alc_error_t
EncryptGcm(const uint8_t* pPlainText,  // ptr to plaintext
           uint8_t*       pCipherText, // ptr to ciphertext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv,         // ptr to Initialization Vector
           __m128i*       pgHash_128,
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
    __m128i c1, c2, c3, c4, swap_ctr;
    __m128i b1, b2, b3, b4;

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);
    // nonce counter
    c1                = _mm_loadu_si128((__m128i*)pIv);
    c1                = _mm_insert_epi32(c1, 0x2000000, 3);
    __m128i one_128   = _mm_set_epi32(1, 0, 0, 0);
    __m128i two_128   = _mm_set_epi32(2, 0, 0, 0);
    __m128i three_128 = _mm_set_epi32(3, 0, 0, 0);
    __m128i four_128  = _mm_set_epi32(4, 0, 0, 0);
    c1                = _mm_shuffle_epi8(c1, swap_ctr);

    for (; blocks >= 4; blocks -= 4) {
        c2 = _mm_add_epi32(c1, one_128);
        c3 = _mm_add_epi32(c1, two_128);
        c4 = _mm_add_epi32(c1, three_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = _mm_loadu_si128(p_in_128 + 3);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        b2 = _mm_shuffle_epi8(c2, swap_ctr);
        b3 = _mm_shuffle_epi8(c3, swap_ctr);
        b4 = _mm_shuffle_epi8(c4, swap_ctr);

        aesni::AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

        a1 = _mm_xor_si128(b1, a1);
        a2 = _mm_xor_si128(b2, a2);
        a3 = _mm_xor_si128(b3, a3);
        a4 = _mm_xor_si128(b4, a4);

        // increment counter
        c1 = _mm_add_epi32(c1, four_128);

        __m128i ra  = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        ra          = _mm_shuffle_epi8(a2, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        ra          = _mm_shuffle_epi8(a3, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        ra          = _mm_shuffle_epi8(a4, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);
        _mm_storeu_si128(p_out_128 + 2, a3);
        _mm_storeu_si128(p_out_128 + 3, a4);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        c2 = _mm_add_epi32(c1, one_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        b2 = _mm_shuffle_epi8(c2, swap_ctr);

        aesni::AesEncrypt(&b1, &b2, pkey128, nRounds);

        a1 = _mm_xor_si128(b1, a1);
        a2 = _mm_xor_si128(b2, a2);

        // increment counter
        c1 = _mm_add_epi32(c1, two_128);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        __m128i ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra2, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        a1 = _mm_loadu_si128(p_in_128);

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1 = _mm_add_epi32(c1, one_128);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        _mm_storeu_si128(p_out_128, a1);

        p_in_128++;
        p_out_128++;
    }

    if (remBytes) {
        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        aesni::AesEncrypt(&b1, pkey128, nRounds);

        unsigned char* p_in  = (unsigned char*)p_in_128;
        unsigned char* p_out = (unsigned char*)&a1;
        int            i     = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }
        a1 = _mm_xor_si128(b1, a1);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);
    }
    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
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
          __m128i  reverse_mask_128,
          uint8_t* tag)
{
    alc_error_t err       = ALC_ERROR_NONE;
    auto        p_tag_128 = reinterpret_cast<__m128i*>(tag);
    __m128i     a1        = _mm_set_epi32(0, 0, 0, 0);

    a1 = _mm_insert_epi64(a1, (len << 3), 0);
    a1 = _mm_insert_epi64(a1, (adLength << 3), 1);
    a1 = _mm_shuffle_epi8(a1, reverse_mask_128);

    *pgHash_128 = _mm_xor_si128(a1, *pgHash_128);
    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
    gMul(*pgHash_128, Hsubkey_128, pgHash_128);

    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
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
