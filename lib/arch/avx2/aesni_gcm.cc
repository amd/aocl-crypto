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

/*
 Modulo Reduction of 256bit to 128bit
 Modulor reduction algorithm 5 in "Intel carry-less multiplication instruction
 in gcm mode" paper
*/
static void
redMod(__m128i x10, __m128i x32, __m128i* res)
{
    __m128i a, b, c, d, e, f, g;

    /* shifting x10 and x32 left by 1 */
    a = _mm_slli_epi64(x10, 1);  //(x1:x0)<<1
    c = _mm_srli_epi64(x10, 63); //(x1:x0)>>63

    b = _mm_slli_epi64(x32, 1);  //(x3:x2)<<1
    d = _mm_srli_epi64(x32, 63); //(x3:x2)>>63

    e = _mm_slli_si128(c, 8); // x0>>63 : 0
    f = _mm_srli_si128(c, 8); //     0 : x1>>63
    g = _mm_slli_si128(d, 8); // x2>>63 : 0

    x10 = _mm_or_si128(e, a);   // (x0>>63|x1<<1 ) : (0|x0<<1)
    x32 = _mm_or_si128(g, b);   // (x3<<1 |x2>>63) : (x2<<1)
    x32 = _mm_or_si128(f, x32); // (x3<<1 |x2>>63) : (x2<<1 | x1>>63)

    /* compute A, B and C */
    a = _mm_slli_epi64(x10, 63); //*:x0<<63
    b = _mm_slli_epi64(x10, 62); //*:x0<<62
    c = _mm_slli_epi64(x10, 57); //*:x0<<57

    /* compute D = a⊕b⊕c */
    a = _mm_xor_si128(a, b);  //       *:a⊕b
    a = _mm_xor_si128(a, c);  //       *:a⊕b⊕c
    a = _mm_slli_si128(a, 8); // a⊕b⊕c:0

    /* compute d:x0 */
    d = _mm_xor_si128(x10, a); // x1 ⊕ (a⊕b⊕c) : x0 ⊕ 0

    /* e1:e0, f1:f0, g1:g0 */
    // e1:e0
    a = _mm_srli_epi64(d, 1);  // d:x0>>1
    e = _mm_slli_epi64(d, 63); // d:x0<<63
    // f1:f0
    b = _mm_srli_epi64(d, 2);  // d:x0>>2
    f = _mm_slli_epi64(d, 62); // d:x0<<62
    // g1:g0
    c = _mm_srli_epi64(d, 7);  // d:x0>>7
    g = _mm_slli_epi64(d, 57); // d:x0>>57

    /* compute Part1 of  e1⊕f1⊕g1 : e0⊕f0⊕g0 */
    a = _mm_xor_si128(b, a); // e1⊕f1    : e0⊕f0
    a = _mm_xor_si128(c, a); // e1⊕f1⊕g1 : e0⊕f0⊕g0

    /* compute Part2 of  e1⊕f1⊕g1 : e0⊕f0⊕g0 */
    e = _mm_xor_si128(e, f); // e1⊕f1    : e0⊕f0
    e = _mm_xor_si128(e, g); // e1⊕f1⊕g1 : e0⊕f0⊕g0
    e = _mm_srli_si128(e, 8);

    /* combine part1 and part2 */
    a = _mm_xor_si128(e, a); // part1 ⊕ part2

    /* compute H1:H0 */
    a = _mm_xor_si128(d, a); // H1:H0 = d⊕e1⊕f1⊕g1 : x0⊕e0⊕f0⊕g0

    /* X3⊕H1: X2⊕H0 */
    *res = _mm_xor_si128(x32, a);
}

static void
gMul(__m128i a, __m128i b, __m128i* res)
{
    __m128i c, d;
    carrylessMul(a, b, &c, &d);
    redMod(c, d, res);
}

alc_error_t
InitGcm(const uint8_t* pKey,
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
CryptGcm(const uint8_t* pInputText,  // ptr to inputText
         uint8_t*       pOutputText, // ptr to outputtext
         uint64_t       len,         // message length in bytes
         const uint8_t* pKey,        // ptr to Key
         int            nRounds,     // No. of rounds
         const uint8_t* pIv,         // ptr to Initialization Vector
         __m128i*       pgHash_128,
         __m128i        Hsubkey_128,
         __m128i        reverse_mask_128,
         bool           isEncrypt)
{
    alc_error_t err      = ALC_ERROR_NONE;
    uint64_t    blocks   = len / Rijndael::cBlockSize;
    int         remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pOutputText);
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

        if (isEncrypt == false) {
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
        }

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

        if (isEncrypt == true) {
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
        }

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

        if (isEncrypt == false) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);

            __m128i ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra2, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        b2 = _mm_shuffle_epi8(c2, swap_ctr);

        aesni::AesEncrypt(&b1, &b2, pkey128, nRounds);

        a1 = _mm_xor_si128(b1, a1);
        a2 = _mm_xor_si128(b2, a2);

        // increment counter
        c1 = _mm_add_epi32(c1, two_128);

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);

            __m128i ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra2, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        a1 = _mm_loadu_si128(p_in_128);

        if (isEncrypt == false) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        // re-arrange as per spec
        b1 = _mm_shuffle_epi8(c1, swap_ctr);
        aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1 = _mm_add_epi32(c1, one_128);

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

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

        if (isEncrypt == false) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        a1 = _mm_xor_si128(b1, a1);

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }
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

} // namespace alcp::cipher::aesni
