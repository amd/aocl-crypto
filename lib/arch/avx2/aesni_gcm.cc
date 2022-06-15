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

#define AGGREGATED_REDUCTION
//#define DEBUG_P /* Enable for debugging only */

/*
    debug prints to be print input, cipher, iv and decrypted output
*/
#ifdef DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("\n %s", S);                                                        \
    for (int x = 0; x < L; x++) {                                              \
        printf(" %2x", *(I + x));                                              \
    }
#else // DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)
#endif // DEBUG_P

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
 Modulo reduction algorithm 5 in "Intel carry-less multiplication instruction
 in gcm mode" paper is used.
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

#ifdef AGGREGATED_REDUCTION
static void
computeKaratsubaZ0_Z2(__m128i  H1,
                      __m128i  H2,
                      __m128i  H3,
                      __m128i  H4,
                      __m128i  a,
                      __m128i  b,
                      __m128i  c,
                      __m128i  d,
                      __m128i* z0,
                      __m128i* z2)
{
    __m128i z0_a, z0_b, z0_c, z0_d, z2_a, z2_b, z2_c, z2_d;

    // compute x0y0
    // (Xi • H1)
    z0_a = _mm_clmulepi64_si128(H1, a, 0x00);
    // (Xi-1 • H2)
    z0_b = _mm_clmulepi64_si128(H2, b, 0x00);
    // (Xi-2 • H3)
    z0_c = _mm_clmulepi64_si128(H3, c, 0x00);
    // (Xi-3+Yi-4) •H4
    z0_d = _mm_clmulepi64_si128(H4, d, 0x00);

    // compute x1y1
    z2_a = _mm_clmulepi64_si128(H1, a, 0x11);
    z2_b = _mm_clmulepi64_si128(H2, b, 0x11);
    z2_c = _mm_clmulepi64_si128(H3, c, 0x11);
    z2_d = _mm_clmulepi64_si128(H4, d, 0x11);

    /* compute: z0 = x0y0
    z0 component of below equation:
    [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] */
    *z0 = _mm_xor_si128(z0_a, z0_b);
    *z0 = _mm_xor_si128(*z0, z0_c);
    *z0 = _mm_xor_si128(*z0, z0_d);

    /* compute: z2 = x1y1
    z2 component of below equation:
    [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] */
    *z2 = _mm_xor_si128(z2_a, z2_b);
    *z2 = _mm_xor_si128(*z2, z2_c);
    *z2 = _mm_xor_si128(*z2, z2_d);
}

static void
carrylessMul(__m128i  H1,
             __m128i  H2,
             __m128i  H3,
             __m128i  H4,
             __m128i  a,
             __m128i  b,
             __m128i  c,
             __m128i  d,
             __m128i* high,
             __m128i* low)
{
    /*
        Karatsuba algorithm to multiply two elements x,y
        Elements x,y are split as two equal 64 bit elements each.
        x = x1:x0
        y = y1:y0

        compute z2 and z0
        z0 = x0y0
        z2 = x1y1

        Reduce two multiplications in z1 to one.
        original: z1 = x1y0 + x0y1
        Reduced : z1 = (x1+x0) (y1+y0) - z2 - z0

        Aggregrated Reduction:
        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] mod P

    */

    __m128i z0, z2;
    __m128i a0, a1, a2, a3, a4, a5, a6, a7;
    __m128i xt, yt;
    computeKaratsubaZ0_Z2(H1, H2, H3, H4, a, b, c, d, &z0, &z2);

    /* compute: z1 = (x1+x0) (y1+y0) - z2 - z0 */

    // compute (x1+x0) and (y1+y0) for all 4 components
    // 1st component
    xt = _mm_srli_si128(a, 8);
    a1 = _mm_xor_si128(a, xt);
    yt = _mm_srli_si128(H1, 8);
    a0 = _mm_xor_si128(H1, yt);

    // 2nd component
    xt = _mm_srli_si128(b, 8);
    a3 = _mm_xor_si128(b, xt);
    yt = _mm_srli_si128(H2, 8);
    a2 = _mm_xor_si128(H2, yt);

    // 3rd component
    xt = _mm_srli_si128(c, 8);
    a5 = _mm_xor_si128(c, xt);
    yt = _mm_srli_si128(H3, 8);
    a4 = _mm_xor_si128(H3, yt);

    // 4th component
    xt = _mm_srli_si128(d, 8);
    a7 = _mm_xor_si128(d, xt);
    yt = _mm_srli_si128(H4, 8);
    a6 = _mm_xor_si128(H4, yt);

    // multiply (x1+x0) and (y1+y0)
    a0 = _mm_clmulepi64_si128(a0, a1, 0x00);
    a1 = _mm_clmulepi64_si128(a2, a3, 0x00);
    a2 = _mm_clmulepi64_si128(a4, a5, 0x00);
    a3 = _mm_clmulepi64_si128(a6, a7, 0x00);

    // add (-z2 -z0)
    a0 = _mm_xor_si128(z0, a0);
    a0 = _mm_xor_si128(z2, a0);

    // add 4 components
    a0 = _mm_xor_si128(a1, a0);
    a0 = _mm_xor_si128(a2, a0);
    a0 = _mm_xor_si128(a3, a0);

    a1 = _mm_slli_si128(a0, 8);
    a0 = _mm_srli_si128(a0, 8);

    *low  = _mm_xor_si128(a1, z0);
    *high = _mm_xor_si128(a0, z2);
}

static void
gMul(__m128i  H1,
     __m128i  H2,
     __m128i  H3,
     __m128i  H4,
     __m128i  a,
     __m128i  b,
     __m128i  c,
     __m128i  d,
     __m128i* res)
{
    __m128i high, low;

    /*
        Instead of 4 moduloReduction, perform aggregated reduction as per below
        equation.
        Aggregrated Reduction:
        [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3) +
            (Xi - 3 + Yi - 4) • H4] mod P
    */

    /*
        A = [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3) +
            (Xi - 3 + Yi - 4) • H4]
            */
    carrylessMul(H1, H2, H3, H4, a, b, c, d, &high, &low);

    // A mod P
    redMod(low, high, res);
}
#endif // AGGREGATED_REDUCTION

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
        *piv_128 = _mm_loadu_si128((__m128i*)pIv);
        // T= 96 bit iv : 32bit counter
        *ptag_128 = _mm_insert_epi32(*piv_128, 0x1000000, 3);
        aesni::AesEncrypt(ptag_128, pkey128, nRounds);

        // nonce counter
        *piv_128 = _mm_insert_epi32(*piv_128, 0x2000000, 3);
        *piv_128 = _mm_shuffle_epi8(*piv_128, swap_ctr);
    } else {
        int     ivBlocks = ivBytes / AES_BLOCK_SIZE(128);
        int     remBytes = ivBytes - (ivBlocks * AES_BLOCK_SIZE(128));
        __m128i a128;
        __m128i one_128 = _mm_set_epi32(1, 0, 0, 0);

        *ptag_128 = _mm_setzero_si128();
        for (; ivBlocks >= 1; ivBlocks--) {
            a128      = _mm_loadu_si128(pIv128);
            a128      = _mm_shuffle_epi8(a128, reverse_mask_128);
            *ptag_128 = _mm_xor_si128(a128, *ptag_128);
            gMul(*ptag_128, *pHsubKey_128, ptag_128);
            pIv128++;
        }
        if (remBytes) {
            a128                 = _mm_setzero_si128();
            const uint8_t* p_in  = pIv;
            uint8_t*       p_out = reinterpret_cast<uint8_t*>(&a128);
            for (int i = 0; i < remBytes; i++) {
                p_out[i] = p_in[i];
            }
            a128      = _mm_shuffle_epi8(a128, reverse_mask_128);
            *ptag_128 = _mm_xor_si128(a128, *ptag_128);
            gMul(*ptag_128, *pHsubKey_128, ptag_128);
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

    ALCP_PRINT_TEXT((uint8_t*)pHsubKey_128, 16, "subkey   ")
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

    __m128i a1, a2, a3, a4;
    __m128i c1, c2, c3, c4, swap_ctr;
    __m128i b1, b2, b3, b4;

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctr =
        _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);

    c1                = iv_128;
    __m128i one_128   = _mm_set_epi32(1, 0, 0, 0);
    __m128i two_128   = _mm_set_epi32(2, 0, 0, 0);
    __m128i three_128 = _mm_set_epi32(3, 0, 0, 0);
    __m128i four_128  = _mm_set_epi32(4, 0, 0, 0);

#ifdef AGGREGATED_REDUCTION
    __m128i Hsubkey_128_2, Hsubkey_128_3, Hsubkey_128_4;

    if (blocks >= 4) {
        gMul(Hsubkey_128, Hsubkey_128, &Hsubkey_128_2);
        gMul(Hsubkey_128_2, Hsubkey_128, &Hsubkey_128_3);
        gMul(Hsubkey_128_3, Hsubkey_128, &Hsubkey_128_4);
    }
#endif

    for (; blocks >= 4; blocks -= 4) {
        c2 = _mm_add_epi32(c1, one_128);
        c3 = _mm_add_epi32(c1, two_128);
        c4 = _mm_add_epi32(c1, three_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = _mm_loadu_si128(p_in_128 + 3);

        if (isEncrypt == false) {
            __m128i ra1, ra2, ra3, ra4;

            ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
            ra3 = _mm_shuffle_epi8(a3, reverse_mask_128);
            ra4 = _mm_shuffle_epi8(a4, reverse_mask_128);

#ifdef AGGREGATED_REDUCTION
            ra1 = _mm_xor_si128(ra1, *pgHash_128);

            gMul(Hsubkey_128,
                 Hsubkey_128_2,
                 Hsubkey_128_3,
                 Hsubkey_128_4,
                 ra4,
                 ra3,
                 ra2,
                 ra1,
                 pgHash_128);

#else
            ra1 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(ra1, Hsubkey_128, pgHash_128);

            ra2 = _mm_xor_si128(ra2, *pgHash_128);
            gMul(ra2, Hsubkey_128, pgHash_128);

            ra3 = _mm_xor_si128(ra3, *pgHash_128);
            gMul(ra3, Hsubkey_128, pgHash_128);

            ra4 = _mm_xor_si128(ra4, *pgHash_128);
            gMul(ra4, Hsubkey_128, pgHash_128);
#endif
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
            __m128i ra1, ra2, ra3, ra4;

            ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            ra2 = _mm_shuffle_epi8(a2, reverse_mask_128);
            ra3 = _mm_shuffle_epi8(a3, reverse_mask_128);
            ra4 = _mm_shuffle_epi8(a4, reverse_mask_128);

#ifdef AGGREGATED_REDUCTION

            ra1 = _mm_xor_si128(ra1, *pgHash_128);

            gMul(Hsubkey_128,
                 Hsubkey_128_2,
                 Hsubkey_128_3,
                 Hsubkey_128_4,
                 ra4,
                 ra3,
                 ra2,
                 ra1,
                 pgHash_128);

#else
            ra1 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(ra1, Hsubkey_128, pgHash_128);

            ra2 = _mm_xor_si128(ra2, *pgHash_128);
            gMul(ra2, Hsubkey_128, pgHash_128);

            ra3 = _mm_xor_si128(ra3, *pgHash_128);
            gMul(ra3, Hsubkey_128, pgHash_128);

            ra4 = _mm_xor_si128(ra4, *pgHash_128);
            gMul(ra4, Hsubkey_128, pgHash_128);
#endif
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

        const uint8_t* p_in  = reinterpret_cast<const uint8_t*>(p_in_128);
        uint8_t*       p_out = reinterpret_cast<uint8_t*>(&a1);

        int i = 0;
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
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        uint8_t* p_store = reinterpret_cast<uint8_t*>(p_out_128);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }
    }

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

    int ad_remBytes = additionalDataLen - (adBlocks * AES_BLOCK_SIZE(128));

    for (; adBlocks >= 1; adBlocks--) {
        ad1 = _mm_loadu_si128(pAd128);
        ad1 = _mm_shuffle_epi8(ad1, reverse_mask_128);

        *pgHash_128 = _mm_xor_si128(ad1, *pgHash_128);
        gMul(*pgHash_128, hash_subKey_128, pgHash_128);

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

        ad1 = _mm_shuffle_epi8(ad1, reverse_mask_128);

        *pgHash_128 = _mm_xor_si128(ad1, *pgHash_128);
        gMul(*pgHash_128, hash_subKey_128, pgHash_128);
    }

    ALCP_PRINT_TEXT((uint8_t*)pAd128, 16, "adddata  ")
    ALCP_PRINT_TEXT((uint8_t*)pgHash_128, 16, "addHash  ")

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

    *pgHash_128 = _mm_xor_si128(a1, *pgHash_128);
    gMul(*pgHash_128, Hsubkey_128, pgHash_128);

    *pgHash_128 = _mm_shuffle_epi8(*pgHash_128, reverse_mask_128);
    *ptag128    = _mm_xor_si128(*pgHash_128, *ptag128);
    _mm_storeu_si128(p_tag_128, *ptag128);

    return err;
}

} // namespace alcp::cipher::aesni
