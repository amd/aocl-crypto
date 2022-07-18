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
#include "cipher/aes_gcm.hh"
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
 Modulo reduction algorithm 5 in "Intel carry-less multiplication instruction
 in gcm mode" paper is used.
*/
void
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

void
gMulR(__m128i a, __m128i b, __m128i reverse_mask_128, __m128i* res)
{
    a    = _mm_shuffle_epi8(a, reverse_mask_128);
    *res = alcp_xor(a, *res);

    __m128i c, d;
    carrylessMul(*res, b, &c, &d);
    redMod(c, d, res);
}

void
gMul(__m128i a, __m128i b, __m128i* res)
{
    __m128i c, d;
    carrylessMul(a, b, &c, &d);
    redMod(c, d, res);
}

static void
computeKaratsuba_Z0_Z2(__m128i  H1,
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
    computeKaratsuba_Z0_Z2(H1, H2, H3, H4, a, b, c, d, &z0, &z2);

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

void
gMulR(__m128i  H1,
      __m128i  H2,
      __m128i  H3,
      __m128i  H4,
      __m128i  a,
      __m128i  b,
      __m128i  c,
      __m128i  d,
      __m128i  reverse_mask_128,
      __m128i* res)
{
    a = _mm_shuffle_epi8(a, reverse_mask_128);
    b = _mm_shuffle_epi8(b, reverse_mask_128);
    c = _mm_shuffle_epi8(c, reverse_mask_128);
    d = _mm_shuffle_epi8(d, reverse_mask_128);

    *res = alcp_xor(d, *res);

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

    carrylessMul(H1, H2, H3, H4, a, b, c, *res, &high, &low);

    // A mod P
    redMod(low, high, res);
}

void
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
} // namespace alcp::cipher::aesni