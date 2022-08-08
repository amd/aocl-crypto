/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include <immintrin.h>

#include "alcp/error.h"

/*
 *
 * Galois Multiplicaiton we use below algorithms from "Intel carry-less
 * multiplication instruction in gcm mode"
 *     1. Aggregated Reduction and
 *     2. ModuloReduction algorithms
 * https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
 *
 *
 *     24 blocks (6*512bit) Aggregated reduction seems to perform better than
 * 16 blocks (4*512bit) Aggregated reduction in our experiments for larger
 *
 *     Inorder to reduce number of ModuloReduction operation, we parallelize 96
 * blocks and do one ModuloReduction at the end. This results in one
 * ModuloReduction for 96 blocks. But this results in performance penalty in
 * precomputing 95 HashSubkeys. So we use threshold to choose sizes above
 * which parallel 96blocks galoisMul can be used.
 *
 */

namespace alcp::cipher { namespace vaes {

    /*
     * Modulo Reduction of 256bit to 128bit
     * Modulo reduction algorithm 5 in "Intel carry-less multiplication
     * instruction in gcm mode" paper is used.
     */
    static inline void redModx(__m128i x10, __m128i x32, __m128i* res)
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

    static inline __m128i amd512_horizontal_sum128(__m512i x_512)
    {
        __m128i a_128, b_128, c_128, d_128;
        a_128 = _mm512_extracti64x2_epi64(x_512, 0);
        b_128 = _mm512_extracti64x2_epi64(x_512, 1);
        c_128 = _mm512_extracti64x2_epi64(x_512, 2);
        d_128 = _mm512_extracti64x2_epi64(x_512, 3);

        a_128 = _mm_xor_si128(a_128, b_128);
        a_128 = _mm_xor_si128(a_128, c_128);
        a_128 = _mm_xor_si128(a_128, d_128);

        return a_128;
    }

    static inline __m512i amd512xorLast128bit(__m512i a, __m128i b_128)
    {
        // a3:a2:a1:(a0 xor b_128)
        uint64_t* b_64  = (uint64_t*)&b_128;
        __m512i   b_512 = _mm512_set_epi64(0, 0, 0, 0, 0, 0, b_64[1], b_64[0]);
        return _mm512_mask_xor_epi64(a, 3, a, b_512);
    }

    static inline void computeKaratsuba_Z0_Z2(__m512i  H_512,
                                              __m512i  abcd_512,
                                              __m512i* z0_512,
                                              __m512i* z2_512)
    {
        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        *z0_512 = _mm512_clmulepi64_epi128(H_512, abcd_512, 0x00);

        // compute x1y1
        *z2_512 = _mm512_clmulepi64_epi128(H_512, abcd_512, 0x11);
    }

    static inline void computeKaratsuba_Z1(__m512i  H_512,
                                           __m512i  abcd_512,
                                           __m512i* z1_512)
    {
        __m512i H_512_high, abcd_512_high;
        H_512_high    = _mm512_bsrli_epi128(H_512, 8);
        abcd_512_high = _mm512_bsrli_epi128(abcd_512, 8);

        H_512_high    = _mm512_xor_si512(H_512_high, H_512);
        abcd_512_high = _mm512_xor_si512(abcd_512_high, abcd_512);

        *z1_512 = _mm512_clmulepi64_epi128(H_512_high, abcd_512_high, 0x00);
    }

    /* Aggregated reduction method + Karatsuba algorithm */
    static inline void computeKaratsubaComponents(__m512i  H_512,
                                                  __m512i  abcd_512,
                                                  __m512i* z0_512,
                                                  __m512i* z1_512,
                                                  __m512i* z2_512)
    {
        /*
         *  Karatsuba algorithm to multiply two elements x,y
         *  Elements x,y are split as two equal 64 bit elements each.
         *  x = x1:x0
         *  y = y1:y0
         *
         *  compute z2 and z0
         *  z0 = x0y0
         *  z2 = x1y1
         *
         *  Reduce two multiplications in z1 to one.
         *  original: z1 = x1y0 + x0y1
         *  Reduced : z1 = (x1+x0) (y1+y0) - z2 - z0
         *
         *  Aggregrated Reduction:
         *  [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] modP
         *
         */
        computeKaratsuba_Z0_Z2(H_512, abcd_512, z0_512, z2_512);

        /* compute: z1 = (x1+x0) (y1+y0) - z2 - z0 */
        computeKaratsuba_Z1(H_512, abcd_512, z1_512);
    }

    static inline __m512i amd512_reverse512_xorLast128bit(
        __m512i a, __m512i reverse_mask_512, __m128i res)
    {
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        return amd512xorLast128bit(a, res);
    }

    static inline void computeKaratsubaMul(
        __m128i z0, __m128i z1, __m128i z2, __m128i* low, __m128i* high)
    {
        __m128i a1;

        z1 = _mm_xor_si128(z1, z0); // z1 - zo
        z1 = _mm_xor_si128(z1, z2); // z1 - zo -z2

        a1 = _mm_slli_si128(z1, 8);
        z1 = _mm_srli_si128(z1, 8);

        *low  = _mm_xor_si128(a1, z0);
        *high = _mm_xor_si128(z1, z2);
    }

    static inline void gMulR(__m512i  H_512,
                             __m512i  abcd_512,
                             __m512i  reverse_mask_512,
                             __m128i* res)
    {
        __m128i high, low;
        __m512i z0_512, z1_512, z2_512;
        __m128i z0, z1, z2;

        abcd_512 =
            amd512_reverse512_xorLast128bit(abcd_512, reverse_mask_512, *res);
        computeKaratsubaComponents(H_512, abcd_512, &z0_512, &z1_512, &z2_512);

        /* compute: z0 = x0y0
         *        z0 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         *
         *  compute: z2 = x1y1
         *        z2 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         */
        z0 = amd512_horizontal_sum128(z0_512);
        z2 = amd512_horizontal_sum128(z2_512);
        z1 = amd512_horizontal_sum128(z1_512);

        computeKaratsubaMul(z0, z1, z2, &low, &high);

        // ModuloReduction
        redModx(low, high, res);
    }

    static inline __m512i amd512_xor_all(__m512i x0,
                                         __m512i x1,
                                         __m512i x2,
                                         __m512i x3)
    {
        x0 = _mm512_xor_si512(x0, x1);
        x0 = _mm512_xor_si512(x0, x2);
        return _mm512_xor_si512(x0, x3);
    }

    /* 16 blocks aggregated reduction
     * Galois field Multiplication of 16 blocks followed by one modulo
     * Reducation
     */
    static inline void gMulR(__m512i  H1,
                             __m512i  H2,
                             __m512i  H3,
                             __m512i  H4,
                             __m512i  a,
                             __m512i  b,
                             __m512i  c,
                             __m512i  d,
                             __m512i  reverse_mask_512,
                             __m128i* res)
    {

        __m512i z0_512_a, z1_512_a, z2_512_a;
        __m512i z0_512_b, z1_512_b, z2_512_b;
        __m512i z0_512_c, z1_512_c, z2_512_c;
        __m512i z0_512_d, z1_512_d, z2_512_d;

        __m128i z0, z1, z2;

        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);

        __m128i low, high;
        // a
        a = amd512xorLast128bit(a, *res);
        computeKaratsubaComponents(H4, a, &z0_512_a, &z1_512_a, &z2_512_a);

        // b
        computeKaratsubaComponents(H3, b, &z0_512_b, &z1_512_b, &z2_512_b);

        // c
        computeKaratsubaComponents(H2, c, &z0_512_c, &z1_512_c, &z2_512_c);

        // d
        computeKaratsubaComponents(H1, d, &z0_512_d, &z1_512_d, &z2_512_d);

        z0_512_a = amd512_xor_all(z0_512_a, z0_512_b, z0_512_c, z0_512_d);
        z1_512_a = amd512_xor_all(z1_512_a, z1_512_b, z1_512_c, z1_512_d);
        z2_512_a = amd512_xor_all(z2_512_a, z2_512_b, z2_512_c, z2_512_d);

        z0 = amd512_horizontal_sum128(z0_512_a);
        z1 = amd512_horizontal_sum128(z1_512_a);
        z2 = amd512_horizontal_sum128(z2_512_a);

        computeKaratsubaMul(z0, z1, z2, &low, &high);
        redModx(low, high, res);
    }

    static inline __m512i amd512_xor_all(
        __m512i x0, __m512i x1, __m512i x2, __m512i x3, __m512i x4, __m512i x5)
    {
        x0 = _mm512_xor_si512(x0, x1);
        x0 = _mm512_xor_si512(x0, x2);
        x0 = _mm512_xor_si512(x0, x3);
        x0 = _mm512_xor_si512(x0, x4);
        x0 = _mm512_xor_si512(x0, x5);
        return x0;
    }

    /* 24 blocks aggregated reduction
     * Galois field Multiplication of 24 blocks followed by one modulo
     * Reducation
     *
     * Each 512 bit zmm register contains 4 blocks of 128 bit.
     * 6 * 512 bit = 6 * 4 blocks = 24 blocks
     */
    static inline void gMulR(__m512i  H1,
                             __m512i  H2,
                             __m512i  H3,
                             __m512i  H4,
                             __m512i  H5,
                             __m512i  H6,
                             __m512i  a,
                             __m512i  b,
                             __m512i  c,
                             __m512i  d,
                             __m512i  e,
                             __m512i  f,
                             __m512i  reverse_mask_512,
                             __m128i* res)
    {
        __m512i z0_512_a, z1_512_a, z2_512_a;
        __m512i z0_512_b, z1_512_b, z2_512_b;
        __m512i z0_512_c, z1_512_c, z2_512_c;
        __m512i z0_512_d, z1_512_d, z2_512_d;
        __m512i z0_512_e, z1_512_e, z2_512_e;
        __m512i z0_512_f, z1_512_f, z2_512_f;

        __m128i z0, z1, z2;

        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);
        e = _mm512_shuffle_epi8(e, reverse_mask_512);
        f = _mm512_shuffle_epi8(f, reverse_mask_512);

        __m128i low, high;
        // a
        a = amd512xorLast128bit(a, *res);

        computeKaratsubaComponents(H6, a, &z0_512_a, &z1_512_a, &z2_512_a);
        // b
        computeKaratsubaComponents(H5, b, &z0_512_b, &z1_512_b, &z2_512_b);
        // c
        computeKaratsubaComponents(H4, c, &z0_512_c, &z1_512_c, &z2_512_c);
        // d
        computeKaratsubaComponents(H3, d, &z0_512_d, &z1_512_d, &z2_512_d);
        // e
        computeKaratsubaComponents(H2, e, &z0_512_e, &z1_512_e, &z2_512_e);
        // f
        computeKaratsubaComponents(H1, f, &z0_512_f, &z1_512_f, &z2_512_f);

        z0_512_a = amd512_xor_all(
            z0_512_a, z0_512_b, z0_512_c, z0_512_d, z0_512_e, z0_512_f);
        z1_512_a = amd512_xor_all(
            z1_512_a, z1_512_b, z1_512_c, z1_512_d, z1_512_e, z1_512_f);
        z2_512_a = amd512_xor_all(
            z2_512_a, z2_512_b, z2_512_c, z2_512_d, z2_512_e, z2_512_f);

        z0 = amd512_horizontal_sum128(z0_512_a);
        z1 = amd512_horizontal_sum128(z1_512_a);
        z2 = amd512_horizontal_sum128(z2_512_a);

        computeKaratsubaMul(z0, z1, z2, &low, &high);
        redModx(low, high, res);
    }

    /*
     * For 24 blocks (6*512 bit), Compute Karatsuba comonents z0, z1 and z2
     *
     * Each 512 bit zmm register contains 4 blocks of 128 bit.
     * 6 * 512 bit = 6 * 4 blocks = 24 blocks
     */
    static inline void get_aggregated_karatsuba_components(
        __m512i  H1,
        __m512i  H2,
        __m512i  H3,
        __m512i  H4,
        __m512i  H5,
        __m512i  H6,
        __m512i  a,
        __m512i  b,
        __m512i  c,
        __m512i  d,
        __m512i  e,
        __m512i  f,
        __m512i  reverse_mask_512,
        __m512i* z0_512,
        __m512i* z1_512,
        __m512i* z2_512,
        __m128i  res,
        bool     isFirst)
    {

        __m512i z0_512_a, z1_512_a, z2_512_a;
        __m512i z0_512_b, z1_512_b, z2_512_b;
        __m512i z0_512_c, z1_512_c, z2_512_c;
        __m512i z0_512_d, z1_512_d, z2_512_d;
        __m512i z0_512_e, z1_512_e, z2_512_e;
        __m512i z0_512_f, z1_512_f, z2_512_f;

        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);
        e = _mm512_shuffle_epi8(e, reverse_mask_512);
        f = _mm512_shuffle_epi8(f, reverse_mask_512);

        if (isFirst) {
            // a
            a = amd512xorLast128bit(a, res);
        }

        computeKaratsubaComponents(H6, a, &z0_512_a, &z1_512_a, &z2_512_a);
        // b
        computeKaratsubaComponents(H5, b, &z0_512_b, &z1_512_b, &z2_512_b);
        // c
        computeKaratsubaComponents(H4, c, &z0_512_c, &z1_512_c, &z2_512_c);
        // d
        computeKaratsubaComponents(H3, d, &z0_512_d, &z1_512_d, &z2_512_d);
        // e
        computeKaratsubaComponents(H2, e, &z0_512_e, &z1_512_e, &z2_512_e);
        // f
        computeKaratsubaComponents(H1, f, &z0_512_f, &z1_512_f, &z2_512_f);

        *z0_512 = amd512_xor_all(
            z0_512_a, z0_512_b, z0_512_c, z0_512_d, z0_512_e, z0_512_f);
        *z1_512 = amd512_xor_all(
            z1_512_a, z1_512_b, z1_512_c, z1_512_d, z1_512_e, z1_512_f);
        *z2_512 = amd512_xor_all(
            z2_512_a, z2_512_b, z2_512_c, z2_512_d, z2_512_e, z2_512_f);
    }

    /*
     * For 16 blocks (4*512 bit), Compute Karatsuba comonents z0, z1 and z2
     *
     * Each 512 bit zmm register contains 4 blocks of 128 bit.
     * 4 * 512 bit = 4 * 4 blocks = 16 blocks
     */
    static inline void get_aggregated_karatsuba_components(
        __m512i  H1,
        __m512i  H2,
        __m512i  H3,
        __m512i  H4,
        __m512i  a,
        __m512i  b,
        __m512i  c,
        __m512i  d,
        __m512i  reverse_mask_512,
        __m512i* z0_512,
        __m512i* z1_512,
        __m512i* z2_512,
        __m128i  res,
        bool     isFirst)
    {
        __m512i z0_512_a, z1_512_a, z2_512_a;
        __m512i z0_512_b, z1_512_b, z2_512_b;
        __m512i z0_512_c, z1_512_c, z2_512_c;
        __m512i z0_512_d, z1_512_d, z2_512_d;

        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);

        if (isFirst) {
            // a
            a = amd512xorLast128bit(a, res);
        }

        computeKaratsubaComponents(H4, a, &z0_512_a, &z1_512_a, &z2_512_a);
        // b
        computeKaratsubaComponents(H3, b, &z0_512_b, &z1_512_b, &z2_512_b);
        // c
        computeKaratsubaComponents(H2, c, &z0_512_c, &z1_512_c, &z2_512_c);
        // d
        computeKaratsubaComponents(H1, d, &z0_512_d, &z1_512_d, &z2_512_d);

        *z0_512 = amd512_xor_all(z0_512_a, z0_512_b, z0_512_c, z0_512_d);
        *z1_512 = amd512_xor_all(z1_512_a, z1_512_b, z1_512_c, z1_512_d);
        *z2_512 = amd512_xor_all(z2_512_a, z2_512_b, z2_512_c, z2_512_d);
    }

    static inline void getGhash(__m512i  z0_512,
                                __m512i  z1_512,
                                __m512i  z2_512,
                                __m128i* res)
    {

        __m128i z0 = amd512_horizontal_sum128(z0_512);
        __m128i z1 = amd512_horizontal_sum128(z1_512);
        __m128i z2 = amd512_horizontal_sum128(z2_512);

        __m128i low, high;
        computeKaratsubaMul(z0, z1, z2, &low, &high);
        redModx(low, high, res);
    }

}} // namespace alcp::cipher::vaes
