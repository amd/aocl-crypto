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

#pragma once

#include <immintrin.h>

#include "alcp/cipher/gmul.hh"
#include "alcp/error.h"

/*
 *
 * Galois Multiplicaiton we use below algorithms from "Intel carry-less
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

namespace alcp::cipher { namespace vaes512 {

    /*
     * Modulo Reduction of 256bit to 128bit
     * Modulo reduction algorithm 4 (Montgomery Reduction) in
     *
     * "Shay Gueron. AES-GCM for Efficient Authenticated Encryption -
     * Ending the reign of HMAC-SHA-1?, Workshop on Real-World Cryptography,
     * 2013. https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf.
     */

    static const Uint64 const_factor[] = { 0x1, 0xC200000000000000,
                                           0x1, 0xC200000000000000,
                                           0x1, 0xC200000000000000,
                                           0x1, 0xC200000000000000 };

    /* Intermediate Ghash computation done stored in 512 bit */
    static inline void montgomeryReduction(__m256i       input_256,
                                           __m512i&      result,
                                           const __m256i const_factor_256)
    {
        __m256i       mul, high_256;
        constexpr int cSwizzle = SWIZZLE(2, 3, 0, 1);

        high_256 =
            _mm256_permute4x64_epi64(input_256, cSwizzle); // move hi to low.

        // A1:A0
        mul = _mm256_clmulepi64_epi128(input_256, const_factor_256, 0x10);
        // A0:A1
        mul = _mm256_shuffle_epi32(mul, cSwizzle);

        // B0:B1
        input_256 = _mm256_xor_si256(mul, input_256);

        mul = _mm256_clmulepi64_epi128(input_256, const_factor_256, 0x11);

        input_256 = _mm256_xor_si256(mul, input_256);

        mul    = _mm256_xor_si256(high_256, input_256);
        result = _mm512_castsi256_si512(mul);
    }

    static inline __m128i amd512_horizontal_sum128(const __m512i& x_512)
    {
        __m256i a_256, b_256;
        __m128i a_128, b_128;

        a_256 = _mm512_castsi512_si256(x_512);
        b_256 = _mm512_extracti64x4_epi64(x_512, 1);

        a_256 = _mm256_xor_si256(a_256, b_256);

        a_128 = _mm256_extracti32x4_epi32(a_256, 1);
        b_128 = _mm256_castsi256_si128(a_256);

        a_128 = _mm_xor_si128(a_128, b_128);

        return a_128;
    }

    static inline void amd512xorLast128bit(__m512i& a, const __m512i& b)
    {
        // a3:a2:a1:(a0 xor b)
        a = _mm512_mask_xor_epi64(a, 3, a, b);
    }

    static inline void computeKaratsuba_Z0_Z2(const __m512i& H,
                                              const __m512i& a,
                                              __m512i&       z0_512,
                                              __m512i&       z2_512)
    {
        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        z0_512 = _mm512_clmulepi64_epi128(H, a, 0x00);

        // compute x1y1
        z2_512 = _mm512_clmulepi64_epi128(H, a, 0x11);
    }

    static inline void computeKaratsuba_Z1(const __m512i& H,
                                           const __m512i& a,
                                           __m512i&       z1_512)
    {
        __m512i H_high, a_high;
        H_high = _mm512_bsrli_epi128(H, 8);
        a_high = _mm512_bsrli_epi128(a, 8);

        H_high = _mm512_xor_si512(H_high, H);
        a_high = _mm512_xor_si512(a_high, a);

        z1_512 = _mm512_clmulepi64_epi128(H_high, a_high, 0x00);
    }

    /* Aggregated reduction method + Karatsuba algorithm */
    static inline void computeKaratsubaComponents(const __m512i& H, // input
                                                  const __m512i& a, // input
                                                  __m512i& z0_512,  // output
                                                  __m512i& z1_512,  // output
                                                  __m512i& z2_512)  // output
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
        computeKaratsuba_Z0_Z2(H, a, z0_512, z2_512);

        /* To compute: z1 = (x1+x0) (y1+y0) - z2 - z0
         * compute (x1+x0) (y1+y0) part in below function */
        computeKaratsuba_Z1(H, a, z1_512);
    }

    /* Aggregated reduction method + Karatsuba algorithm */
    static inline void computeKaratsubaComponentsAccumulate(const __m512i& H,
                                                            const __m512i& a,
                                                            __m512i& z0_512,
                                                            __m512i& z1_512,
                                                            __m512i& z2_512)
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

        __m512i t1, t2;

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2) : (Xi-2 • H3) : (Xi-3+Yi-4) •H4
        t1 = _mm512_clmulepi64_epi128(H, a, 0x00);

        // compute x1y1
        t2 = _mm512_clmulepi64_epi128(H, a, 0x11);

        // accumulate with verious z0
        z0_512 = _mm512_xor_si512(t1, z0_512);

        // accumulate with verious z2
        z2_512 = _mm512_xor_si512(t2, z2_512);

        // z1 compute: extract all x1 and y1
        t1 = _mm512_bsrli_epi128(H, 8); // high of H
        t2 = _mm512_bsrli_epi128(a, 8); // high of a

        // z1 compute: (x1+x0) and (y1+y0)
        t1 = _mm512_xor_si512(t1, H);
        t2 = _mm512_xor_si512(t2, a);

        t1 = _mm512_clmulepi64_epi128(t1, t2, 0x00);

        // accumulate with verious z1
        z1_512 = _mm512_xor_si512(t1, z1_512);
    }

    static inline void amd512_reverse512_xorLast128bit(
        __m512i& a, const __m512i& reverse_mask_512, const __m512i& res)
    {
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        amd512xorLast128bit(a, res);
    }

    static inline void computeKaratsubaMul(__m128i  z0,
                                           __m128i  z1,
                                           __m128i  z2,
                                           __m256i& res)
    {
        __m128i a1;
        res = _mm256_set_m128i(z2, z0);
        /*
         * compute:    z1 = (x1+x0) (y1+y0) - z2 - z0
         *
         * inputParam: z1 = (x1+x0) (y1+y0) */

        // (x1+x0) (y1+y0) - zo -z2 = (x1+x0) (y1+y0) xor z0 xor z2
        z1 = _mm_xor_si128(z1, z0);
        z1 = _mm_xor_si128(z1, z2);

        a1 = _mm_slli_si128(z1, 8);
        z1 = _mm_srli_si128(z1, 8);

        __m256i temp = _mm256_set_m128i(z1, a1);
        res          = _mm256_xor_si256(temp, res);
    }

    /* 16 blocks aggregated reduction
     * Galois field Multiplication of 16 blocks followed by one modulo
     * Reducation
     */
    static inline void gMulR(const __m512i& H1,
                             const __m512i& H2,
                             const __m512i& H3,
                             const __m512i& H4,
                             __m512i        a,
                             __m512i        b,
                             __m512i        c,
                             __m512i        d,
                             const __m512i& reverse_mask_512,
                             __m512i&       res,
                             const __m256i& const_factor_256)
    {

        __m512i z0_512, z1_512, z2_512;

        // reverseInput
        amd512_reverse512_xorLast128bit(a, reverse_mask_512, res);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);

        computeKaratsubaComponents(H4, a, z0_512, z1_512, z2_512);
        computeKaratsubaComponentsAccumulate(H3, b, z0_512, z1_512, z2_512);
        computeKaratsubaComponentsAccumulate(H2, c, z0_512, z1_512, z2_512);
        computeKaratsubaComponentsAccumulate(H1, d, z0_512, z1_512, z2_512);

        __m128i z0_or_low, z1, z2_or_high;
        z0_or_low  = amd512_horizontal_sum128(z0_512);
        z2_or_high = amd512_horizontal_sum128(z2_512);
        z1         = amd512_horizontal_sum128(z1_512);

        aesni::computeKaratsubaMul(z0_or_low, z1, z2_or_high);
        __m256i z2z0 = _mm256_set_m128i(z2_or_high, z0_or_low);
        montgomeryReduction(z2z0, res, const_factor_256);
    }

    /* 8 blocks aggregated reduction
     * Galois field Multiplication of 16 blocks followed by one modulo
     * Reducation
     */
    static inline void gMulR(const __m512i& H1,
                             const __m512i& H2,
                             __m512i        a,
                             __m512i        b,
                             const __m512i& reverse_mask_512,
                             __m512i&       res,
                             const __m256i& const_factor_256)
    {
        __m512i z0_512, z1_512, z2_512;

        // reverseInput
        amd512_reverse512_xorLast128bit(a, reverse_mask_512, res);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);

        computeKaratsubaComponents(H2, a, z0_512, z1_512, z2_512);
        computeKaratsubaComponentsAccumulate(H1, b, z0_512, z1_512, z2_512);

        __m128i z0_or_low, z1, z2_or_high;
        z0_or_low  = amd512_horizontal_sum128(z0_512);
        z2_or_high = amd512_horizontal_sum128(z2_512);
        z1         = amd512_horizontal_sum128(z1_512);

        aesni::computeKaratsubaMul(z0_or_low, z1, z2_or_high);
        __m256i z2z0 = _mm256_set_m128i(z2_or_high, z0_or_low);
        montgomeryReduction(z2z0, res, const_factor_256);
    }

    static inline void gMulR(const __m512i& H,
                             __m512i        a,
                             const __m512i& reverse_mask_512,
                             __m512i&       res,
                             const __m256i& const_factor_256)
    {
        __m512i z0_512, z1_512, z2_512;
        __m128i z0_or_low, z1, z2_or_high;

        amd512_reverse512_xorLast128bit(a, reverse_mask_512, res);
        computeKaratsubaComponents(H, a, z0_512, z1_512, z2_512);

        /* compute: z0 = x0y0
         *        z0 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         *
         *  compute: z2 = x1y1
         *        z2 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         */
        z0_or_low  = amd512_horizontal_sum128(z0_512);
        z2_or_high = amd512_horizontal_sum128(z2_512);
        z1         = amd512_horizontal_sum128(z1_512);

        aesni::computeKaratsubaMul(z0_or_low, z1, z2_or_high);
        __m256i z2z0 = _mm256_set_m128i(z2_or_high, z0_or_low);
        montgomeryReduction(z2z0, res, const_factor_256);
    }

    static inline void gMulParallel4(__m512i&       res,
                                     const __m512i& H4321_512,
                                     const __m512i& H4444_512,
                                     const __m512i  const_factor_512)
    {
        __m512i z0_512, z1_512, z1L_512, z2_512;

        computeKaratsubaComponents(
            H4321_512, H4444_512, z0_512, z1_512, z2_512);

        /* compute: z0 = x0y0
         *        z0 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         *
         *  compute: z2 = x1y1
         *        z2 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4]
         */

        // z1 - zo -z2 = z1 xor z0 xor z2
        z1_512 = _mm512_xor_si512(z1_512, z0_512);
        z1_512 = _mm512_xor_si512(z1_512, z2_512);

        // z1Low64bit
        z1L_512 = _mm512_bslli_epi128(z1_512, 8);
        // z1High64bit
        z1_512 = _mm512_bsrli_epi128(z1_512, 8);

        // low 128bit CLMul result for 4 GHASH
        z0_512 = _mm512_xor_si512(z0_512, z1L_512);
        // high 128bit CLMul result for 4 GHASH
        z2_512 = _mm512_xor_si512(z2_512, z1_512);

        /* Modulo reduction of (high 128bit: low 128bit)  components to
         * 128bit Fast modulo reduction  Algorithm 4 in
         * https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
         *
         */
        // A1:A0 = X0 *  0xc200000000000000
        z1_512 = _mm512_clmulepi64_epi128(z0_512, const_factor_512, 0x10);
        // shuffle to X0:X1
        z0_512 = _mm512_shuffle_epi32(z0_512, _MM_PERM_BADC);
        // B1:B0 = X0 + A1: X1 + A0
        z1_512 = _mm512_xor_epi64(z1_512, z0_512);
        // C1:C0 = B0 *  0xc200000000000000
        z0_512 = _mm512_clmulepi64_epi128(z1_512, const_factor_512, 0x10);
        // shuffle to B0:B1
        z1_512 = _mm512_shuffle_epi32(z1_512, _MM_PERM_BADC);

        // D1:D0 = B0 + C1: B1 + C0
        z0_512 = _mm512_xor_epi64(z1_512, z0_512);
        // D1 + X3: D0 + X2
        res = _mm512_xor_epi64(z2_512, z0_512);
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

    static inline void get_aggregated_karatsuba_components_first(
        __m512i&       H1,
        __m512i&       H2,
        __m512i&       H3,
        __m512i&       H4,
        __m512i&       a,
        __m512i&       b,
        __m512i&       c,
        __m512i&       d,
        const __m512i& reverse_mask_512,
        __m512i&       z0_512, // out
        __m512i&       z1_512, // out
        __m512i&       z2_512, // out
        const __m512i& res)
    {
        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        amd512xorLast128bit(a, res);

        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);

        computeKaratsubaComponents(H4, a, z0_512, z1_512, z2_512);

        // b
        computeKaratsubaComponentsAccumulate(H3, b, z0_512, z1_512, z2_512);

        // c
        computeKaratsubaComponentsAccumulate(H2, c, z0_512, z1_512, z2_512);

        // d
        computeKaratsubaComponentsAccumulate(H1, d, z0_512, z1_512, z2_512);
    }

    static inline void get_aggregated_karatsuba_components_last(
        const __m512i& H1,
        const __m512i& H2,
        const __m512i& H3,
        const __m512i& H4,
        __m512i        a,
        __m512i        b,
        __m512i        c,
        __m512i        d,
        const __m512i& reverse_mask_512,
        __m512i&       z0_512, // out
        __m512i&       z1_512, // out
        __m512i&       z2_512  // out
    )
    {

        // reverseInput
        a = _mm512_shuffle_epi8(a, reverse_mask_512);
        b = _mm512_shuffle_epi8(b, reverse_mask_512);
        c = _mm512_shuffle_epi8(c, reverse_mask_512);
        d = _mm512_shuffle_epi8(d, reverse_mask_512);

        computeKaratsubaComponentsAccumulate(H4, a, z0_512, z1_512, z2_512);

        // b
        computeKaratsubaComponentsAccumulate(H3, b, z0_512, z1_512, z2_512);

        // c
        computeKaratsubaComponentsAccumulate(H2, c, z0_512, z1_512, z2_512);

        // d
        computeKaratsubaComponentsAccumulate(H1, d, z0_512, z1_512, z2_512);
    }

    static inline void getGhash(__m512i&       z0_512,
                                __m512i&       z1_512,
                                __m512i&       z2_512,
                                __m512i&       res,
                                const __m256i& const_factor_256)
    {

        __m128i z0 = amd512_horizontal_sum128(z0_512);
        __m128i z1 = amd512_horizontal_sum128(z1_512);
        __m128i z2 = amd512_horizontal_sum128(z2_512);

        __m256i res_256;
        computeKaratsubaMul(z0, z1, z2, res_256);
        montgomeryReduction(res_256, res, const_factor_256);
    }

}} // namespace alcp::cipher::vaes512
