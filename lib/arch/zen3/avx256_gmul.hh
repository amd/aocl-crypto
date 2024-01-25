/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

namespace alcp::cipher { namespace vaes {

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

    /* Intermediate Ghash computation done stored in 256 bit */
    static inline void montgomeryReduction(__m256i       input,
                                           __m256i&      result,
                                           const __m256i const_factor)
    {
        __m256i       mul, high;
        constexpr int cSwizzle = SWIZZLE(2, 3, 0, 1);

        high = _mm256_permute4x64_epi64(input, cSwizzle); // move hi to low.

        // A1:A0
        mul = _mm256_clmulepi64_epi128(input, const_factor, 0x10);
        // A0:A1
        mul = _mm256_shuffle_epi32(mul, cSwizzle);

        // B0:B1
        input = _mm256_xor_si256(mul, input);

        mul = _mm256_clmulepi64_epi128(input, const_factor, 0x11);

        input = _mm256_xor_si256(mul, input);

        result = _mm256_xor_si256(high, input);
    }

    static inline __m128i amd256_horizontal_sum128(const __m256i& x)
    {
        __m128i a_128, b_128;

        a_128 = _mm256_extracti128_si256(x, 1);
        b_128 = _mm256_castsi256_si128(x);

        a_128 = _mm_xor_si128(a_128, b_128);

        return a_128;
    }

    static inline void amd256xorLast128bit(__m256i& a, const __m256i& b)
    {
        // a1:(a0 xor b0)
        __m128i hi, lo, blo;
        lo  = _mm256_castsi256_si128(a);
        blo = _mm256_castsi256_si128(b);
        lo  = _mm_xor_si128(blo, lo);
        hi  = _mm256_extracti128_si256(a, 1);

        a = _mm256_set_m128i(hi, lo);
    }

    static inline void computeKaratsuba_Z0_Z2(const __m256i& H,
                                              const __m256i& abcd,
                                              __m256i&       z0,
                                              __m256i&       z2)
    {
        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2)
        z0 = _mm256_clmulepi64_epi128(H, abcd, 0x00);

        // compute x1y1
        z2 = _mm256_clmulepi64_epi128(H, abcd, 0x11);
    }

    static inline void computeKaratsuba_Z1(const __m256i& H,
                                           const __m256i& abcd,
                                           __m256i&       z1)
    {
        __m256i H_high, abcd_high;
        H_high    = _mm256_bsrli_epi128(H, 8);
        abcd_high = _mm256_bsrli_epi128(abcd, 8);

        H_high    = _mm256_xor_si256(H_high, H);
        abcd_high = _mm256_xor_si256(abcd_high, abcd);

        z1 = _mm256_clmulepi64_epi128(H_high, abcd_high, 0x00);
    }

    /* Aggregated reduction method + Karatsuba algorithm */
    static inline void computeKaratsubaComponents(__m256i& H,    // input
                                                  __m256i& abcd, // input
                                                  __m256i& z0,   // output
                                                  __m256i& z1,   // output
                                                  __m256i& z2)   // output
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
        computeKaratsuba_Z0_Z2(H, abcd, z0, z2);

        /* To compute: z1 = (x1+x0) (y1+y0) - z2 - z0
         * compute (x1+x0) (y1+y0) part in below function */
        computeKaratsuba_Z1(H, abcd, z1);
    }

    /* Aggregated reduction method + Karatsuba algorithm */
    static inline void computeKaratsubaComponentsAccumulate(const __m256i& H,
                                                            const __m256i& a,
                                                            __m256i&       z0,
                                                            __m256i&       z1,
                                                            __m256i&       z2)
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
         *  [(Xi • H1) + (Xi-1 • H2)] modP
         *
         */

        __m256i t1, t2;

        // compute x0y0
        // (Xi • H1) :  (Xi-1 • H2)
        t1 = _mm256_clmulepi64_epi128(H, a, 0x00);

        // compute x1y1
        t2 = _mm256_clmulepi64_epi128(H, a, 0x11);

        // accumulate with verious z0
        z0 = _mm256_xor_si256(t1, z0);

        // accumulate with verious z2
        z2 = _mm256_xor_si256(t2, z2);

        // z1 compute: extract all x1 and y1
        t1 = _mm256_bsrli_epi128(H, 8); // high of H
        t2 = _mm256_bsrli_epi128(a, 8); // high of a

        // z1 compute: (x1+x0) and (y1+y0)
        t1 = _mm256_xor_si256(t1, H);
        t2 = _mm256_xor_si256(t2, a);

        t1 = _mm256_clmulepi64_epi128(t1, t2, 0x00);

        // accumulate with verious z1
        z1 = _mm256_xor_si256(t1, z1);
    }

    static inline void amd256_reverse256_xorLast128bit(
        __m256i& a, const __m256i& reverse_mask, __m256i res)
    {
        a = _mm256_shuffle_epi8(a, reverse_mask);
        amd256xorLast128bit(a, res);
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

    static inline void gMulR(__m256i        H,
                             __m256i        a,
                             const __m256i& reverse_mask,
                             __m256i&       res,
                             const __m256i  const_factor)
    {
        __m256i z0, z1, z2;
        __m128i z0_or_low, z1_128, z2_or_high;

        amd256_reverse256_xorLast128bit(a, reverse_mask, res);
        computeKaratsubaComponents(H, a, z0, z1, z2);

        /* compute: z0 = x0y0
         *        z0 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2)]
         *
         *  compute: z2 = x1y1
         *        z2 component of below equation:
         *        [(Xi • H1) + (Xi-1 • H2)]
         */
        z0_or_low  = amd256_horizontal_sum128(z0);
        z2_or_high = amd256_horizontal_sum128(z2);
        z1_128     = amd256_horizontal_sum128(z1);

        aesni::computeKaratsubaMul(z0_or_low, z1_128, z2_or_high);
        __m256i z2z0 = _mm256_set_m128i(z2_or_high, z0_or_low);
        montgomeryReduction(z2z0, res, const_factor);
    }

    static inline __m256i amd256_xor_all(__m256i x0,
                                         __m256i x1,
                                         __m256i x2,
                                         __m256i x3)
    {
        x0 = _mm256_xor_si256(x0, x1);
        x0 = _mm256_xor_si256(x0, x2);
        return _mm256_xor_si256(x0, x3);
    }

    static inline void get_aggregated_karatsuba_components_first(
        __m256i&       H1,
        __m256i&       H2,
        __m256i&       H3,
        __m256i&       H4,
        __m256i&       a,
        __m256i&       b,
        __m256i&       c,
        __m256i&       d,
        const __m256i& reverse_mask,
        __m256i&       z0, // out
        __m256i&       z1, // out
        __m256i&       z2, // out
        const __m256i& res)
    {
        // reverseInput
        a = _mm256_shuffle_epi8(a, reverse_mask);
        amd256xorLast128bit(a, res);

        b = _mm256_shuffle_epi8(b, reverse_mask);
        c = _mm256_shuffle_epi8(c, reverse_mask);
        d = _mm256_shuffle_epi8(d, reverse_mask);

        computeKaratsubaComponents(H4, a, z0, z1, z2);

        // b
        computeKaratsubaComponentsAccumulate(H3, b, z0, z1, z2);

        // c
        computeKaratsubaComponentsAccumulate(H2, c, z0, z1, z2);

        // d
        computeKaratsubaComponentsAccumulate(H1, d, z0, z1, z2);
    }

    static inline void get_aggregated_karatsuba_components_last(
        __m256i&       H1,
        __m256i&       H2,
        __m256i&       H3,
        __m256i&       H4,
        __m256i        a,
        __m256i        b,
        __m256i        c,
        __m256i        d,
        const __m256i& reverse_mask,
        __m256i&       z0, // out
        __m256i&       z1, // out
        __m256i&       z2  // out
    )
    {

        // reverseInput
        a = _mm256_shuffle_epi8(a, reverse_mask);
        b = _mm256_shuffle_epi8(b, reverse_mask);
        c = _mm256_shuffle_epi8(c, reverse_mask);
        d = _mm256_shuffle_epi8(d, reverse_mask);

        computeKaratsubaComponentsAccumulate(H4, a, z0, z1, z2);

        // b
        computeKaratsubaComponentsAccumulate(H3, b, z0, z1, z2);

        // c
        computeKaratsubaComponentsAccumulate(H2, c, z0, z1, z2);

        // d
        computeKaratsubaComponentsAccumulate(H1, d, z0, z1, z2);
    }

    static inline void getGhash(__m256i&      z0_256,
                                __m256i&      z1_256,
                                __m256i&      z2_256,
                                __m256i&      res,
                                const __m256i const_factor_256)
    {

        __m128i z0 = amd256_horizontal_sum128(z0_256);
        __m128i z1 = amd256_horizontal_sum128(z1_256);
        __m128i z2 = amd256_horizontal_sum128(z2_256);

        __m256i res_256;
        computeKaratsubaMul(z0, z1, z2, res_256);
        montgomeryReduction(res_256, res, const_factor_256);
    }

}} // namespace alcp::cipher::vaes
