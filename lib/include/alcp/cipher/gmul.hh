/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
 * Galois Multiplicaiton we use below algorithms from "Intel carry-less
 * multiplication instruction in gcm mode"
 *    1. Aggregated Reduction and
 *    2. ModuloReduction algorithms
 * https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
 */

#define SWIZZLE(a, b, c, d) (((a) << 0) | ((b) << 2) | ((c) << 4) | ((d) << 6))

namespace alcp::cipher { namespace aesni {

    static inline void computeKaratsuba_Z0_Z2(__m128i  H1,
                                              __m128i  H2,
                                              __m128i  H3,
                                              __m128i  H4,
                                              __m128i  a,
                                              __m128i  b,
                                              __m128i  c,
                                              __m128i  d,
                                              __m128i& z0,
                                              __m128i& z2)
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
         * z0 component of below equation:
         * [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] */
        z0 = _mm_xor_si128(z0_a, z0_b);
        z0 = _mm_xor_si128(z0, z0_c);
        z0 = _mm_xor_si128(z0, z0_d);

        /* compute: z2 = x1y1
         * z2 component of below equation:
         * [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] */
        z2 = _mm_xor_si128(z2_a, z2_b);
        z2 = _mm_xor_si128(z2, z2_c);
        z2 = _mm_xor_si128(z2, z2_d);
    }

    static inline void carrylessMul(__m128i  H1,
                                    __m128i  H2,
                                    __m128i  H3,
                                    __m128i  H4,
                                    __m128i  a,
                                    __m128i  b,
                                    __m128i  c,
                                    __m128i  d,
                                    __m128i& high,
                                    __m128i& low)
    {
        /*
         *    Karatsuba algorithm to multiply two elements x,y
         *    Elements x,y are split as two equal 64 bit elements each.
         *    x = x1:x0
         *    y = y1:y0
         *
         *    compute z2 and z0
         *    z0 = x0y0
         *    z2 = x1y1
         *
         *    Reduce two multiplications in z1 to one.
         *    original: z1 = x1y0 + x0y1
         *    Reduced : z1 = (x1+x0) (y1+y0) - z2 - z0
         *
         *    Aggregrated Reduction:
         *    [(Xi • H1) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] mod P
         */

        __m128i z0, z2;
        __m128i a0, a1, a2, a3, a4, a5, a6, a7;
        __m128i xt, yt;
        computeKaratsuba_Z0_Z2(H1, H2, H3, H4, a, b, c, d, z0, z2);

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

        low  = _mm_xor_si128(a1, z0);
        high = _mm_xor_si128(a0, z2);
    }

    /*
     * Bitreflection in galoisMultiplication is avoided by modifying the
     * hashKey to hashKey << 1 mod poly. Avoiding bitreflection on
     * galoisMultiplication improves performance of GHASH computation.
     *
     * Reference:
     * Vinodh Gopal et. al. Optimized Galois-Counter-Mode
     * Implementation on Intel® Architecture Processors. Intel White Paper,
     * August 2010.
     */

    /* 128 bit gMul with montogomery reduction */
    static inline void carrylessMul(__m128i  a,
                                    __m128i  b,
                                    __m128i& c,
                                    __m128i& d)
    {
        __m128i e, f;
        /* carryless multiplication of a1:a0 * b1:b0 */
        c = _mm_clmulepi64_si128(a, b, 0x00); // C1:C0 = a0*b0
        d = _mm_clmulepi64_si128(a, b, 0x11); // D1:D0 = a1*b1
        e = _mm_clmulepi64_si128(a, b, 0x10); // E1:E0 = a0*b1
        f = _mm_clmulepi64_si128(a, b, 0x01); // F1:F0 = a1*b0

        /*
         * compute D1  :  D0+E1+F1 : C1+E0+F0: C0
         */
        e = _mm_xor_si128(e, f);  // E1+F1 : E0+F0
        f = _mm_slli_si128(e, 8); // E0+F0:0
        e = _mm_srli_si128(e, 8); // 0:E1+F1

        /* d : c = D1 : D0+E1+F1 : C1+E0+F1 : C0 */
        c = _mm_xor_si128(c, f); // C1+(E0+F1):C0
        d = _mm_xor_si128(d, e); // D1:D0+(E1+F1)
    }

    inline void HashSubKeyLeftByOne(__m128i& hashSubkey)
    {
        __m128i res;
        /* Compute reflected hKey<<1 mod poly */
        __m128i a, b, c, d, cPoly;
        __m64   lo = _m_from_int64(0xC200000000000000);
        __m64   hi = _m_from_int64(0x1);
        b          = _mm_set_epi64(_m_from_int(0), _m_from_int(2));
        aesni::carrylessMul(hashSubkey, b, c, d); // hkey *2
        __m256i cd = _mm256_set_m128i(d, c);
        res        = _mm256_castsi256_si128(cd);

        a     = _mm_srai_epi32(hashSubkey, 31);
        a     = _mm_shuffle_epi32(a, 255); //_MM_PERM_DDDD
        cPoly = _mm_set_epi64(lo, hi);
        a     = _mm_and_si128(a, cPoly);

        hashSubkey = _mm_xor_si128(res, a);
    }

    /*
     * Modulo Reduction of 256bit to 128bit
     * Modulo reduction algorithm 4 (Montgomery Reduction) in
     *
     * "Shay Gueron. AES-GCM for Efficient Authenticated Encryption -
     * Ending the reign of HMAC-SHA-1?, Workshop on Real-World Cryptography,
     * 2013. https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf.
     */

    static inline void montgomeryReduction(__m128i        input128,
                                           __m128i        high128,
                                           __m128i&       result,
                                           const __m128i& const_factor_128)
    {
        constexpr int cSwizzle = SWIZZLE(2, 3, 0, 1);

        __m128i mul128;

        /**
         * Number of shuffles has been reduced compared "Fast reduction Modulo
         * algorithm". Instead of shuffling X1:X0 and B1:B0, A1:A0 is shuffled
         * once. Number shuffled reduced by half.
         */

        // A1:A0 = X0 * 0xc200000000000000
        mul128 = _mm_clmulepi64_si128(input128, const_factor_128, 0x10);
        // A0:A1
        mul128 = _mm_shuffle_epi32(mul128, cSwizzle);

        // B0:B1, result in shuffled order
        input128 = _mm_xor_si128(input128, mul128);

        // C1:C0 = B0 • 0xc200000000000000
        mul128 = _mm_clmulepi64_si128(input128, const_factor_128, 0x11);

        result = _mm_xor_si128(input128, mul128);
        result = _mm_xor_si128(high128, result);
    }

    static inline void gMulR(__m128i        H1,
                             __m128i        H2,
                             __m128i        H3,
                             __m128i        H4,
                             __m128i        a,
                             __m128i        b,
                             __m128i        c,
                             __m128i        d,
                             __m128i        reverse_mask_128,
                             __m128i&       res,
                             const __m128i& const_factor_128)
    {
        a = _mm_shuffle_epi8(a, reverse_mask_128);
        b = _mm_shuffle_epi8(b, reverse_mask_128);
        c = _mm_shuffle_epi8(c, reverse_mask_128);
        d = _mm_shuffle_epi8(d, reverse_mask_128);

        res = _mm_xor_si128(d, res);

        __m128i high, low;

        /*
         *    Instead of 4 moduloReduction, perform aggregated reduction as per
         *   below equation. Aggregrated Reduction:
         *    [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3) +
         *        (Xi - 3 + Yi - 4) • H4] mod P
         */

        /*
         *    A = [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3)
         *          + (Xi - 3 + Yi - 4)• H4]
         */

        carrylessMul(H1, H2, H3, H4, a, b, c, res, high, low);

        // A mod P
        montgomeryReduction(low, high, res, const_factor_128);
    }

    static inline void gMul(__m128i        H1,
                            __m128i        H2,
                            __m128i        H3,
                            __m128i        H4,
                            __m128i        a,
                            __m128i        b,
                            __m128i        c,
                            __m128i        d,
                            __m128i&       res,
                            const __m128i& const_factor_128)
    {
        __m128i high, low;

        /*
         *    Instead of 4 moduloReduction, perform aggregated reduction as per
         *   below equation. Aggregrated Reduction:
         *    [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3) +
         *        (Xi - 3 + Yi - 4) • H4] mod P
         */

        /*
         *   A = [(Xi • H1) + (Xi - 1 • H2) + (Xi - 2 • H3) +
         *       (Xi - 3 + Yi - 4) • H4]
         */
        carrylessMul(H1, H2, H3, H4, a, b, c, d, high, low);

        // A mod P
        montgomeryReduction(low, high, res, const_factor_128);
    }

    static inline void gMul(__m128i        a,
                            __m128i        b,
                            __m128i&       res,
                            const __m128i& const_factor_128)
    {
        __m128i c, d;
        carrylessMul(a, b, c, d);
        montgomeryReduction(c, d, res, const_factor_128);
    }

    static inline void gMulR(__m128i        a,
                             __m128i        b,
                             __m128i        reverse_mask_128,
                             __m128i&       res,
                             const __m128i& const_factor_128)
    {
        a   = _mm_shuffle_epi8(a, reverse_mask_128);
        res = _mm_xor_si128(a, res);

        __m128i c, d;
        carrylessMul(res, b, c, d);
        montgomeryReduction(c, d, res, const_factor_128);
    }

    static inline void computeKaratsubaMul(
        __m128i& z0_or_low, // input and output
        __m128i& z1,        // input
        __m128i& z2_or_high // input and output
    )
    {
        __m128i a1;

        /*
         * compute:    z1 = (x1+x0) (y1+y0) - z2 - z0
         *
         * inputParam: z1 = (x1+x0) (y1+y0) */

        // (x1+x0) (y1+y0) - zo -z2 = (x1+x0) (y1+y0) xor z0 xor z2
        z1 = _mm_xor_si128(z1, z0_or_low);
        z1 = _mm_xor_si128(z1, z2_or_high);

        a1 = _mm_slli_si128(z1, 8);
        z1 = _mm_srli_si128(z1, 8);

        z0_or_low  = _mm_xor_si128(z0_or_low, a1);
        z2_or_high = _mm_xor_si128(z2_or_high, z1);
    }

}} // namespace alcp::cipher::aesni