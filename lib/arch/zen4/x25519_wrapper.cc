/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include <immintrin.h>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

#include "ec/ecdh.hh"
#include "ec/ed_25519_table.hh"
#include "utils/copy.hh"
#include "x25519_radix51bit.hh"
#include "x25519_radix64bit.hh"

namespace alcp::ec {

using namespace radix64bit;
/*
 * Current version supports radix51bit arithmetic kernels.
 * when radix64bit support is added, its sufficient to change the namespace. */

static inline void
ConditionalSwap(__m512i& a_512, __m512i& b_512, const __m512i swap_512)
{
    __m512i temp_512;

    temp_512 = _mm512_xor_epi64(a_512, b_512);
    temp_512 = _mm512_and_epi64(swap_512, temp_512);
    a_512    = _mm512_xor_epi64(a_512, temp_512);
    b_512    = _mm512_xor_epi64(b_512, temp_512);
}

/* Note: wrapper is with avx512 registers, when all arithmetic kernels are
 * added to avx512 typecast to Uint64* will be avoided. */

/* Compute Inverse of Z:
 * Inverse(z) = z ^ (p-2) mod p
 * p          = 2^255 - 19
 * p - 2      = 2^255 - 21
 * 2^255 - 21 = 2^5 * (2^250-1) + 11
 */

static inline void
InverseX25519(Uint64 out[4], const Uint64 in[4])
{

    Uint64 a[4], b[4], c[4], d[4];

    // square and Multiply algorithm to compute z ^ (2^5 * (2^250-1) + 11)

    SquareX25519Count(a, in, 1); // a = z^2
    SquareX25519Count(d, a, 2);  // d = z^8
    MulX25519(b, d, in);         // b = z^8*z     = z^9
    MulX25519(a, b, a);          // a = z^9*z^2   = z^11
    SquareX25519Count(d, a, 1);  // d = sqr(z^11) = z^22

    /*
     * b  = z^22 * z^9
     *    = z^31 = z ^(32-1)
     *    = z^ (2^5 - 1)
     */
    MulX25519(b, d, b);

    /*
     * d = sqr5times(z^ (2^5 - 1))
     *   = z ^ (2^10 - 2^5)
     */
    SquareX25519Count(d, b, 5);

    /*
     * b = z ^ (2^10 - 2^5) * z^ (2^5 - 1)
     *   = z ^ (2^10 - 2^5 + 2^5 - 1)
     *   = z ^ (2 ^10 - 1 )
     *   = z ^ (2 ^10 - 2^0 )
     */
    MulX25519(b, d, b);

    /*
     * d = sqr10times(  z ^ (2^10 - 2^5) )
     *   = z ^ (2^20 - 2^10)
     */
    SquareX25519Count(d, b, 10);

    /*
     * c = z ^ (2^20 - 2^10) *  z ^ (2 ^10 - 2^0 )
     *   = z ^ (2^20 - 2^0)
     */
    MulX25519(c, d, b);

    /*
     *  c = sqr20times( z ^ (2^20 - 2^10) )
     *    = z ^ (2^40 - 2^20)
     */
    SquareX25519Count(d, c, 20);
    MulX25519(d, d, c);            /* d = z ^ (2^40 - 2^0)   */
    SquareX25519Count(d, d, 10);   /* d = z ^ (2^50 - 2^10)  */
    MulX25519(b, d, b);            /* b = z ^ (2^50 - 2^0)   */
    SquareX25519Count(d, b, 50);   /* d = z ^ (2^100 - 2^50) */
    MulX25519(c, d, b);            /* c = z ^ (2^100 - 2^0)  */
    SquareX25519Count(d, c, 100);  /* d = z ^ (2^200 - 2^100)*/
    MulX25519(d, d, c);            /* d = z ^ (2^200 - 2^0)  */
    SquareX25519Count(d, d, 50);   /* d = z ^ (2^250 - 2^50) */
    MulX25519(d, d, b);            /* d = z ^ (2^250 - 2^0)  */
    SquareX25519Count(d, d, 5);    /* d = z ^ (2^255 - 2^5)  */
    MulX25519((Uint64*)out, d, a); /* Inverse(z) = z ^ (2^255 - 21)   */
}

static void
MontCore(__m512i*      x2, // output x2
         __m512i*      z2, // output z2
         __m512i*      x3, // output x3
         __m512i*      z3, // output z3
         __m512i       a,  // input x
         __m512i       b,  // input z
         __m512i       c,  // input xp
         __m512i       d,  // input zp
         __m512i       basePoint512,
         const __m512i subConst_512)
{
    __m512i t1, t2, t3, t, a2, c2, m, n, p;

    const Uint64* p64BasePoint = (Uint64*)&basePoint512;

    SumX25519((Uint64*)&t1, (Uint64*)&a, (Uint64*)&b);
    SubX25519((Uint64*)&b, (Uint64*)&a, (Uint64*)&b);

    SumX25519((Uint64*)&t2, (Uint64*)&c, (Uint64*)&d);
    SubX25519((Uint64*)&d, (Uint64*)&c, (Uint64*)&d);

    // to do: parallel mul once r*19 is reducted to 52 bits
    MulX25519((Uint64*)&m, (Uint64*)&t2, (Uint64*)&b);
    MulX25519((Uint64*)&n, (Uint64*)&t1, (Uint64*)&d);

    SumX25519((Uint64*)&t3, (Uint64*)&m, (Uint64*)&n);
    SubX25519((Uint64*)&n, (Uint64*)&m, (Uint64*)&n);

    // to do, parallel square
    SquareX25519Count((Uint64*)x3, (Uint64*)&t3, 1);
    SquareX25519Count((Uint64*)&p, (Uint64*)&n, 1);
    SquareX25519Count((Uint64*)&a2, (Uint64*)&t1, 1);
    SquareX25519Count((Uint64*)&c2, (Uint64*)&b, 1);

    MulX25519((Uint64*)z3, (Uint64*)&p, p64BasePoint);

    MulX25519((Uint64*)x2, (Uint64*)&a2, (Uint64*)&c2);
    SubX25519((Uint64*)&c2, (Uint64*)&a2, (Uint64*)&c2);

    ScalarMulX25519((Uint64*)&t, (Uint64*)&c2);

    SumX25519((Uint64*)&t, (Uint64*)&t, (Uint64*)&a2);
    MulX25519((Uint64*)z2, (Uint64*)&c2, (Uint64*)&t);
}

static void
MontLadder(__m512i*      resultx_512,
           __m512i*      resultz_512,
           const Uint8*  pScalar,
           const __m512i basePoint512)
{
    __m512i a_512 = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, 1);
    __m512i b_512 = _mm512_set1_epi64(0);
    __m512i c_512 = b_512; // 0
    __m512i d_512 = a_512; // 1

    __m512i g_512 = b_512; // 0
    __m512i h_512 = a_512; // 1
    __m512i e_512 = b_512; // 0
    __m512i f_512 = a_512; // 1

    unsigned i, j;
    c_512 = basePoint512;

    static const Uint64 constA = (((Uint64)1) << 54) - 152;
    static const Uint64 constB = (((Uint64)1) << 54) - 8;

    __m512i subConst_512 =
        _mm512_set_epi64(0, 0, 0, constB, constB, constB, constB, constA);

    for (i = 0; i < 32; ++i) {
        Uint8 byte = pScalar[31 - i];
        for (j = 0; j < 8; ++j) {
            const Uint64 bit = byte >> 7;

            const __m512i swap_512 = _mm512_set1_epi64(-bit);

            ConditionalSwap(a_512, c_512, swap_512);
            ConditionalSwap(b_512, d_512, swap_512);

            MontCore(&e_512,
                     &f_512,
                     &g_512,
                     &h_512,
                     a_512,
                     b_512,
                     c_512,
                     d_512,
                     basePoint512,
                     subConst_512);

            ConditionalSwap(e_512, g_512, swap_512);
            ConditionalSwap(f_512, h_512, swap_512);

            __m512i t_512 = a_512;
            a_512         = e_512;
            e_512         = t_512;

            // swap d,h
            t_512 = b_512;
            b_512 = f_512;
            f_512 = t_512;

            // swap a,e
            t_512 = c_512;
            c_512 = g_512;
            g_512 = t_512;

            // swap b,f
            t_512 = d_512;
            d_512 = h_512;
            h_512 = t_512;

            byte <<= 1;
        }
    }
    *resultx_512 = a_512;
    *resultz_512 = b_512;
}

void
alcpScalarMulX25519(Uint8*       mypublic,
                    const Uint8* scalar,
                    const Uint8* basepoint)
{
    __m512i bp_512, x_512, z_512, zInverse_512, out_512;
    BytesToRadix((Uint64*)&bp_512, (Uint64*)basepoint);

    Uint8 clippedScalar[32];

    alcp::utils::CopyBytes(clippedScalar, scalar, 32);

    // clipping first and last byte.
    clippedScalar[0] &= 248;
    clippedScalar[31] = (clippedScalar[31] & 127) | 64;

    MontLadder(&x_512, &z_512, clippedScalar, bp_512);

    InverseX25519((Uint64*)&zInverse_512, (Uint64*)&z_512);
    MulX25519((Uint64*)&z_512, (Uint64*)&x_512, (Uint64*)&zInverse_512);

    RadixToBytes((Uint64*)&out_512, (Uint64*)&z_512);
    alcp::utils::CopyBytes(mypublic, (const void*)&out_512, 32);
}

static inline void
alcp_load_conditional(__m256i& a_256, __m256i& b_256, Uint64 iswap)
{
    const __m256i swap_256 = _mm256_set1_epi64x(-iswap);
    __m256i       x_256;

    x_256 = _mm256_xor_epi64(a_256, b_256);
    x_256 = _mm256_and_si256(swap_256, x_256);
    a_256 = _mm256_xor_epi64(a_256, x_256);
}

void
AlcpLoadPrecomputed(__m256i&     x_256,
                    __m256i&     y_256,
                    __m256i&     z_256,
                    const Uint64 point[3][4],
                    Uint64       iswap)
{

    __m256i pt_x_256 =
        _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[0]));
    __m256i pt_y_256 =
        _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[1]));
    __m256i pt_z_256 =
        _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(point[2]));

    alcp_load_conditional(x_256, pt_x_256, iswap);
    alcp_load_conditional(y_256, pt_y_256, iswap);
    alcp_load_conditional(z_256, pt_z_256, iswap);
}

static inline void
FetchIntermediateMul(Int8 i, Int8 j, PrecomputedPoint& point)
{

    __m256i negative_point_x_256, negative_point_y_256, negative_point_z_256;

    __m256i x_256 = { 1, 0, 0, 0 };
    __m256i y_256 = { 1, 0, 0, 0 };
    __m256i z_256 = { 0 };

    const int abs_j = abs(j);

    UNROLL_16
    for (Uint8 z = 0; z < 16; z++) {
        AlcpLoadPrecomputed(
            x_256, y_256, z_256, &cPrecomputedTable[i][z][0], abs_j == z + 1);
    }

    negative_point_x_256 = y_256;
    negative_point_y_256 = x_256;

    Uint64 temp[4] = { 0 };
    SubX25519((Uint64*)&negative_point_z_256, temp, (Uint64*)&z_256);

    Uint64 iswap = ((Uint8)j >> 7);
    alcp_load_conditional(x_256, negative_point_x_256, iswap);
    alcp_load_conditional(y_256, negative_point_y_256, iswap);
    alcp_load_conditional(z_256, negative_point_z_256, iswap);

    _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_x), x_256);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_y), y_256);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(point.m_z), z_256);
}

static inline void
PointAddInEdward(AlcpEcPointExtended& result, const PrecomputedPoint& point)
{
    // a ← (y1 − x1) · (y2 − x2), b ← (y1 + x1) · (y2 + x2), c ← k t1 · t2,
    // k <-2dconst, d ← 2z1 · z2, e ← b − a, f ← d − c, g ← d + c, h ← b + a, x3
    // ← e · f, y3 ← g · h, t3 ← e · h, z3 ← f · g

    Uint64 a[4], b[4], c[4], d[4], e[4], f[4], g[4];
    SubX25519(a, result.y, result.x);
    MulX25519(a, a, point.m_y);
    SumX25519(b, result.y, result.x);
    MulX25519(b, b, point.m_x);
    MulX25519(c, result.t, point.m_z);
    SumX25519(d, result.z, result.z);
    SubX25519(e, b, a);
    SumX25519(b, b, a);

    SubX25519(f, d, c);
    SumX25519(g, d, c);

    MulX25519(result.x, e, f);
    MulX25519(result.y, g, b);
    MulX25519(result.z, f, g);
    MulX25519(result.t, e, b);
}

static inline void
CovertEdwardToMont(const AlcpEcPointExtended& result, Uint8* pPublicKey)
{
    Uint64 numerator[4], denominator[4], inverse_denominator[4];

    SumX25519(numerator, result.z, result.y);
    SubX25519(denominator, result.z, result.y);
    InverseX25519(inverse_denominator, denominator);
    MulX25519(numerator, numerator, inverse_denominator);
    RadixToBytes(reinterpret_cast<Uint64*>(pPublicKey), numerator);
}

void
AlcpScalarPubX25519(Int8* privKeyRadix32, Uint8* pPublicKey)
{

    AlcpEcPointExtended result;

    PrecomputedPoint point;
    UNROLL_52
    for (int i = 51; i >= 0; i--) {
        FetchIntermediateMul(i, privKeyRadix32[i], point);
        PointAddInEdward(result, point);
    }
    CovertEdwardToMont(result, pPublicKey);
}

#if 0
namespace experimentalParallel {
static void
MontCore(__m512i*      x2,
         __m512i*      z2,
         __m512i*      x3,
         __m512i*      z3,
         __m512i       a, // x
         __m512i       b, // z
         __m512i       c, // xp
         __m512i       d, // zp
         __m512i       basePoint512,
         const __m512i subConst_512)
{
    __m512i       t, a2, c2, m, n, p;
    const Uint64* p64BasePoint = (Uint64*)&basePoint512;

    // a = a + b
    // b = a - b
    // c = c + d
    // d = c - d
    AddSubX25519(a, b, c, d, subConst_512);

    MulX25519((Uint64*)&m, (Uint64*)&c, (Uint64*)&b);
    MulX25519((Uint64*)&n, (Uint64*)&a, (Uint64*)&d);

    // m = m + n
    // n = m - n
    AddSubX25519(m, n, subConst_512);

    SquareX25519Count((Uint64*)x3, (Uint64*)&m, 1);
    SquareX25519Count((Uint64*)&p, (Uint64*)&n, 1);
    SquareX25519Count((Uint64*)&a2, (Uint64*)&a, 1);
    SquareX25519Count((Uint64*)&c2, (Uint64*)&b, 1);

    MulX25519((Uint64*)z3, (Uint64*)&p, p64BasePoint);
    MulX25519((Uint64*)x2, (Uint64*)&a2, (Uint64*)&c2);

    // c2 = a2 - c2
    SubX25519(c2, a2, c2, subConst_512);

    ScalarMulX25519((Uint64*)&t, (Uint64*)&c2, 121665);

    // t = t + a2
    AddX25519(t, t, a2);
    MulX25519((Uint64*)z2, (Uint64*)&c2, (Uint64*)&t);
}
} // namespace experimentalParallel
#endif

} // namespace alcp::ec