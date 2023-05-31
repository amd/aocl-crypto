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

#pragma once

#include <immintrin.h>

#include "alcp/types.hh"

typedef unsigned Uint128 __attribute__((mode(TI)));
#define ALCP_FORCE_INLINE __attribute__((always_inline))
#define SWIZZLE_512(a, b, c, d)                                                \
    (((d) << 0) | ((c) << 2) | ((b) << 4) | ((a) << 6))

namespace alcp::ec::radix51bit {
#define RADIX_51 51

//(1 << RADIX_51) - 1
static constexpr Uint64 MaskRadix51bit = 0x7ffffffffffff;

static inline Uint64 ALCP_FORCE_INLINE
ApplyRadix51bitMask(Uint64 a)
{
    return (a & MaskRadix51bit);
}

static inline Uint64 ALCP_FORCE_INLINE
GetRadix51bitCarry(Uint64 a)
{
    return (a >> RADIX_51);
}

static inline Uint64 ALCP_FORCE_INLINE
GetRadix51bitCarry(Uint128 a)
{
    return ((Uint64)(a >> RADIX_51));
}

static inline Uint64 ALCP_FORCE_INLINE
ApplyRadix51bitMask(Uint128 a)
{
    return ((Uint64)a & MaskRadix51bit);
}

static inline void
BytesToRadix(__m512i* output_512, const Uint8* in)
{
    __m128i* pOutput_128 = (__m128i*)output_512;

    // mask to be moved to init time.
    Int64   mask    = MaskRadix51bit;
    __m128i maskAND = _mm_set1_epi64((__m64)mask);

    __m128i a0 = _mm_loadu_si64(in);
    __m128i a1 = _mm_loadu_si64(in + 6);

    __m128i a2 = _mm_loadu_si64(in + 12);
    __m128i a3 = _mm_loadu_si64(in + 19);
    __m128i a4 = _mm_loadl_epi64((__m128i*)(in + 24));

    a1 = _mm_srli_epi64(a1, 3);
    a2 = _mm_srli_epi64(a2, 6);
    a3 = _mm_srli_epi64(a3, 1);
    a4 = _mm_srli_epi64(a4, 12);

    a0 = _mm_unpacklo_epi64(a0, a1);
    a2 = _mm_unpacklo_epi64(a2, a3);

    a0 = _mm_and_si128(a0, maskAND);
    a2 = _mm_and_si128(a2, maskAND);
    a4 = _mm_and_si128(a4, maskAND);

    // todo: pack it in zmm register instead of store operation.
    _mm_store_epi64(pOutput_128, a0);
    _mm_store_epi64(pOutput_128 + 1, a2);
    _mm_store_epi64(pOutput_128 + 2, a4);
}

static inline void
RadixToBytes(Uint8* output, const Uint64* a)
{
    Uint64* out = (Uint64*)output;
    Uint64  a0  = a[0];
    Uint64  a1  = a[1];
    Uint64  a2  = a[2];
    Uint64  a3  = a[3];
    Uint64  a4  = a[4];
    Uint64  r;

    r = GetRadix51bitCarry(a0 + 19);
    r = GetRadix51bitCarry(a1 + r);
    r = GetRadix51bitCarry(a2 + r);
    r = GetRadix51bitCarry(a3 + r);
    r = GetRadix51bitCarry(a4 + r);

    // reduce
    a0 += 19 * r;
    a1 += GetRadix51bitCarry(a0);
    a0 = ApplyRadix51bitMask(a0);
    a2 += GetRadix51bitCarry(a1);
    a1 = ApplyRadix51bitMask(a1);
    a3 += GetRadix51bitCarry(a2);
    a2 = ApplyRadix51bitMask(a2);
    a4 += GetRadix51bitCarry(a3);
    a3 = ApplyRadix51bitMask(a3);
    a4 = ApplyRadix51bitMask(a4);

    out[0] = a0 | (a1 << 51);
    out[1] = (a1 >> 13) | (a2 << 38);
    out[2] = (a2 >> 26) | (a3 << 25);
    out[3] = (a3 >> 39) | (a4 << 12);
}

/* Add two inputs and reduce to radix 51 format
 * Reduction helps in parallelizing mul and square
 */
inline void
SumX25519(Uint64* c, const Uint64* a, const Uint64* b)
{
    Uint64 s;
    s    = a[0] + b[0];
    c[0] = ApplyRadix51bitMask(s);

    s    = a[1] + b[1] + GetRadix51bitCarry(s);
    c[1] = ApplyRadix51bitMask(s);

    s    = a[2] + b[2] + GetRadix51bitCarry(s);
    c[2] = ApplyRadix51bitMask(s);

    s    = a[3] + b[3] + GetRadix51bitCarry(s);
    c[3] = ApplyRadix51bitMask(s);

    s    = a[4] + b[4] + GetRadix51bitCarry(s);
    c[4] = ApplyRadix51bitMask(s);

    c[0] += GetRadix51bitCarry(s) * 19;
}

/* sub two inputs and reduce to radix 51 format
 * Reduction helps in parallelizing mul and square
 */
inline void
SubX25519(Uint64* c, const Uint64* a, const Uint64* b)
{
    Uint128 t0, t1, t2, t3, t4;
    Uint64  c0, c1, c2, c3, c4;

    t0 = (a[0] + 0xfffffffffffda) - b[0];
    t1 = (a[1] + 0xffffffffffffe) - b[1];
    t2 = (a[2] + 0xffffffffffffe) - b[2];
    t3 = (a[3] + 0xffffffffffffe) - b[3];
    t4 = (a[4] + 0xffffffffffffe) - b[4];

    c0 = ApplyRadix51bitMask(t0);
    t1 += GetRadix51bitCarry(t0);

    c1 = ApplyRadix51bitMask(t1);
    t2 += GetRadix51bitCarry(t1);

    c2 = ApplyRadix51bitMask(t2);
    t3 += GetRadix51bitCarry(t2);

    c3 = ApplyRadix51bitMask(t3);
    t4 += GetRadix51bitCarry(t3);

    c4 = ApplyRadix51bitMask(t4);

    c0 += (GetRadix51bitCarry(t4) * 19);
    c1 += GetRadix51bitCarry(c0);
    c0 = ApplyRadix51bitMask(c0);

    c2 += GetRadix51bitCarry(c1);
    c1 = ApplyRadix51bitMask(c1);

    c[0] = c0;
    c[1] = c1;
    c[2] = c2;
    c[3] = c3;
    c[4] = c4;
}

/*
static inline void
SumX25519_radix51(__m512i* c, __m512i a, __m512i b)
{
    __m512i sum, mask, carry;
    sum = _mm512_add_epi64(a, b);

    mask  = _mm512_set1_epi64(MaskRadix51bit);
    carry = _mm512_srai_epi64(sum, RADIX_51);

    sum = _mm512_and_epi64(mask, carry);

    *c = sum;
}*/

/* vectorized add and sub arithmetic operations without reduction
 *
 * These arithmetic operations cant be used if mul and sqr operations are
 * parallized with avx512, due to overflow above 51 bit.
 */
static inline void
AddSubX25519(__m512i&      a, //
             __m512i&      b,
             const __m512i subConst_512)
{
    // add
    __m512i tempadd = _mm512_add_epi64(a, b);

    // sub
    a = _mm512_add_epi64(a, subConst_512);
    b = _mm512_sub_epi64(a, b); // sub result stored
    a = tempadd;                // add result stored
}

static inline void
AddSubX25519(__m512i&      a, // a = a + b
             __m512i&      b, // b = a - b
             __m512i&      c, // c = c + d
             __m512i&      d, // d = c - d
             const __m512i subConst_512)
{
    __m512i temp1 = _mm512_add_epi64(a, b);
    __m512i temp3 = _mm512_add_epi64(c, d);

    a = _mm512_add_epi64(a, subConst_512);
    c = _mm512_add_epi64(c, subConst_512);

    b = _mm512_sub_epi64(a, b);
    d = _mm512_sub_epi64(c, d);

    a = temp1;
    c = temp3;
}

static inline void
AddX25519(__m512i& output, __m512i a, __m512i b)
{
    output = _mm512_add_epi64(a, b);
}

static inline void
SubX25519(__m512i& out, const __m512i a, const __m512i b, const __m512i add_512)
{
    __m512i temp = _mm512_add_epi64(a, add_512);
    out          = _mm512_sub_epi64(temp, b);
}

inline void
Add512(__m512i& a, __m512i b)
{
    // Parallel Addition
    __mmask16 carry, maxFlag;

    const __m512i MAX_UINT64 = _mm512_set1_epi64(0xffffffffffffffff);
    __m512i       sum        = _mm512_add_epi64(a, b);

    // check carry and shift left by 1
    carry   = (_mm512_cmplt_epu64_mask(sum, a) << 1);
    maxFlag = _mm512_cmpeq_epi64_mask(sum, MAX_UINT64);

    carry += maxFlag;
    maxFlag = _mm512_kxor(maxFlag, carry);

    a = _mm512_mask_sub_epi64(sum, maxFlag, sum, MAX_UINT64);
}

inline void
CombineLowHigh52bits(__m512i& low, __m512i high)
{
    __m512i h1;
    /* re-arrange higher half of each 128 bits */
    h1   = _mm512_shuffle_epi32(high, (_MM_PERM_ENUM)SWIZZLE_512(1, 0, 3, 3));
    high = _mm512_slli_epi64(high, 52);
    h1   = _mm512_srli_epi64(h1, (64 - 52));
    high = _mm512_add_epi64(high, h1);
    /* combine lower 64 bits and higher 64 bits */
    Add512(low, high);
}

inline void
Mul512LowHigh(__m512i& lo_512,
              __m512i& hi_512,
              __m512i  zmm_zero,
              __m512i  a,
              __m512i  b,
              int      print)
{
    lo_512 = hi_512 = _mm512_setzero_si512();
    lo_512          = _mm512_madd52lo_epu64(zmm_zero, a, b);
    hi_512          = _mm512_madd52hi_epu64(zmm_zero, a, b);
    // CombineLowHigh52bits(lo_512, hi_512);
}

inline void
MulX25519(Uint64* c, const Uint64* b, const Uint64* a)
{
    Uint128 t0, t1, t2, t3, t4;
    Uint64  r0, r1, r2, r3, r4, s0, s1, s2, s3, s4;

    r0 = a[0];
    r1 = a[1];
    r2 = a[2];
    r3 = a[3];
    r4 = a[4];

    s0 = b[0];
    s1 = b[1];
    s2 = b[2];
    s3 = b[3];
    s4 = b[4];

    __m512i zmm_zero;
    __m512i l0, h0;
    zmm_zero = _mm512_setzero_si512();

    __m512i sx10, sx11, sx12, sx13, sx14;
    __m512i l1, l2, l3, l4, h1, h2, h3, h4;
    __m512i r0_broadcast, r1_broadcast, r2_broadcast, r3_broadcast,
        r4_broadcast;

    // to do: set only sx10 and rest generate only with register level
    // manipulation.
    sx10 = _mm512_setr_epi64(s1, 0, s2, 0, s3, 0, s4, 0);
    sx11 = _mm512_setr_epi64(s0, 0, s1, 0, s2, 0, s3, 0);
    sx12 = _mm512_setr_epi64(0, 0, s0, 0, s1, 0, s2, 0);
    sx13 = _mm512_setr_epi64(0, 0, 0, 0, s0, 0, s1, 0);
    sx14 = _mm512_setr_epi64(0, 0, 0, 0, 0, 0, s0, 0);

    r0_broadcast = _mm512_setr_epi64(r0, 0, r0, 0, r0, 0, r0, 0);
    r1_broadcast = _mm512_setr_epi64(r1, 0, r1, 0, r1, 0, r1, 0);
    r2_broadcast = _mm512_setr_epi64(0, 0, r2, 0, r2, 0, r2, 0);
    r3_broadcast = _mm512_setr_epi64(0, 0, 0, 0, r3, 0, r3, 0);
    r4_broadcast = _mm512_setr_epi64(0, 0, 0, 0, 0, 0, r4, 0);

    Mul512LowHigh(l0, h0, zmm_zero, sx10, r0_broadcast, 1);
    Mul512LowHigh(l1, h1, zmm_zero, sx11, r1_broadcast, 0);
    Mul512LowHigh(l2, h2, zmm_zero, sx12, r2_broadcast, 0);
    Mul512LowHigh(l3, h3, zmm_zero, sx13, r3_broadcast, 0);
    Mul512LowHigh(l4, h4, zmm_zero, sx14, r4_broadcast, 0);

    l0 = _mm512_add_epi64(l0, l1);
    l0 = _mm512_add_epi64(l0, l2);
    l0 = _mm512_add_epi64(l0, l3);
    l0 = _mm512_add_epi64(l0, l4);

    h0 = _mm512_add_epi64(h0, h1);
    h0 = _mm512_add_epi64(h0, h2);
    h0 = _mm512_add_epi64(h0, h3);
    h0 = _mm512_add_epi64(h0, h4);

    CombineLowHigh52bits(l0, h0);

    t1 = (Uint128)_mm512_extracti64x2_epi64(l0, 0);
    t2 = (Uint128)_mm512_extracti64x2_epi64(l0, 1);
    t3 = (Uint128)_mm512_extracti64x2_epi64(l0, 2);
    t4 = (Uint128)_mm512_extracti64x2_epi64(l0, 3);

    t0 = ((Uint128)r0) * s0;

    r1 *= 19;
    r2 *= 19;
    r3 *= 19;
    r4 *= 19;

    t0 += ((Uint128)r4) * s1;
    t0 += ((Uint128)r3) * s2;
    t0 += ((Uint128)r2) * s3;
    t0 += ((Uint128)r1) * s4;

    t1 += ((Uint128)r4) * s2;
    t1 += ((Uint128)r3) * s3;
    t1 += ((Uint128)r2) * s4;

    t2 += ((Uint128)r4) * s3;
    t2 += ((Uint128)r3) * s4;

    t3 += ((Uint128)r4) * s4;

    r0 = ApplyRadix51bitMask(t0);
    t1 += GetRadix51bitCarry(t0);
    r1 = ApplyRadix51bitMask(t1);
    t2 += GetRadix51bitCarry(t1);
    r2 = ApplyRadix51bitMask(t2);
    t3 += GetRadix51bitCarry(t2);
    r3 = ApplyRadix51bitMask(t3);
    t4 += GetRadix51bitCarry(t3);
    r4 = ApplyRadix51bitMask(t4);

    r0 += (GetRadix51bitCarry(t4)) * 19;
    r1 += GetRadix51bitCarry(r0);
    r0 = ApplyRadix51bitMask(r0);
    r2 += GetRadix51bitCarry(r1);
    r1 = ApplyRadix51bitMask(r1);

    c[0] = r0;
    c[1] = r1;
    c[2] = r2;
    c[3] = r3;
    c[4] = r4;
}

Uint128 inline Mul128(Uint128 x, Uint64 scalar)
{
    return (x * scalar);
}

void inline ScalarMulX25519(Uint64* output, const Uint64* in)
{
    Uint128 a;

    const Uint64 scalar = 121665;
    a                   = Mul128(in[0], scalar);
    output[0]           = ApplyRadix51bitMask(a);

    a         = Mul128(in[1], scalar) + GetRadix51bitCarry(a);
    output[1] = ApplyRadix51bitMask(a);

    a         = Mul128(in[2], scalar) + GetRadix51bitCarry(a);
    output[2] = ApplyRadix51bitMask(a);

    a         = Mul128(in[3], scalar) + GetRadix51bitCarry(a);
    output[3] = ApplyRadix51bitMask(a);

    a         = Mul128(in[4], scalar) + GetRadix51bitCarry(a);
    output[4] = ApplyRadix51bitMask(a);

    output[0] += GetRadix51bitCarry(a) * 19;
}

inline void
SquareX25519Count(Uint64* output, const Uint64* a, Uint64 count)
{
    Uint128 t0, t1, t2, t3, t4;
    Uint64  a0, a1, a2, a3, a4;
    Uint64  d0, d1, d2, d4, d419;

    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];
    a4 = a[4];

    do {
        d0   = a0 << 1;
        d1   = a1 << 1;
        d2   = a2 * 38;
        d419 = a4 * 19;
        d4   = d419 << 1;

        t0 = Mul128(a0, a0);
        t0 += Mul128(d4, a1);
        t0 += Mul128(d2, a3);

        t1 = Mul128(d0, a1);
        t1 += Mul128(d4, a2);
        t1 += Mul128(a3, (a3 * 19));

        t2 = Mul128(d0, a2);
        t2 += Mul128(a1, a1);
        t2 += Mul128(d4, a3);

        t3 = Mul128(d0, a3);
        t3 += Mul128(d1, a2);
        t3 += Mul128(a4, d419);

        t4 = Mul128(d0, a4);
        t4 += Mul128(d1, a3);
        t4 += Mul128(a2, a2);

        a0 = ApplyRadix51bitMask(t0);
        t1 += GetRadix51bitCarry(t0);

        a1 = ApplyRadix51bitMask(t1);
        t2 += GetRadix51bitCarry(t1);

        a2 = ApplyRadix51bitMask(t2);
        t3 += GetRadix51bitCarry(t2);

        a3 = ApplyRadix51bitMask(t3);
        t4 += GetRadix51bitCarry(t3);

        a4 = ApplyRadix51bitMask(t4);
        a0 += (GetRadix51bitCarry(t4) * 19);

        a1 += GetRadix51bitCarry(a0);
        a0 = ApplyRadix51bitMask(a0);

        a2 += GetRadix51bitCarry(a1);
        a1 = ApplyRadix51bitMask(a1);

    } while (--count);

    output[0] = a0;
    output[1] = a1;
    output[2] = a2;
    output[3] = a3;
    output[4] = a4;
}

namespace experiemental {
    // Method fails due to overflow 51bit * 5bit(19).
    inline void MulX25519(Uint64* c, const Uint64* b, const Uint64* a)
    {
        Uint128 t0, t1, t2, t3, t4;
        Uint64  r0, r1, r2, r3, r4, s0, s1, s2, s3, s4;

        r0 = a[0];
        r1 = a[1];
        r2 = a[2];
        r3 = a[3];
        r4 = a[4];

        s0 = b[0];
        s1 = b[1];
        s2 = b[2];
        s3 = b[3];
        s4 = b[4];

        __m512i zmm_zero;
        __m512i l0, h0;
        zmm_zero = _mm512_setzero_si512();

        __m512i sx10, sx11, sx12, sx13, sx14;
        __m512i l1, l2, l3, l4, h1, h2, h3, h4;
        __m512i r0_broadcast, r1_broadcast, r2_broadcast, r3_broadcast,
            r4_broadcast;

        Uint64 r1_19 = r1 * 19;
        Uint64 r2_19 = r2 * 19;
        Uint64 r3_19 = r3 * 19;
        Uint64 r4_19 = r4 * 19;

        t0 = ((Uint128)r0) * s0 + ((Uint128)r4_19) * s1 + ((Uint128)r3_19) * s2
             + ((Uint128)r2_19) * s3 + ((Uint128)r1_19) * s4;

        {
            sx10 = _mm512_setr_epi64(s1, 0, s2, 0, s3, 0, s4, 0);
            sx11 = _mm512_setr_epi64(s0, 0, s1, 0, s2, 0, s3, 0);
            sx12 = _mm512_setr_epi64(s4, 0, s0, 0, s1, 0, s2, 0);
            sx13 = _mm512_setr_epi64(s3, 0, s4, 0, s0, 0, s1, 0);
            sx14 = _mm512_setr_epi64(s2, 0, s3, 0, s4, 0, s0, 0);

            r0_broadcast = _mm512_setr_epi64(r0, 0, r0, 0, r0, 0, r0, 0);
            r1_broadcast = _mm512_setr_epi64(r1, 0, r1, 0, r1, 0, r1, 0);
            r2_broadcast = _mm512_setr_epi64(r2_19, 0, r2, 0, r2, 0, r2, 0);
            r3_broadcast = _mm512_setr_epi64(r3_19, 0, r3_19, 0, r3, 0, r3, 0);
            r4_broadcast =
                _mm512_setr_epi64(r4_19, 0, r4_19, 0, r4_19, 0, r4, 0);

            Mul512LowHigh(l0, h0, zmm_zero, sx10, r0_broadcast, 1);
            Mul512LowHigh(l1, h1, zmm_zero, sx11, r1_broadcast, 0);
            Mul512LowHigh(l2, h2, zmm_zero, sx12, r2_broadcast, 0);
            Mul512LowHigh(l3, h3, zmm_zero, sx13, r3_broadcast, 0);
            Mul512LowHigh(l4, h4, zmm_zero, sx14, r4_broadcast, 0);

            l0 = _mm512_add_epi64(l0, l1);
            l0 = _mm512_add_epi64(l0, l2);
            l0 = _mm512_add_epi64(l0, l3);
            l0 = _mm512_add_epi64(l0, l4);

            h0 = _mm512_add_epi64(h0, h1);
            h0 = _mm512_add_epi64(h0, h2);
            h0 = _mm512_add_epi64(h0, h3);
            h0 = _mm512_add_epi64(h0, h4);

            CombineLowHigh52bits(l0, h0);

            t1 = (Uint128)_mm512_extracti64x2_epi64(l0, 0);
            t2 = (Uint128)_mm512_extracti64x2_epi64(l0, 1);
            t3 = (Uint128)_mm512_extracti64x2_epi64(l0, 2);
            t4 = (Uint128)_mm512_extracti64x2_epi64(l0, 3);
        }

        r0 = ApplyRadix51bitMask(t0);
        t1 += GetRadix51bitCarry(t0);
        r1 = ApplyRadix51bitMask(t1);
        t2 += GetRadix51bitCarry(t1);
        r2 = ApplyRadix51bitMask(t2);
        t3 += GetRadix51bitCarry(t2);
        r3 = ApplyRadix51bitMask(t3);
        t4 += GetRadix51bitCarry(t3);
        r4 = ApplyRadix51bitMask(t4);

        r0 += (GetRadix51bitCarry(t4)) * 19;
        r1 += GetRadix51bitCarry(r0);
        r0 = ApplyRadix51bitMask(r0);
        r2 += GetRadix51bitCarry(r1);
        r1 = ApplyRadix51bitMask(r1);

        c[0] = r0;
        c[1] = r1;
        c[2] = r2;
        c[3] = r3;
        c[4] = r4;
    }

} // namespace experiemental

} // namespace alcp::ec::radix51bit