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

namespace radix64bit {
using namespace alcp;
static inline void
RadixToBytes(Uint64 out[4], const Uint64 a[4])
{
    Uint64 a0, a1, a2, a3;
    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];

    Uint64 b0 = 2 * a3;
    a3        = -(a3 >> 63);
    b0        = b0 >> 1;
    a3        = a3 & 19;
    a3 += 19;

    Uint64 cf = _addcarryx_u64(0, a3, a0, (unsigned long long*)&a0);
    cf        = _addcarryx_u64(cf, 0, a1, (unsigned long long*)&a1);
    cf        = _addcarryx_u64(cf, 0, a2, (unsigned long long*)&a2);
    b0 += cf;
    a3 = 2 * b0;
    b0 = -(b0 >> 63);
    a3 = a3 >> 1;
    b0 = ~b0;
    b0 = b0 & 19;

    cf = _subborrow_u64(0, a0, b0, (unsigned long long*)&a0);
    cf = _subborrow_u64(cf, a1, 0, (unsigned long long*)&a1);
    cf = _subborrow_u64(cf, a2, 0, (unsigned long long*)&a2);
    a3 -= cf;

    out[0] = a0;
    out[1] = a1;
    out[2] = a2;
    out[3] = a3;
}

static void
BytesToRadix(Uint64 out[4], const Uint64 a[4])
{
    out[0] = a[0];
    out[1] = a[1];
    out[2] = a[2];
    out[3] = a[3];
}

static inline void
SumX25519(Uint64* c, const Uint64* a, const Uint64* b)
{
    Uint64 x, a0, a1, a2, a3;
    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];

    unsigned char carry = 0;
    carry = _addcarryx_u64(carry, b[0], a0, (unsigned long long*)&a0);
    carry = _addcarryx_u64(carry, b[1], a1, (unsigned long long*)&a1);
    carry = _addcarryx_u64(carry, b[2], a2, (unsigned long long*)&a2);
    carry = _addcarryx_u64(carry, b[3], a3, (unsigned long long*)&a3);

    _subborrow_u64(carry, x, x, (unsigned long long*)&x);
    x = x & 38;

    carry = 0;
    carry = _addcarryx_u64(carry, x, a0, (unsigned long long*)&a0);
    carry = _addcarryx_u64(carry, 0, a1, (unsigned long long*)&a1);
    carry = _addcarryx_u64(carry, 0, a2, (unsigned long long*)&a2);
    carry = _addcarryx_u64(carry, 0, a3, (unsigned long long*)&a3);

    _subborrow_u64(carry, x, x, (unsigned long long*)&x);
    x  = x & 38;
    a0 = a0 + x;

    c[0] = a0;
    c[1] = a1;
    c[2] = a2;
    c[3] = a3;
}

static inline void
SubX25519(Uint64* c, const Uint64* a, const Uint64* b)
{
    Uint64 x, a0, a1, a2, a3;
    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];

    unsigned char carry = 0;

    carry = _subborrow_u64(carry, b[0], a0, (unsigned long long*)&a0);
    carry = _subborrow_u64(carry, b[1], a1, (unsigned long long*)&a1);
    carry = _subborrow_u64(carry, b[2], a2, (unsigned long long*)&a2);
    carry = _subborrow_u64(carry, b[3], a3, (unsigned long long*)&a3);

    _subborrow_u64(carry, x, x, (unsigned long long*)&x);
    x = x & 38;

    carry = 0;
    carry = _subborrow_u64(carry, x, a0, (unsigned long long*)&a0);
    carry = _subborrow_u64(carry, 0, a1, (unsigned long long*)&a1);
    carry = _subborrow_u64(carry, 0, a2, (unsigned long long*)&a2);
    carry = _subborrow_u64(carry, 0, a3, (unsigned long long*)&a3);

    _subborrow_u64(carry, x, x, (unsigned long long*)&x);
    x = x & 38;

    a0 = a0 - x;

    c[0] = a0;
    c[1] = a1;
    c[2] = a2;
    c[3] = a3;
}

inline void
SquareX25519Count(Uint64* output, const Uint64* a, Uint64 count)
{
    Uint64 r0 = a[0];
    Uint64 r1 = a[1];
    Uint64 r2 = a[2];
    Uint64 r3 = a[3];

    for (Uint64 i = 0; i < count; i++) {
        Uint64 a7, b0, b1, a4, cf1, a5, a6;
        Uint64 a0 = _mulx_u64(r0, r0, (unsigned long long*)&a7);
        Uint64 a1 = _mulx_u64(r0, r1, (unsigned long long*)&b0);
        Uint64 a2 = _mulx_u64(r0, r2, (unsigned long long*)&b1);
        Uint64 cf = _addcarryx_u64(0, b0, a2, (unsigned long long*)&a2);
        Uint64 a3 = _mulx_u64(r0, r3, (unsigned long long*)&a4);
        r0        = r1;
        cf        = _addcarryx_u64(cf, b1, a3, (unsigned long long*)&a3);
        a4 += cf;

        b0  = _mulx_u64(r0, r2, (unsigned long long*)&b1);
        cf  = _addcarryx_u64(0, b0, a3, (unsigned long long*)&a3);
        cf1 = _addcarryx_u64(0, b1, a4, (unsigned long long*)&a4);
        b0  = _mulx_u64(r0, r3, (unsigned long long*)&a5);
        r0  = r2;
        cf  = _addcarryx_u64(cf, b0, a4, (unsigned long long*)&a4);
        cf1 = _addcarryx_u64(cf1, 0, a5, (unsigned long long*)&a5);

        b0 = _mulx_u64(r0, r3, (unsigned long long*)&a6);
        r0 = r1;
        cf = _addcarryx_u64(cf, b0, a5, (unsigned long long*)&a5);
        a6 += (cf1 + cf);

        cf  = _addcarryx_u64(0, a1, a1, (unsigned long long*)&a1);
        cf1 = _addcarryx_u64(0, a7, a1, (unsigned long long*)&a1);
        cf  = _addcarryx_u64(cf, a2, a2, (unsigned long long*)&a2);
        b0  = _mulx_u64(r0, r0, (unsigned long long*)&b1);
        r0  = r2;
        cf  = _addcarryx_u64(cf, a3, a3, (unsigned long long*)&a3);
        cf1 = _addcarryx_u64(cf1, b0, a2, (unsigned long long*)&a2);
        cf  = _addcarryx_u64(cf, a4, a4, (unsigned long long*)&a4);
        cf1 = _addcarryx_u64(cf1, b1, a3, (unsigned long long*)&a3);
        b0  = _mulx_u64(r0, r0, (unsigned long long*)&b1);
        r0  = r3;
        cf  = _addcarryx_u64(cf, a5, a5, (unsigned long long*)&a5);
        cf1 = _addcarryx_u64(cf1, b0, a4, (unsigned long long*)&a4);
        cf  = _addcarryx_u64(cf, a6, a6, (unsigned long long*)&a6);
        cf1 = _addcarryx_u64(cf1, b1, a5, (unsigned long long*)&a5);
        b0  = _mulx_u64(r0, r0, (unsigned long long*)&a7);
        r0  = 38;
        cf1 = _addcarryx_u64(cf1, b0, a6, (unsigned long long*)&a6);
        a7 += (cf + cf1);

        b0  = _mulx_u64(r0, a4, (unsigned long long*)&b1);
        cf  = _addcarryx_u64(0, b0, a0, (unsigned long long*)&a0);
        cf1 = _addcarryx_u64(0, b1, a1, (unsigned long long*)&a1);
        b0  = _mulx_u64(r0, a5, (unsigned long long*)&b1);
        cf  = _addcarryx_u64(cf, b0, a1, (unsigned long long*)&a1);
        cf1 = _addcarryx_u64(cf1, b1, a2, (unsigned long long*)&a2);
        b0  = _mulx_u64(r0, a6, (unsigned long long*)&b1);
        cf  = _addcarryx_u64(cf, b0, a2, (unsigned long long*)&a2);
        cf1 = _addcarryx_u64(cf1, b1, a3, (unsigned long long*)&a3);
        b0  = _mulx_u64(r0, a7, (unsigned long long*)&a4);
        cf  = _addcarryx_u64(cf, b0, a3, (unsigned long long*)&a3);
        a4  = a4 + cf + cf1;

        a4 = _mulx_u64(r0, a4, (unsigned long long*)&cf);
        cf = _addcarryx_u64(0, a4, a0, (unsigned long long*)&r0);
        cf = _addcarryx_u64(cf, 0, a1, (unsigned long long*)&r1);
        cf = _addcarryx_u64(cf, 0, a2, (unsigned long long*)&r2);
        cf = _addcarryx_u64(cf, 0, a3, (unsigned long long*)&r3);

        b0 = -cf;
        b0 = b0 & 38;
        r0 += b0;
    }

    output[0] = r0;
    output[1] = r1;
    output[2] = r2;
    output[3] = r3;
}

static inline void
MulX25519(Uint64* c, const Uint64* a, const Uint64* b)
{

    long long unsigned int a0, a1, a2, a3;
    long long unsigned int b0, b1, b2, b3;
    long long unsigned int c0, c1, c2, c3, c4, c5, c6, c7, hi0, lo, hi;

    unsigned char carry = 0;
    unsigned char o     = 0;

    b0 = b[0];
    b1 = b[1];
    b2 = b[2];
    b3 = b[3];

    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];

    c0    = _mulx_u64(a0, b0, &hi0);
    c1    = _mulx_u64(a0, b1, &hi);
    carry = _addcarryx_u64(carry, hi0, c1, &c1);
    c2    = _mulx_u64(a0, b2, &hi0);
    carry = _addcarryx_u64(carry, hi, c2, &c2);
    c3    = _mulx_u64(a0, b3, &c4);

    carry = _addcarryx_u64(carry, hi0, c3, &c3);
    carry = _addcarryx_u64(carry, 0, c4, &c4);

    /////////////////////////////////////////
    lo    = _mulx_u64(a1, b0, &hi);
    o     = _addcarry_u64(0, lo, c1, &c1);
    carry = _addcarry_u64(carry, hi, c2, &c2);
    lo    = _mulx_u64(a1, b1, &hi);
    o     = _addcarry_u64(o, lo, c2, &c2);
    carry = _addcarry_u64(carry, hi, c3, &c3);
    lo    = _mulx_u64(a1, b2, &hi);
    o     = _addcarry_u64(o, lo, c3, &c3);
    carry = _addcarry_u64(carry, hi, c4, &c4);
    lo    = _mulx_u64(a1, b3, &c5);

    o     = _addcarry_u64(o, lo, c4, &c4);
    carry = _addcarry_u64(carry, o, c5, &c5);

    ////////////////////////////////////////////

    lo    = _mulx_u64(a2, b0, &hi);
    carry = _addcarry_u64(0, lo, c2, &c2);
    o     = _addcarry_u64(0, hi, c3, &c3);
    lo    = _mulx_u64(a2, b1, &hi);
    carry = _addcarry_u64(carry, lo, c3, &c3);
    o     = _addcarry_u64(o, hi, c4, &c4);
    lo    = _mulx_u64(a2, b2, &hi);
    carry = _addcarry_u64(carry, lo, c4, &c4);
    o     = _addcarry_u64(o, hi, c5, &c5);
    lo    = _mulx_u64(a2, b3, &c6);
    carry = _addcarry_u64(carry, lo, c5, &c5);
    carry = _addcarry_u64(carry, o, c6, &c6);

    ////////////////////////////////////////////
    lo    = _mulx_u64(a3, b0, &hi);
    o     = _addcarry_u64(0, lo, c3, &c3);
    carry = _addcarry_u64(0, hi, c4, &c4);
    lo    = _mulx_u64(a3, b1, &hi);
    o     = _addcarry_u64(o, lo, c4, &c4);
    carry = _addcarry_u64(carry, hi, c5, &c5);
    lo    = _mulx_u64(a3, b2, &hi);
    o     = _addcarry_u64(o, lo, c5, &c5);
    carry = _addcarry_u64(carry, hi, c6, &c6);
    lo    = _mulx_u64(a3, b3, &c7);
    o     = _addcarry_u64(o, lo, c6, &c6);
    carry = _addcarry_u64(carry, o, c7, &c7);

    ////////////////////reduction /////////////////
    long unsigned int f = 38;

    lo    = _mulx_u64(c4, f, &hi);
    carry = _addcarry_u64(0, lo, c0, &c0);
    o     = _addcarry_u64(0, hi, c1, &c1);
    lo    = _mulx_u64(c5, f, &hi);
    carry = _addcarry_u64(carry, lo, c1, &c1);
    o     = _addcarry_u64(o, hi, c2, &c2);
    lo    = _mulx_u64(c6, f, &hi);
    carry = _addcarry_u64(carry, lo, c2, &c2);
    o     = _addcarry_u64(o, hi, c3, &c3);
    lo    = _mulx_u64(c7, f, &c4);
    carry = _addcarry_u64(carry, lo, c3, &c3);
    carry = _addcarry_u64(carry, o, c4, &c4);

    c4 = 38 * c4;

    carry = _addcarry_u64(0, c0, c4, &c0);
    carry = _addcarry_u64(carry, c1, 0, &c1);
    carry = _addcarry_u64(carry, c2, 0, &c2);
    carry = _addcarry_u64(carry, c3, 0, &c3);

    _subborrow_u64(carry, lo, lo, &lo);
    lo = lo & 38;
    c0 = c0 + lo;

    c[0] = c0;
    c[1] = c1;
    c[2] = c2;
    c[3] = c3;
}

static inline void
ScalarMulX25519(Uint64* output, const Uint64* in)
{
    Uint64 mult = 121665, c, adder;
    Uint64 a0, a1, a2, a3;
    a0 = _mulx_u64(in[0], mult, (unsigned long long*)&c);
    a1 = _mulx_u64(in[1], mult, (unsigned long long*)&adder);

    Uint8 carry = _addcarry_u64(0, c, a1, (unsigned long long*)&a1);

    a2 = _mulx_u64(in[2], mult, (unsigned long long*)&c);

    carry = _addcarry_u64(carry, adder, a2, (unsigned long long*)&a2);

    a3 = _mulx_u64(in[3], mult, (unsigned long long*)&adder);

    carry = _addcarry_u64(carry, c, a3, (unsigned long long*)&a3);

    adder += carry;

    adder = _mulx_u64(38, adder, (unsigned long long*)&c);

    carry = _addcarry_u64(0, adder, a0, (unsigned long long*)&a0);
    carry = _addcarry_u64(carry, 0, a1, (unsigned long long*)&a1);
    carry = _addcarry_u64(carry, 0, a2, (unsigned long long*)&a2);
    carry = _addcarry_u64(carry, 0, a3, (unsigned long long*)&a3);

    adder = -carry;

    adder = adder & 38;

    a0 += adder;

    output[0] = a0;
    output[1] = a1;
    output[2] = a2;
    output[3] = a3;
}

} // namespace radix64bit