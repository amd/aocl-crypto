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

namespace radix64bit {

static void
RadixExpand(__m512i* pOutput, const Uint8* in)
{
    __m256i maskAND = _m256_set_epi64(0, 0, 0, 0, 0x7ffffffffffff, -1, -1, -1);

    auto    pOut256 = reinterpret_cast<const __m256i*>(pOutput);
    __m256i a0      = _mm256_loadu_epi64(in);
    a0              = _mm256_and_si256(a0, maskAND);

    _m256_store_epi64(pOut256, a0);
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
    carry               = _addcarryx_u64(carry, b[0], a0, &a0);
    carry               = _addcarryx_u64(carry, b[1], a1, &a1);
    carry               = _addcarryx_u64(carry, b[2], a2, &a2);
    carry               = _addcarryx_u64(carry, b[3], a3, &a3);

    _subborrow_u64(carry, x, x, &x);
    x = x & 38;

    carry = 0;
    carry = _addcarryx_u64(carry, x, a0, &a0);
    carry = _addcarryx_u64(carry, 0, a1, &a1);
    carry = _addcarryx_u64(carry, 0, a2, &a2);
    carry = _addcarryx_u64(carry, 0, a3, &a3);

    _subborrow_u64(carry, x, x, &x);
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

    carry = _subborrow_u64(carry, b[0], a0, &a0);
    carry = _subborrow_u64(carry, b[1], a1, &a1);
    carry = _subborrow_u64(carry, b[2], a2, &a2);
    carry = _subborrow_u64(carry, b[3], a3, &a3);

    _subborrow_u64(carry, x, x, &x);
    x = x & 38;

    carry = 0;
    carry = _subborrow_u64(carry, x, a0, &a0);
    carry = _subborrow_u64(carry, 0, a1, &a1);
    carry = _subborrow_u64(carry, 0, a2, &a2);
    carry = _subborrow_u64(carry, 0, a3, &a3);

    _subborrow_u64(carry, x, x, &x);
    x = x & 38;

    a0 = a0 - x;

    c[0] = a0;
    c[1] = a1;
    c[2] = a2;
    c[3] = a3;
}

static inline void
MulX25519(Uint64* c, const Uint64* a, const Uint64* b)
{

    long long unsigned int a0, a1, a2, a3;
    long long unsigned int b0, b1, b2, b3;
    long long unsigned int c0, c1, c2, c3, c4, c5, c6, c7, hi0, lo, hi;

    unsigned char c = 0;
    unsigned char o = 0;

    b0 = b[0];
    b1 = b[1];
    b2 = b[2];
    b3 = b[3];

    a0 = a[0];
    a1 = a[1];
    a2 = a[2];
    a3 = a[3];

    c0 = _mulx_u64(a0, b0, &hi0);
    c1 = _mulx_u64(a0, b1, &hi);
    c  = _addcarryx_u64(c, hi0, c1, &c1);
    c2 = _mulx_u64(a0, b2, &hi0);
    c  = _addcarryx_u64(c, hi, c2, &c2);
    c3 = _mulx_u64(a0, b3, &c4);

    c = _addcarryx_u64(c, hi0, c3, &c3);
    c = _addcarryx_u64(c, 0, c4, &c4);

    /////////////////////////////////////////
    lo = _mulx_u64(a1, b0, &hi);
    o  = _addcarry_u64(0, lo, c1, &c1);
    c  = _addcarry_u64(c, hi, c2, &c2);
    lo = _mulx_u64(a1, b1, &hi);
    o  = _addcarry_u64(o, lo, c2, &c2);
    c  = _addcarry_u64(c, hi, c3, &c3);
    lo = _mulx_u64(a1, b2, &hi);
    o  = _addcarry_u64(o, lo, c3, &c3);
    c  = _addcarry_u64(c, hi, c4, &c4);
    lo = _mulx_u64(a1, b3, &c5);

    o = _addcarry_u64(o, lo, c4, &c4);
    c = _addcarry_u64(c, o, c5, &c5);

    ////////////////////////////////////////////

    lo = _mulx_u64(a2, b0, &hi);
    c  = _addcarry_u64(0, lo, c2, &c2);
    o  = _addcarry_u64(0, hi, c3, &c3);
    lo = _mulx_u64(a2, b1, &hi);
    c  = _addcarry_u64(c, lo, c3, &c3);
    o  = _addcarry_u64(o, hi, c4, &c4);
    lo = _mulx_u64(a2, b2, &hi);
    c  = _addcarry_u64(c, lo, c4, &c4);
    o  = _addcarry_u64(o, hi, c5, &c5);
    lo = _mulx_u64(a2, b3, &c6);
    c  = _addcarry_u64(c, lo, c5, &c5);
    c  = _addcarry_u64(c, o, c6, &c6);

    ////////////////////////////////////////////
    lo = _mulx_u64(a3, b0, &hi);
    o  = _addcarry_u64(0, lo, c3, &c3);
    c  = _addcarry_u64(0, hi, c4, &c4);
    lo = _mulx_u64(a3, b1, &hi);
    o  = _addcarry_u64(o, lo, c4, &c4);
    c  = _addcarry_u64(c, hi, c5, &c5);
    lo = _mulx_u64(a3, b2, &hi);
    o  = _addcarry_u64(o, lo, c5, &c5);
    c  = _addcarry_u64(c, hi, c6, &c6);
    lo = _mulx_u64(a3, b3, &c7);
    o  = _addcarry_u64(o, lo, c6, &c6);
    c  = _addcarry_u64(c, o, c7, &c7);

    ////////////////////reduction /////////////////
    long unsigned int f = 38;

    lo = _mulx_u64(c4, f, &hi);
    c  = _addcarry_u64(0, lo, c0, &c0);
    o  = _addcarry_u64(0, hi, c1, &c1);
    lo = _mulx_u64(c5, f, &hi);
    c  = _addcarry_u64(c, lo, c1, &c1);
    o  = _addcarry_u64(o, hi, c2, &c2);
    lo = _mulx_u64(c6, f, &hi);
    c  = _addcarry_u64(c, lo, c2, &c2);
    o  = _addcarry_u64(o, hi, c3, &c3);
    lo = _mulx_u64(c7, f, &c4);
    c  = _addcarry_u64(c, lo, c3, &c3);
    c  = _addcarry_u64(c, o, c4, &c4);

    c4 = 38 * c4;

    c = _addcarry_u64(0, c0, c4, &c0);
    c = _addcarry_u64(c, c1, 0, &c1);
    c = _addcarry_u64(c, c2, 0, &c2);
    c = _addcarry_u64(c, c3, 0, &c3);

    _subborrow_u64(c, lo, lo, &lo);
    lo = lo & 38;
    c0 = c0 + lo;

    c[0] = c0;
    c[1] = c1;
    c[2] = c2;
    c[3] = c3;
}

} // namespace radix64bit