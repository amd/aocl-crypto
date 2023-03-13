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
#include "config.h"

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

#if !ALCP_DISABLE_ASSEMBLY
// convert to a ->in1 and b - > in2
static inline void
SquareX25519Count(Uint64 out[4], const Uint64 a[4], Uint64 count)
{

    Uint64 temp[4];
    temp[0] = a[0];
    temp[1] = a[1];
    temp[2] = a[2];
    temp[3] = a[3];

    for (Uint64 i = 0; i < count; i++) {
        asm("push   %%rax;"
            "push   %%rbx;"
            "push   %%rcx;"
            "push   %%rdx;"
            "push   %%rsi;"
            "push   %%rdi;"
            "push   %%rbp;"
            "push	%%r8;"
            "push	%%r9;"
            "push	%%r10;"
            "push	%%r11;"
            "push	%%r12;"
            "push	%%r13;"
            "push	%%r14;"
            "push	%%r15;"

            "xor	%%rdi,%%rdi;"
            "lea	-8*2(%%rsp),%%rsp;"
            "mov	8*0(%%rax),%%rdx;"
            "mov	8*1(%%rax),%%rcx;"
            "mov	8*2(%%rax),%%rbp;"
            "mov	8*3(%%rax),%%rax;"
            "mulx	%%rdx,%%r8,%%r15;"
            "mulx	%%rcx,%%r9,%%rsi;"
            "mulx	%%rbp,%%r10,%%rbx;"
            "adcx	%%rsi,%%r10;"
            "mulx	%%rax,%%r11,%%r12;"
            "mov	%%rcx,%%rdx;"
            "adcx	%%rbx,%%r11;"
            "adcx	%%rdi,%%r12;"
            "mulx	%%rbp,%%rsi,%%rbx;"
            "adox	%%rsi,%%r11;"
            "adcx	%%rbx,%%r12;"
            "mulx	%%rax,%%rsi,%%r13;"
            "mov	%%rbp,%%rdx;"
            "adox	%%rsi,%%r12;"
            "adcx	%%rdi,%%r13;"
            "mulx	%%rax,%%rsi,%%r14;"
            "mov	%%rcx,%%rdx;"
            "adox	%%rsi,%%r13;"
            "adcx	%%rdi,%%r14;"
            "adox	%%rdi,%%r14;"
            "adcx	%%r9,%%r9;"
            "adox	%%r15,%%r9;"
            "adcx	%%r10,%%r10;"
            "mulx	%%rdx,%%rsi,%%rbx;"
            "mov	%%rbp,%%rdx;"
            "adcx	%%r11,%%r11;"
            "adox	%%rsi,%%r10;"
            "adcx	%%r12,%%r12;"
            "adox	%%rbx,%%r11;"
            "mulx	%%rdx,%%rsi,%%rbx;"
            "mov	%%rax,%%rdx;"
            "adcx	%%r13,%%r13;"
            "adox	%%rsi,%%r12;"
            "adcx	%%r14,%%r14;"
            "adox	%%rbx,%%r13;"
            "mulx	%%rdx,%%rsi,%%r15;"
            "mov	$38,%%edx;"
            "adox	%%rsi,%%r14;"
            "adcx	%%rdi,%%r15;"
            "adox	%%rdi,%%r15;"
            "mulx	%%r12,%%rsi,%%rbx;"
            "adcx	%%rsi,%%r8;"
            "adox	%%rbx,%%r9;"
            "mulx	%%r13,%%rsi,%%rbx;"
            "adcx	%%rsi,%%r9;"
            "adox	%%rbx,%%r10;"
            "mulx	%%r14,%%rsi,%%rbx;"
            "adcx	%%rsi,%%r10;"
            "adox	%%rbx,%%r11;"
            "mulx	%%r15,%%rsi,%%r12;"
            "adcx	%%rsi,%%r11;"
            "adox	%%rdi,%%r12;"
            "adcx	%%rdi,%%r12;"
            "mov	8*10(%%rsp),%%rbp;"
            "mov	8*15(%%rsp),%%rbx;"
            "imulq	%%rdx,%%r12;"
            "add	%%r12,%%r8;"
            "adc	$0,%%r9;"
            "adc	$0,%%r10;"
            "adc	$0,%%r11;"
            "sbb	%%rsi,%%rsi;"
            "and	$38,%%rsi;"
            "add	%%rsi,%%r8;"
            "mov	%%r8,8*0(%1);"
            "mov	%%r9,8*1(%1);"
            "mov	%%r10,8*2(%1);"
            "mov	%%r11,8*3(%1);"
            "mov	8*2(%%rsp),%%r15;"
            "mov	8*3(%%rsp),%%r14;"
            "mov	8*4(%%rsp),%%r13;"
            "mov	8*5(%%rsp),%%r12;"
            "mov	8*6(%%rsp),%%r11;"
            "mov	8*7(%%rsp),%%r10;"
            "mov	8*8(%%rsp),%%r9;"
            "mov	8*9(%%rsp),%%r8;"
            "mov	8*11(%%rsp),%%rdi;"
            "mov	8*12(%%rsp),%%rsi;"
            "mov	8*13(%%rsp),%%rdx;"
            "mov	8*14(%%rsp),%%rcx;"
            "mov	8*16(%%rsp),%%rax;"
            "lea    8*17(%%rsp),%%rsp;"
            :
            : "a"(temp), "b"(out)
            : "memory");
        temp[0] = out[0];
        temp[1] = out[1];
        temp[2] = out[2];
        temp[3] = out[3];
    }
}
#else
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
#endif

#if !ALCP_DISABLE_ASSEMBLY
static void // convert to a ->in1 and b - > in2
MulX25519(Uint64 out[4], const Uint64 a[4], const Uint64 b[4])
{
    asm("push   %%rax;"
        "push   %%rbx;"
        "push   %%rcx;"
        "push   %%rdx;"
        "push   %%rsi;"
        "push   %%rdi;"
        "push   %%rbp;"
        "push	%%r8;"
        "push	%%r9;"
        "push	%%r10;"
        "push	%%r11;"
        "push	%%r12;"
        "push	%%r13;"
        "push	%%r14;"
        "push	%%r15;"

        "xor	%%rdi,%%rdi;"
        "lea	-8*2(%%rsp),%%rsp;"
        "mov	8*0(%%rbx),%%rbp;"
        "mov	8*1(%%rbx),%%rcx;"
        "mov	8*2(%%rbx),%%r14;"
        "mov	8*3(%%rbx),%%r15;"
        "mov	8*0(%%rax),%%rdx;"
        "mulx	%%rbp,%%r8,%%rsi;"
        "mulx	%%rcx,%%r9,%%rbx;"
        "adcx	%%rsi,%%r9;"
        "mulx	%%r14,%%r10,%%rsi;"
        "adcx	%%rbx,%%r10;"
        "mulx	%%r15,%%r11,%%r12;"
        "mov	8*1(%%rax),%%rdx;"
        "adcx	%%rsi,%%r11;"
        "mov	%%r14,(%%rsp);"
        "adcx	%%rdi,%%r12;"
        "mulx	%%rbp,%%rsi,%%rbx;"
        "adox	%%rsi,%%r9;"
        "adcx	%%rbx,%%r10;"
        "mulx	%%rcx,%%rsi,%%rbx;"
        "adox	%%rsi,%%r10;"
        "adcx	%%rbx,%%r11;"
        "mulx	%%r14,%%rsi,%%rbx;"
        "adox	%%rsi,%%r11;"
        "adcx	%%rbx,%%r12;"
        "mulx	%%r15,%%rsi,%%r13;"
        "mov	8*2(%%rax),%%rdx;"
        "adox	%%rsi,%%r12;"
        "adcx	%%rdi,%%r13;"
        "adox	%%rdi,%%r13;"
        "mulx	%%rbp,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r10;"
        "adox	%%rbx,%%r11;"
        "mulx	%%rcx,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r11;"
        "adox	%%rbx,%%r12;"
        "mulx	%%r14,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r12;"
        "adox	%%rbx,%%r13;"
        "mulx	%%r15,%%rsi,%%r14;"
        "mov	8*3(%%rax),%%rdx;"
        "adcx	%%rsi,%%r13;"
        "adox	%%rdi,%%r14;"
        "adcx	%%rdi,%%r14;"
        "mulx	%%rbp,%%rsi,%%rbx;"
        "adox	%%rsi,%%r11;"
        "adcx	%%rbx,%%r12;"
        "mulx	%%rcx,%%rsi,%%rbx;"
        "adox	%%rsi,%%r12;"
        "adcx	%%rbx,%%r13;"
        "mulx	(%%rsp),%%rsi,%%rbx;"
        "adox	%%rsi,%%r13;"
        "adcx	%%rbx,%%r14;"
        "mulx	%%r15,%%rsi,%%r15;"
        "mov	$38,%%edx;"
        "adox	%%rsi,%%r14;"
        "adcx	%%rdi,%%r15;"
        "adox	%%rdi,%%r15;"
        "mulx	%%r12,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r8;"
        "adox	%%rbx,%%r9;"
        "mulx	%%r13,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r9;"
        "adox	%%rbx,%%r10;"
        "mulx	%%r14,%%rsi,%%rbx;"
        "adcx	%%rsi,%%r10;"
        "adox	%%rbx,%%r11;"
        "mulx	%%r15,%%rsi,%%r12;"
        "adcx	%%rsi,%%r11;"
        "adox	%%rdi,%%r12;"
        "adcx	%%rdi,%%r12;"
        "mov	8*10(%%rsp),%%rbp;"
        "mov	8*14(%%rsp),%%rcx;"
        "imulq	%%rdx,%%r12;"
        "add	%%r12,%%r8;"
        "adc	$0,%%r9;"
        "adc	$0,%%r10;"
        "adc	$0,%%r11;"
        "sbb	%%rsi,%%rsi;"
        "and	$38,%%rsi;"
        "add	%%rsi,%%r8;"
        "mov	%%r9,8*1(%2);"
        "mov	%%r10,8*2(%2);"
        "mov	%%r11,8*3(%2);"
        "mov	%%r8,8*0(%2);"

        "mov	8*2(%%rsp),%%r15;"
        "mov	8*3(%%rsp),%%r14;"
        "mov	8*4(%%rsp),%%r13;"
        "mov	8*5(%%rsp),%%r12;"
        "mov	8*6(%%rsp),%%r11;"
        "mov	8*7(%%rsp),%%r10;"
        "mov	8*8(%%rsp),%%r9;"
        "mov	8*9(%%rsp),%%r8;"
        "mov	8*11(%%rsp),%%rdi;"
        "mov	8*12(%%rsp),%%rsi;"
        "mov	8*13(%%rsp),%%rdx;"
        "mov	8*15(%%rsp),%%rbx;"
        "mov	8*16(%%rsp),%%rax;"
        "lea    8*17(%%rsp),%%rsp;"
        :
        : "a"(a), "b"(b), "c"(out)
        : "memory");
}

#else
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
#endif

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