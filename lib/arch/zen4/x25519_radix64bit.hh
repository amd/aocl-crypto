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

    Uint64 b0 = a3 & 0x7fffffffffffffff;

    a3 = 19 + (a3 >> 63) * 19;

    Uint64 cf = _addcarryx_u64(0, a3, a0, (unsigned long long*)&a0);
    cf        = _addcarryx_u64(cf, 0, a1, (unsigned long long*)&a1);
    cf        = _addcarryx_u64(cf, 0, a2, (unsigned long long*)&a2);
    b0 += cf;

    a3 = b0 & 0x7fffffffffffffff;

    b0 = !(b0 >> 63) * 19;

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

    unsigned char carry = _addcarryx_u64(0, b[0], a0, (unsigned long long*)&a0);
    carry = _addcarryx_u64(carry, b[1], a1, (unsigned long long*)&a1);
    carry = _addcarryx_u64(carry, b[2], a2, (unsigned long long*)&a2);
    carry = _addcarryx_u64(carry, b[3], a3, (unsigned long long*)&a3);

    x = carry * 38;

    carry = _addcarryx_u64(0, x, a0, (unsigned long long*)&a0);
    carry = _addcarryx_u64(carry, 0, a1, (unsigned long long*)&a1);
    carry = _addcarryx_u64(carry, 0, a2, (unsigned long long*)&a2);
    carry = _addcarryx_u64(carry, 0, a3, (unsigned long long*)&a3);

    a0 += (carry * 38);

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

    unsigned char carry = _subborrow_u64(0, a0, b[0], (unsigned long long*)&a0);
    carry = _subborrow_u64(carry, a1, b[1], (unsigned long long*)&a1);
    carry = _subborrow_u64(carry, a2, b[2], (unsigned long long*)&a2);
    carry = _subborrow_u64(carry, a3, b[3], (unsigned long long*)&a3);

    x = (carry * 38);

    carry = _subborrow_u64(0, a0, x, (unsigned long long*)&a0);
    carry = _subborrow_u64(carry, a1, 0, (unsigned long long*)&a1);
    carry = _subborrow_u64(carry, a2, 0, (unsigned long long*)&a2);
    carry = _subborrow_u64(carry, a3, 0, (unsigned long long*)&a3);

    a0 -= (carry * 38);

    c[0] = a0;
    c[1] = a1;
    c[2] = a2;
    c[3] = a3;
}

#if !ALCP_DISABLE_ASSEMBLY
static inline void
SquareX25519Count(Uint64 out[4], const Uint64 a[4], Uint64 count)
{

    // Storing the CPU registers on stack to be restored later
    asm("push %%rbp;"
        "push %%rbx;"
        "push %%rcx;"

        "mov	8*0(%%rax),%%rdx;" // a0
        "mov	8*1(%%rax),%%rcx;" // a1
        "mov	8*2(%%rax),%%rbx;" // a2
        "mov	8*3(%%rax),%%rax;" // a3

        "loop:"
        // a0 * a3a2a1a0
        "xor	%%rdi,%%rdi;"       // resetting the carry flags
        "mulx	%%rdx,%%r8,%%r15;"  // a0 * a0
        "mulx	%%rcx,%%r9,%%rsi;"  // a0 * a1
        "mulx	%%rbx,%%r10,%%rbp;" // a0 * a2
        "mulx	%%rax,%%r11,%%r12;" // a0 * a3
        "adcx	%%rsi,%%r10;"       // carry(a0 *a1) + a0 *a2
        "adcx	%%rbp,%%r11;"       // carry(a0 * a2) + a0 * a3
        "adcx	%%rdi,%%r12;"       // carry(a0 * a3)

        // a1 * a3a2
        "mov	%%rcx,%%rdx;"       // a1
        "mulx	%%rbx,%%rsi,%%rbp;" // a1 * a2
        "adox	%%rsi,%%r11;"       // a1 * a2 + carry(a0 * a2) + a0 * a3
        "adcx	%%rbp,%%r12;"       // carry (a1 * a2 ) + carry(a0 * a3)
        "mulx	%%rax,%%rsi,%%r13;" // a3 * a1
        "adox	%%rsi,%%r12;" // a3 * a1 + carry (a1 * a2 ) + carry(a0 * a3)
        "adcx	%%rdi,%%r13;" // carry(a3 * a1)

        // a2 * a3
        "mov	%%rbx,%%rdx;"       // a2
        "mulx	%%rax,%%rsi,%%r14;" // a2 *a3
        "adox	%%rsi,%%r13;"       // a2 * a3 + carry(a3 * a1)
        "adcx	%%rdi,%%r14;"       // carry (a2 *a3) + cf
        "adox	%%rdi,%%r14;"       // carry (a2 *a3) + cf + of

        // sequence of a0a1
        "adcx	%%r9,%%r9;"   // 2 * a0 * a1
        "adox	%%r15,%%r9;"  // carry (a0 * a0) + 2 * a0 * a1
        "adcx	%%r10,%%r10;" // 2 * (carry(a0 *a1) + a0 *a2)

        // sequence of a1a1
        "mov	%%rcx,%%rdx;"       // a1
        "mulx	%%rdx,%%rsi,%%rbp;" // a1 * a1
        "adcx	%%r11,%%r11;"       //  2* (a1 * a2 + carry(a0 * a2) + a0 * a3)
        "adox	%%rsi,%%r10;"       // 2 * (carry(a0 *a1) + a0 *a2) + a1 * a1
        "adcx	%%r12,%%r12;" // 2 * (a3 * a1 + a3 * a1 + carry (a1 * a2 ) +
                              // carry(a0 * a3))
        "adox	%%rbp,%%r11;" // 2* (a1 * a2 + carry(a0 * a2) + a0 * a3) +
                              // carry(a1 * a1)

        // sequence of a2a2
        "mov	%%rbx,%%rdx;"       // a2
        "mulx	%%rdx,%%rsi,%%rbp;" // a2 * a2
        "adcx	%%r13,%%r13;"       // 2 * (a2 * a3 + carry(a3 * a1))
        "adox	%%rsi,%%r12;"       // a2 * a2 + 2 * (a3 * a1 + result_prev_row)
        "adcx	%%r14,%%r14;"       // 2 * (carry (a2 *a3) + cf + of)
        "adox	%%rbp,%%r13;"       // 2 * (a2 * a3 + carry(a3 * a1)) + carry
                                    // (a2*a2)

        // sequence of a3a3
        "mov	%%rax,%%rdx;"       // a3
        "mulx	%%rdx,%%rsi,%%r15;" // a3 * a3
        "adox	%%rsi,%%r14;"       // 2 * (carry (a2 *a3) + cf + of) + a3 * a3
        "adcx	%%rdi,%%r15;"       // carry (a3 * a3) + cf + 0
        "adox	%%rdi,%%r15;"       // carry (a3 * a3) + of + cf

        // modulo 2^255 - 19
        // t0 -> a0a0, t1 ->
        //     a0a1 + a1a0 + carry(t0), t2 -> a0a2 + a1a1 + a2a0 +
        //     carry(t1), t3 -> a0a3 + a1a2 + a2a1 + a3a0 + carry(t2), t4 ->
        //     a1a3 + a2a2 + a3a1 + carry(t3), t5 -> a2a3 + a3a2 +
        //     carry(t4), t6 -> a3a3 + carry(t5), t7
        //    -> carry(t6)
        "mov	$38,%%rdx;"         // 38
        "mulx	%%r12,%%rsi,%%rbp;" // 38 * t4
        "adcx	%%rsi,%%r8;"        // 38 * t4 + t0
        "adox	%%rbp,%%r9;"        // carry(38 * t4) + t1
        "mulx	%%r13,%%rsi,%%rbp;" // 38 * t5
        "adcx	%%rsi,%%r9;"        // carry(38 * t4) + t1 + 38 * t5
        "adox	%%rbp,%%r10;"       // carry(38 *t5) + t2
        "mulx	%%r14,%%rsi,%%rbp;" // 38 * t6
        "adcx	%%rsi,%%r10;"       // 38 * t6 + carry(38 *t5) + t2
        "adox	%%rbp,%%r11;"       // carry(38 * t6) + t3
        "mulx	%%r15,%%rsi,%%r12;" // 38 * t7
        "adcx	%%rsi,%%r11;"       // 38 * t7 + carry(38 * t6) + t3
        "adox	%%rdi,%%r12;"       // carry(38 * t7) + of + 0
        "adcx	%%rdi,%%r12;"       // carry(38 * t7) + of + cf
        "imulq	%%rdx,%%r12;"       // 38 * (carry(38 * t7) + of + cf)
        "add	%%r12,%%r8;"  // 38 * (carry(38 * t7) + of + cf) + 38 * t4 +
                              // t0
        "adc	$0,%%r9;"     // carry(38 * t4) + t1 + 38 * t5 + prevcarry
        "adc	$0,%%r10;"    // 38 * t6 + carry(38 *t5) + t2 + prevcarry
        "adc	$0,%%r11;"    // 38 * t7 + carry(38 * t6) + t3 + prevcarry
        "sbb	%%rsi,%%rsi;" // r12 = all 1 if there is a carry else 0
        "and	$38,%%rsi;"
        "add	%%rsi,%%r8;" // add 38 to t0 if the carry was 1

        "mov	%%r8,%%rdx;"  // a0
        "mov	%%r9,%%rcx;"  // a1
        "mov	%%r10,%%rbx;" // a2
        "mov	%%r11,%%rax;" // a3

        "decq (%%rsp);" // looping for the count times
        "cmpq $1,(%%rsp);"
        "jge loop;"

        // moving the 256 bit result to out array
        "mov	8*1(%%rsp),%%rbx;"
        "mov	%%r8,8*0(%1);"
        "mov	%%r9,8*1(%1);"
        "mov	%%r10,8*2(%1);"
        "mov	%%r11,8*3(%1);"

        "mov	8*2(%%rsp),%%rbp;"
        // restoring the CPU registers
        "lea    8*3(%%rsp),%%rsp;"
        :
        : "a"(a), "b"(out), "c"(count)
        : "memory",
          "r15",
          "cc",
          "r8",
          "r9",
          "r10",
          "r11",
          "r12",
          "r13",
          "r14",
          "rdx",
          "rdi",
          "rsi");
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
    // Storing the CPU registers on stack to be restored later
    asm("push %%rbp;"
        "push   %%rcx;"
        "lea	-8*1(%%rsp),%%rsp;"
        "mov	8*0(%%rbx),%%r12;" // b[0]
        "mov	8*1(%%rbx),%%r13;" // b[1]
        "mov	8*2(%%rbx),%%r14;" // b[2]
        "mov	8*3(%%rbx),%%r15;" // b[3]
        "mov	8*0(%%rax),%%rdx;" // a[0]

        // Applying school book multiplication

        // b3_b2_b1_b0 * a0
        "mulx	%%r12,%%r8,%%rsi;" // a0 * b0
        "mulx	%%r13,%%r9,%%rbx;" // a0 * b1

        "xor	%%rdi,%%rdi;" // clearing off the cf / of flag to be used
                              // in adcx / adox instuction
        "adcx	%%rsi,%%r9;"  // carry(a0 * b0) + (a0 * b1) carry will go in cf
        "mulx	%%r14,%%r10,%%rsi;" // a0 * b2
        "adcx	%%rbx,%%r10;"       // a0 * b2 + carry(a0 * b1)
        "mulx	%%r15,%%r11,%%rbp;" // a0 * b3
        "adcx	%%rsi,%%r11;"       // carry(a0 * b2) + (a0 * b3)
        "adcx	%%rdi,%%rbp;"       // carry(a0 * b3) + 0 + cf

        // b3_b2_b1_b0 * a1
        "mov	8*1(%%rax),%%rdx;"  // a1
        "mulx	%%r12,%%rsi,%%rbx;" // a1 * b0
        "adox	%%rsi,%%r9;"        // (a1 * b0) + result_prev_row
        "adcx	%%rbx,%%r10;"       // carry(a1 * b0) + result_prev_row
        "mulx	%%r13,%%rsi,%%rbx;" // a1 * b1
        "adox	%%rsi,%%r10;" // carry(a1 * b0) + result_prev_row + a1 * b1
        "adcx	%%rbx,%%r11;" // carry(a1 * b1) + result_prev_row
        "mulx	%%r14,%%rsi,%%rbx;" // (b2 * a1)
        "adox	%%rsi,%%r11;" // carry(a1 * b1) + result_prev_row + (b2 * a1)
        "adcx	%%rbx,%%rbp;" // carry(a1 * b2) + result_prev_row
        "mulx	%%r15,%%rsi,%%rcx;" // (b3 * a1)
        "adox	%%rsi,%%rbp;" // (b3 * a1) + carry(a1 * b2) + result_prev_row
        "adcx	%%rdi,%%rcx;" // carry(b3 * a1) + 0 + cf
        "adox	%%rdi,%%rcx;" // carry(b3 * a1) + of + cf + 0

        // b3_b2_b1_b0 * a2
        "mov	%%r14,(%%rsp);"     // b2 -> rsp
        "mov	8*2(%%rax),%%rdx;"  // a2
        "mulx	%%r12,%%rsi,%%rbx;" // b0 * a2
        "adcx	%%rsi,%%r10;"       // (a2 * b0) + result_prev_row
        "adox	%%rbx,%%r11;"       // carry(a2 * b0) + result_prev_row
        "mulx	%%r13,%%rsi,%%rbx;" // a2 * b1
        "adcx	%%rsi,%%r11;" // carry(a2 * b0) + result_prev_row + a2 * b1
        "adox	%%rbx,%%rbp;" // carry(a2 * b1) + result_prev_row
        "mulx	%%r14,%%rsi,%%rbx;" // a2 * b2
        "adcx	%%rsi,%%rbp;" // carry(a2 * b1) + result_prev_row + a2 * b2
        "adox	%%rbx,%%rcx;" // carry (a2 * b2) + result+_prev_row
        "mulx	%%r15,%%rsi,%%r14;" // a2 * b3
        "adcx	%%rsi,%%rcx;" // a2 * b3 + carry (a2 * b2) + result+_prev_row
        "adox	%%rdi,%%r14;" // carry(a2 * b3) + 0 + of
        "adcx	%%rdi,%%r14;" // carry(a2 * b3) + 0 + of + cf

        // b3_b2_b1_b0 * a3
        "mov	8*3(%%rax),%%rdx;"  // a3
        "mulx	%%r12,%%rsi,%%rbx;" // a3 * b0
        "adox	%%rsi,%%r11;"       // a3 * b0 + result_prev_row
        "adcx	%%rbx,%%rbp;"       // carry(a3 * b0) + result_prev_row
        "mulx	%%r13,%%rsi,%%rbx;" // a3 * b1
        "adox	%%rsi,%%rbp;" // carry(a3 * b0) + result_prev_row + a3 * b1
        "adcx	%%rbx,%%rcx;" // carry(a3 * b1) + result_prev_row
        "mulx	(%%rsp),%%rsi,%%rbx;" // a3 * b2
        "adox	%%rsi,%%rcx;" // carry(a3 * b1) + result_prev_row + a3 * b2
        "adcx	%%rbx,%%r14;" // carry(a3 * b2) + result_prev_row
        "mulx	%%r15,%%rsi,%%r15;" // a3 * b3
        "adox	%%rsi,%%r14;" // carry(a3 * b2) + result_prev_row + a3 * b3
        "adcx	%%rdi,%%r15;" // carry(a3 * b3) + 0 + cf
        "adox	%%rdi,%%r15;" // carry(a3 * b3) + of + cf

        //clang-format off

        /*
            modulo 2^255 - 19 -> p = 2^255 - 19 -> 2p + 38 = 2^256
            all the power greater than or equal to 2^256 can we written as
            product of (2p + 38) * (2^64)^i , i ranges from 0 to 3 modulo the
            higher index will result in multiplication by 38 as 2p will be
            reduced to 0 the number formed will be a modulo p t0 -> a0b0, t1 ->
            a0b1 + a1b0 + carry(t0), t2 -> a0b2 + a1b1 + a2b0 + carry(t1), t3 ->
            a0b3 + a1b2 + a2b1 + a3b0 + carry(t2), t4 -> a1b3 + a2b2 + a3b1 +
            carry(t3), t5 -> a2b3 + a3b2 + carry(t4), t6 -> a3b3 + carry(t5), t7
           -> carry(t6)
        */
        // clang-format on

        "mov	$38,%%rdx;"         // 38
        "mulx	%%rbp,%%rsi,%%rbx;" // 38 * t4
        "adcx	%%rsi,%%r8;"        // 38 * t4 + t0
        "adox	%%rbx,%%r9;"        // carry(38 * t4) + t1
        "mulx	%%rcx,%%rsi,%%rbx;" // 38 * t5
        "adcx	%%rsi,%%r9;"        // carry(38 * t4) + t1 + 38 * t5

        "adox	%%rbx,%%r10;"       // carry(38 *t5) + t2
        "mulx	%%r14,%%rsi,%%rbx;" // 38 * t6
        "adcx	%%rsi,%%r10;"       // 38 * t6 + carry(38 *t5) + t2
        "adox	%%rbx,%%r11;"       // carry(38 * t6) + t3
        "mulx	%%r15,%%rsi,%%rbp;" // 38 * t7
        "adcx	%%rsi,%%r11;"       // 38 * t7 + carry(38 * t6) + t3
        "adox	%%rdi,%%rbp;"       // carry(38 * t7) + of + 0
        "adcx	%%rdi,%%rbp;"       // carry(38 * t7) + of + cf
        "imulq	%%rdx,%%rbp;"       // 38 * (carry(38 * t7) + of + cf)
        "add	%%rbp,%%r8;"  // 38 * (carry(38 * t7) + of + cf) + 38 * t4 + t0
        "adc	$0,%%r9;"     // carry(38 * t4) + t1 + 38 * t5 + prevcarry
        "adc	$0,%%r10;"    // 38 * t6 + carry(38 *t5) + t2 + prevcarry
        "adc	$0,%%r11;"    // 38 * t7 + carry(38 * t6) + t3 + prevcarry
        "sbb	%%r12,%%r12;" // r12 = all 1 if there is a carry else 0
        "and	$38,%%r12;"
        "add	%%r12,%%r8;" // add 38 to t0 if the carry was 1

        // moving the 256 bit result to out array
        "mov	8*1(%%rsp),%%rcx;"
        "mov	%%r8,8*0(%2);"
        "mov	%%r9,8*1(%2);"
        "mov	%%r10,8*2(%2);"
        "mov	%%r11,8*3(%2);"

        "mov	8*2(%%rsp),%%rbp;"
        "lea    8*3(%%rsp),%%rsp;"
        :
        : "a"(a), "b"(b), "c"(out)
        : "memory",
          "r15",
          "cc",
          "r8",
          "r9",
          "r10",
          "r11",
          "r12",
          "r13",
          "r14",
          "rdx",
          "rdi",
          "rsi");
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

    lo = -carry & 38;
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