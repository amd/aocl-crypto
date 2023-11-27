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
#include "alcp/types.hh"

#pragma once

#ifdef COMPILER_IS_GCC
#define NO_OPTIMIZE
#else
#define NO_OPTIMIZE __attribute__((optnone))
#endif
Uint64
MUL64(Uint64 a, Uint64 b, long long unsigned* rem)
{
    __uint128_t res = (__uint128_t)a * b;
    *rem            = (Uint64)(res >> 64);
    return (Uint64)res;
}
#define _mulx_u64(x, y, z) MUL64(x, y, z);

NO_OPTIMIZE
Uint8
ADD64(Uint8 carry, Uint64 a, Uint64 b, long long unsigned* res)
{
    __uint128_t sum = (__uint128_t)a + b + carry;
    *res            = (Uint64)(sum);
    return (Uint8)(sum >> 64);
}

#define _addcarryx_u64(x, y, z, t) ADD64(x, y, z, t)

Uint8
SUB64(Uint8 carry, Uint64 a, Uint64 b, long long unsigned* res)
{
    __uint128_t sub = (__uint128_t)a - ((__uint128_t)b + carry);
    *res            = (Uint64)(sub);
    return (Uint8) !!(sub >> 64);
}

#define _subborrow_u64(x, y, z, t) SUB64(x, y, z, t)

Uint64
LEADZEROS(Uint64 a)
{
    unsigned y;
    int      n = 64;

    y = a >> 32;
    if (y != 0) {
        n = n - 32;
        a = y;
    }
    y = a >> 16;
    if (y != 0) {
        n = n - 16;
        a = y;
    }
    y = a >> 8;
    if (y != 0) {
        n = n - 8;
        a = y;
    }
    y = a >> 4;
    if (y != 0) {
        n = n - 4;
        a = y;
    }
    y = a >> 2;
    if (y != 0) {
        n = n - 2;
        a = y;
    }
    y = a >> 1;
    if (y != 0)
        return n - 2;
    return n - a;
}

#define _lzcnt_u64(x) LEADZEROS(x)
