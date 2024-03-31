/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
 * Portions of this file consist of AI-generated content.
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

#include <array>
#include <cassert>
#include <immintrin.h>
#include <tuple>

#include "alcp/mac/poly1305_zen4.hh"

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#include <iostream>
#include <string>
void
debug_print(std::string in)
{
    std::cout << in;
    std::cout << std::endl;
}
#else
void
debug_print(std::string in)
{
}
#endif
// #define POLY_AVX512

namespace alcp::mac::poly1305::zen4 {

// Pure C++ Functions
void
radix44(Uint8 msg[], Uint64 output[3])
{
    // Wipe the output buffer
    std::fill(output, output + 3, 0);

    Uint8* msg_input_ptr = msg;
    for (int i = 0; i < 3; i++) {
        // Load 64 bits from msg_input into output[i] using std::copy
        if (i == 2) {
            // Only 6 more bytes are left for the last message
            std::copy(msg_input_ptr, msg_input_ptr + 6, (Uint8*)&output[i]);
        } else {
            // Load 8 bytes into output[i]
            std::copy(msg_input_ptr, msg_input_ptr + 8, (Uint8*)&output[i]);
        }
        // Right shift output by extra bits
        output[i] >>= 4 * i;
        // Mask output by 44 bits
        output[i] &= 0xfffffffffff;
        msg_input_ptr += 5;
    }
}

void
clamp(Uint8 in[16])
{
    constexpr std::array<std::tuple<int, int>, 7> cIndex = {
        std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
        std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
        std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
        std::tuple<int, int>({ 12, 252 })
    };

    for (const auto& i : cIndex) {
        in[std::get<0>(i)] &= std::get<1>(i);
    }
}

// AVX512 functions
inline void
create_multiplication_matrix(const Uint64 r[5],
                             const Uint64 s[4],
                             __m512i&     reg0,
                             __m512i&     reg1,
                             __m512i&     reg2,
                             __m512i&     reg3,
                             __m512i&     reg4)
{
    __m512i idx, r_reg, s_reg;

    // Load r
    r_reg = _mm512_maskz_loadu_epi64(0x1f, r);

    // Load s
    s_reg = _mm512_maskz_loadu_epi64(0x0f, s);
    reg0  = r_reg;

    // Create multiplication matrix with modulo trick
    idx  = _mm512_setr_epi64(1 << 3 | 3, 0, 1, 2, 3, 6, 6, 6);
    reg1 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(1 << 3 | 2, 1 << 3 | 3, 0, 1, 2, 6, 6, 6);
    reg2 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(1 << 3 | 1, 1 << 3 | 2, 1 << 3 | 3, 0, 1, 6, 6, 6);
    reg3 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(
        1 << 3 | 0, 1 << 3 | 1, 1 << 3 | 2, 1 << 3 | 3, 0, 6, 6, 6);
    reg4 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
}

inline void
multiply_avx512(Uint64  a[5], // Input and output
                __m512i reg0, // Used also as temp reg
                __m512i reg1, // Used also as temp reg
                __m512i reg2, // Used also as temp reg
                __m512i reg3, // Used also as temp reg
                __m512i reg4) // Used also as temp reg
{
    __m512i            regtemp = {}, regtemp1 = {};
    alignas(64) Uint64 temp[8] = {};

    // a*r
    regtemp  = _mm512_set1_epi64(a[0]);
    reg0     = _mm512_mullox_epi64(reg0, regtemp);
    regtemp1 = _mm512_set1_epi64(a[1]);
    reg1     = _mm512_mullox_epi64(reg1, regtemp1);
    regtemp  = _mm512_set1_epi64(a[2]);
    reg2     = _mm512_mullox_epi64(reg2, regtemp);
    regtemp1 = _mm512_set1_epi64(a[3]);
    reg3     = _mm512_mullox_epi64(reg3, regtemp1);
    regtemp  = _mm512_set1_epi64(a[4]);
    reg4     = _mm512_mullox_epi64(reg4, regtemp);
    // compute d[0],d[1],d[2],d[3],d[4]
    regtemp  = reg0;
    regtemp1 = reg3;
    regtemp  = _mm512_add_epi64(regtemp, reg1);
    regtemp  = _mm512_add_epi64(regtemp, reg2);
    regtemp1 = _mm512_add_epi64(regtemp1, reg4);
    regtemp  = _mm512_add_epi64(regtemp, regtemp1);

    // Carry propagate and write it to a
    _mm512_store_epi64(temp, regtemp);
    Uint64 carry = (unsigned long)(temp[0] >> 26);
    a[0]         = (unsigned long)temp[0] & 0x3ffffff;
    temp[1] += carry;
    carry = (unsigned long)(temp[1] >> 26);
    a[1]  = (unsigned long)temp[1] & 0x3ffffff;
    temp[2] += carry;
    carry = (unsigned long)(temp[2] >> 26);
    a[2]  = (unsigned long)temp[2] & 0x3ffffff;
    temp[3] += carry;
    carry = (unsigned long)(temp[3] >> 26);
    a[3]  = (unsigned long)temp[3] & 0x3ffffff;
    temp[4] += carry;
    carry = (unsigned long)(temp[4] >> 26);
    a[4]  = (unsigned long)temp[4] & 0x3ffffff;
    a[0] += carry * 5;
    carry = (a[0] >> 26);
    a[0]  = a[0] & 0x3ffffff;
    a[1] += carry;
}

inline void
multiply_avx512(Uint64 a[5], const Uint64 r[5], const Uint64 s[4])
{
    __m512i            reg0, reg1, reg2, reg3, reg4, idx, r_reg, s_reg;
    __m512i            regtemp = {}, regtemp1 = {};
    alignas(64) Uint64 temp[8] = {};

    // Load r
    r_reg = _mm512_maskz_loadu_epi64(0x1f, r);

    // Load s
    s_reg = _mm512_maskz_loadu_epi64(0x0f, s);
    reg0  = r_reg;

    // Create multiplication matrix with modulo trick
    idx  = _mm512_setr_epi64(1 << 3 | 3, 0, 1, 2, 3, 6, 6, 6);
    reg1 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(1 << 3 | 2, 1 << 3 | 3, 0, 1, 2, 6, 6, 6);
    reg2 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(1 << 3 | 1, 1 << 3 | 2, 1 << 3 | 3, 0, 1, 6, 6, 6);
    reg3 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    idx  = _mm512_setr_epi64(
        1 << 3 | 0, 1 << 3 | 1, 1 << 3 | 2, 1 << 3 | 3, 0, 6, 6, 6);
    reg4 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);

    // a*r
    regtemp  = _mm512_set1_epi64(a[0]);
    reg0     = _mm512_mullox_epi64(reg0, regtemp);
    regtemp1 = _mm512_set1_epi64(a[1]);
    reg1     = _mm512_mullox_epi64(reg1, regtemp1);
    regtemp  = _mm512_set1_epi64(a[2]);
    reg2     = _mm512_mullox_epi64(reg2, regtemp);
    regtemp1 = _mm512_set1_epi64(a[3]);
    reg3     = _mm512_mullox_epi64(reg3, regtemp1);
    regtemp  = _mm512_set1_epi64(a[4]);
    reg4     = _mm512_mullox_epi64(reg4, regtemp);
    // compute d[0],d[1],d[2],d[3],d[4]
    regtemp  = reg0;
    regtemp1 = reg3;
    regtemp  = _mm512_add_epi64(regtemp, reg1);
    regtemp  = _mm512_add_epi64(regtemp, reg2);
    regtemp1 = _mm512_add_epi64(regtemp1, reg4);
    regtemp  = _mm512_add_epi64(regtemp, regtemp1);

    // Carry propagate and write it to a
    _mm512_store_epi64(temp, regtemp);
    Uint64 carry = (unsigned long)(temp[0] >> 26);
    a[0]         = (unsigned long)temp[0] & 0x3ffffff;
    temp[1] += carry;
    carry = (unsigned long)(temp[1] >> 26);
    a[1]  = (unsigned long)temp[1] & 0x3ffffff;
    temp[2] += carry;
    carry = (unsigned long)(temp[2] >> 26);
    a[2]  = (unsigned long)temp[2] & 0x3ffffff;
    temp[3] += carry;
    carry = (unsigned long)(temp[3] >> 26);
    a[3]  = (unsigned long)temp[3] & 0x3ffffff;
    temp[4] += carry;
    carry = (unsigned long)(temp[4] >> 26);
    a[4]  = (unsigned long)temp[4] & 0x3ffffff;
    a[0] += carry * 5;
    carry = (a[0] >> 26);
    a[0]  = a[0] & 0x3ffffff;
    a[1] += carry;
}

/**
 * @brief Function to compute a*b%p given s=b[1:5]*5
 *
 * @param a Multiplicand
 * @param b Multiplier
 * @param s Modulo Trick cached value
 * @return Uint64
 */
inline void
multiply(Uint64 a[5], Uint64 b[5], Uint64 s[4])
{
    alignas(64) Uint64 d[5]  = {};
    Uint64             carry = 0;
    // a = a * r
    // clang-format off
    d[0] = (a[0] * b[0]) + (a[1] * s[3]) + (a[2] * s[2]) + (a[3] * s[1]) + (a[4] * s[0]);
    d[1] = (a[0] * b[1]) + (a[1] * b[0]) + (a[2] * s[3]) + (a[3] * s[2]) + (a[4] * s[1]);
    d[2] = (a[0] * b[2]) + (a[1] * b[1]) + (a[2] * b[0]) + (a[3] * s[3]) + (a[4] * s[2]);
    d[3] = (a[0] * b[3]) + (a[1] * b[2]) + (a[2] * b[1]) + (a[3] * b[0]) + (a[4] * s[3]);
    d[4] = (a[0] * b[4]) + (a[1] * b[3]) + (a[2] * b[2]) + (a[3] * b[1]) + (a[4] * b[0]);
    // clang-format on

    // Carry Propagation
    carry = (unsigned long)(d[0] >> 26);
    a[0]  = (unsigned long)d[0] & 0x3ffffff;
    d[1] += carry;
    carry = (unsigned long)(d[1] >> 26);
    a[1]  = (unsigned long)d[1] & 0x3ffffff;
    d[2] += carry;
    carry = (unsigned long)(d[2] >> 26);
    a[2]  = (unsigned long)d[2] & 0x3ffffff;
    d[3] += carry;
    carry = (unsigned long)(d[3] >> 26);
    a[3]  = (unsigned long)d[3] & 0x3ffffff;
    d[4] += carry;
    carry = (unsigned long)(d[4] >> 26);
    a[4]  = (unsigned long)d[4] & 0x3ffffff;
    a[0] += carry * 5;
    carry = (a[0] >> 26);
    a[0]  = a[0] & 0x3ffffff;
    a[1] += carry;
}

Status
init(const Uint8 key[],           // Input key
     Uint64      keyLen,          // Key Length
     Uint64      accumulator[],   // Output Accumulator
     Uint64      processed_key[], // Output Key
     Uint64      r[10],           // Authentication Key
     Uint64      s[8],            // Addicitive Key
     bool        finalized)              // Finalization indicator
{
    Uint8* p_expanded_key_8 = reinterpret_cast<Uint8*>(processed_key);
    // Uint8* m_acc_8 = reinterpret_cast<Uint8*>(accumulator);
    Status status = StatusOk();
    if (finalized) {
        status.update(status::InternalError("Cannot setKey after finalized!"));
        return status;
    }
    keyLen = keyLen / 8;
    if (keyLen != 32) {
        status.update(status::InvalidArgument("Length does not match"));
        return status;
    }

    // r = k[0..16]
    std::copy(key, key + 16, p_expanded_key_8);

    // s = k[17..32]
    std::copy(key + 16, key + 32, p_expanded_key_8 + 16);

    // r = clamp(r)
    clamp(p_expanded_key_8); // Clamp to polynomial

    // a = 0
    std::fill(accumulator, accumulator + 5, 0);

    // P is already loaded

    // Copy key into 5 limbs
    {
        const Uint8* p_key_8 = reinterpret_cast<const Uint8*>(processed_key);
        // FIXME: Optimize more
        for (int i = 0; i < 5; i++) {
            Uint8* p_r_8 = reinterpret_cast<Uint8*>(&r[i]);
            std::copy(p_key_8, p_key_8 + 4, p_r_8);
            r[i] = r[i] >> (2 * i);
            r[i] &= 0x3ffffff;
            p_key_8 += 3;
        }
    }

    // Precompute the r*5 value
    for (int i = 0; i < 4; i++) {
        s[i] = r[i + 1] * 5;
    }

    // Compute r * r

    std::copy(r, r + 5, r + 5);

    // Precompute r^2 value
    multiply(r + 5, r, s);

    // Precompute (r^2)*5 value
    for (int i = 0; i < 4; i++) {
        s[i + 4] = r[i + 1 + 5] * 5;
    }

    // Compute r^2 * r

    std::copy(r, r + 5, r + 10);

    // Precompute r^3 value
    multiply(r + 10, r + 5, s + 4);

    // Precompute (r^3)*5 value
    for (int i = 0; i < 4; i++) {
        s[i + 8] = r[i + 1 + 10] * 5;
    }

    // Compute r^3 * r

    std::copy(r, r + 5, r + 15);

    // Precompute r^4 value
    multiply(r + 15, r + 10, s + 8);

    // Precompute (r^4)*5 value
    for (int i = 0; i < 4; i++) {
        s[i + 12] = r[i + 1 + 15] * 5;
    }

    // Compute r^4 * r^4

    std::copy(r + 15, r + 20, r + 20);

    // Precompute r^8 value
    multiply(r + 20, r + 15, s + 12);

    // Precompute (r^8)*5 value
    for (int i = 0; i < 4; i++) {
        s[i + 16] = r[i + 1 + 20] * 5;
    }

    return status;
}

Uint64
blk(Uint64      key[],
    const Uint8 pMsg[],
    Uint64      msgLen,
    Uint64      accumulator[],
    Uint64      r[5],
    Uint64      s[4])
{
    __m512i      reg0, reg1, reg2, reg3, reg4; // Multiplication matrix
    Uint64       acc[5]      = {};
    Uint32       msg_temp[5] = {};
    const Uint8* p_msg_8     = pMsg;
    const Uint64 cPadding    = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

#if 1
    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4);
#endif
    // As long as there is poly block size amount of text to process
    while (msgLen > 0) {
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp[i] = (msg_temp[i] >> (2 * i));
            if (i != 4)
                msg_temp[i] &= 0x3ffffff;
            else {
                msg_temp[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        acc[0] += msg_temp[0];
        acc[1] += msg_temp[1];
        acc[2] += msg_temp[2];
        acc[3] += msg_temp[3];
        acc[4] += msg_temp[4];

        // multiply(acc, r, s);
#if 0
        multiply_avx512(acc,r,s);
#else
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);
#endif
        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

// Horner factor 8
Uint64
blkx8_new(Uint64      key[],
          const Uint8 pMsg[],
          Uint64      msgLen,
          Uint64      accumulator[],
          Uint64      r[10],
          Uint64      s[8])
{
    __m512i reg0, reg1, reg2, reg3, reg4;      // R
    __m512i reg10, reg11, reg12, reg13, reg14; // R^2
    __m512i reg20, reg21, reg22, reg23, reg24; // R^3
    __m512i reg30, reg31, reg32, reg33, reg34; // R^4
    __m512i reg40, reg41, reg42, reg43, reg44; // R^8
    bool    fold_needed = false;

    Uint64 acc[5]         = {};
    Uint32 msg_temp_0[5]  = {};
    Uint32 msg_temp_1[35] = {};
    Uint64 msg_temp_2[35] = {};

    const Uint8* p_msg_8  = pMsg;
    const Uint64 cPadding = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

#if 1

    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4); // R
    create_multiplication_matrix(
        r + 5, s + 4, reg10, reg11, reg12, reg13, reg14); // R ^ 2
    create_multiplication_matrix(
        r + 10, s + 8, reg20, reg21, reg22, reg23, reg24); // R ^ 3
    create_multiplication_matrix(
        r + 15, s + 12, reg30, reg31, reg32, reg33, reg34); // R ^ 4
    create_multiplication_matrix(
        r + 20, s + 16, reg40, reg41, reg42, reg43, reg44); // R ^ 8

#endif

#if 1
    // Process 2 blocks at a time
    if (msgLen >= 256) {
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 5
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 15]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 15] = (msg_temp_1[i + 15] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 15] &= 0x3ffffff;
            else {
                msg_temp_1[i + 15] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 6
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 20]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 20] = (msg_temp_1[i + 20] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 20] &= 0x3ffffff;
            else {
                msg_temp_1[i + 20] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 7
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 25]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 25] = (msg_temp_1[i + 25] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 25] &= 0x3ffffff;
            else {
                msg_temp_1[i + 25] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 8
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 30]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 30] = (msg_temp_1[i + 30] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 30] &= 0x3ffffff;
            else {
                msg_temp_1[i + 30] |= cPadding;
            }
            p_msg_8 += 3;
        }

        // Aggregate Accumulator
        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // Minor inconvienence copy
        for (int i = 0; i < 35; i++) {
            msg_temp_2[i] = msg_temp_1[i];
        }

        msgLen -= 128;
        fold_needed = true;
    }
    while (msgLen >= 128 && fold_needed) {
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 5
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 15]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 15] = (msg_temp_1[i + 15] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 15] &= 0x3ffffff;
            else {
                msg_temp_1[i + 15] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 6
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 20]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 20] = (msg_temp_1[i + 20] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 20] &= 0x3ffffff;
            else {
                msg_temp_1[i + 20] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 7
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 25]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 25] = (msg_temp_1[i + 25] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 25] &= 0x3ffffff;
            else {
                msg_temp_1[i + 25] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 8
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 30]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 30] = (msg_temp_1[i + 30] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 30] &= 0x3ffffff;
            else {
                msg_temp_1[i + 30] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        multiply_avx512(acc, reg40, reg41, reg42, reg43, reg44); // m0 * r^8
        multiply_avx512(
            msg_temp_2, reg40, reg41, reg42, reg43, reg44); // m1 * r^8
        multiply_avx512(
            msg_temp_2 + 5, reg40, reg41, reg42, reg43, reg44); // m2 * r^8
        multiply_avx512(
            msg_temp_2 + 10, reg40, reg41, reg42, reg43, reg44); // m3 * r^8
        multiply_avx512(
            msg_temp_2 + 15, reg40, reg41, reg42, reg43, reg44); // m4 * r^8
        multiply_avx512(
            msg_temp_2 + 20, reg40, reg41, reg42, reg43, reg44); // m5 * r^8
        multiply_avx512(
            msg_temp_2 + 25, reg40, reg41, reg42, reg43, reg44); // m6 * r^8
        multiply_avx512(
            msg_temp_2 + 30, reg40, reg41, reg42, reg43, reg44); // m7 * r^8

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // Minor inconvienence copy
        for (int i = 0; i < 35; i++) {
            msg_temp_2[i] += msg_temp_1[i];
        }

        msgLen -= 128;
    }
    if (fold_needed) {
        /*
            (m0*r8 + m1*r7 + m2*r6 + m3*r5 + m4*r4 + m5*r3 + m6*r2 + m7*r)%p
            ((m0*r4 + m4)r4 + (m2*r4 + m5)r3 + ((m3*r4) + m6)r2 + ((m4*r4)+
              m7)r)%p
        */
        multiply_avx512(acc, reg30, reg31, reg32, reg33, reg34); // m0 * r^4
        multiply_avx512(
            msg_temp_2, reg30, reg31, reg32, reg33, reg34); // m1 * r^4
        multiply_avx512(
            msg_temp_2 + 5, reg30, reg31, reg32, reg33, reg34); // m2 * r^4
        multiply_avx512(
            msg_temp_2 + 10, reg30, reg31, reg32, reg33, reg34); // m3 * r^4

        acc[0] += msg_temp_2[15];
        acc[1] += msg_temp_2[16];
        acc[2] += msg_temp_2[17];
        acc[3] += msg_temp_2[18];
        acc[4] += msg_temp_2[19];

        msg_temp_2[0] += msg_temp_2[20];
        msg_temp_2[1] += msg_temp_2[21];
        msg_temp_2[2] += msg_temp_2[22];
        msg_temp_2[3] += msg_temp_2[23];
        msg_temp_2[4] += msg_temp_2[24];

        msg_temp_2[5] += msg_temp_2[25];
        msg_temp_2[6] += msg_temp_2[26];
        msg_temp_2[7] += msg_temp_2[27];
        msg_temp_2[8] += msg_temp_2[28];
        msg_temp_2[9] += msg_temp_2[29];

        msg_temp_2[10] += msg_temp_2[30];
        msg_temp_2[11] += msg_temp_2[31];
        msg_temp_2[12] += msg_temp_2[32];
        msg_temp_2[13] += msg_temp_2[33];
        msg_temp_2[14] += msg_temp_2[34];

        multiply_avx512(acc, reg30, reg31, reg32, reg33, reg34); // m0 * r^4
        multiply_avx512(
            msg_temp_2, reg20, reg21, reg22, reg23, reg24); // m1 * r^3
        multiply_avx512(
            msg_temp_2 + 5, reg10, reg11, reg12, reg13, reg14); // m2 * r^2
        multiply_avx512(
            msg_temp_2 + 10, reg0, reg1, reg2, reg3, reg4); // m3 * r^1

        for (int i = 0; i < 3; i++) {
            acc[0] += msg_temp_2[(i * 5) + 0];
            acc[1] += msg_temp_2[(i * 5) + 1];
            acc[2] += msg_temp_2[(i * 5) + 2];
            acc[3] += msg_temp_2[(i * 5) + 3];
            acc[4] += msg_temp_2[(i * 5) + 4];
        }

        fold_needed = false;
    }
#endif

    // Process 1 Block at a time
    while (msgLen > 0) {

        // Message Extraction block
#if 0
        {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(msg_temp_0);
            for (int i = 0; i < 4; i += 1) {
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));

                msg_temp_0[i] &= 0x3ffffff;

                p_msg_8 += 3;
                p_msg_temp_8 += sizeof(Uint64);
            }
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[4] = (msg_temp_0[4] >> (2 * 4));

            msg_temp_0[4] |= cPadding;

            p_msg_8 += 3;
        }
#else
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
#endif

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r, s);
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

// Horner factor 8
Uint64
blkx8(Uint64      key[],
      const Uint8 pMsg[],
      Uint64      msgLen,
      Uint64      accumulator[],
      Uint64      r[10],
      Uint64      s[8])
{
    __m512i reg0, reg1, reg2, reg3, reg4;      // R
    __m512i reg10, reg11, reg12, reg13, reg14; // R^2
    __m512i reg20, reg21, reg22, reg23, reg24; // R^3
    __m512i reg30, reg31, reg32, reg33, reg34; // R^4

    Uint64 acc[5]         = {};
    Uint32 msg_temp_0[5]  = {};
    Uint32 msg_temp_1[35] = {};
    Uint64 msg_temp_2[35] = {};

    const Uint8* p_msg_8  = pMsg;
    const Uint64 cPadding = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

#if 1

    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4); // R
    create_multiplication_matrix(
        r + 5, s + 4, reg10, reg11, reg12, reg13, reg14); // R ^ 2
    create_multiplication_matrix(
        r + 10, s + 8, reg20, reg21, reg22, reg23, reg24); // R ^ 3
    create_multiplication_matrix(
        r + 15, s + 12, reg30, reg31, reg32, reg33, reg34); // R ^ 4

#endif

#if 17
    // Process 2 blocks at a time
    while (msgLen >= 128) {
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 5
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 15]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 15] = (msg_temp_1[i + 15] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 15] &= 0x3ffffff;
            else {
                msg_temp_1[i + 15] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 6
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 20]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 20] = (msg_temp_1[i + 20] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 20] &= 0x3ffffff;
            else {
                msg_temp_1[i + 20] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 7
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 25]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 25] = (msg_temp_1[i + 25] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 25] &= 0x3ffffff;
            else {
                msg_temp_1[i + 25] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 8
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 30]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 30] = (msg_temp_1[i + 30] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 30] &= 0x3ffffff;
            else {
                msg_temp_1[i + 30] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Minor inconvienence copy
        for (int i = 0; i < 35; i++) {
            msg_temp_2[i] = msg_temp_1[i];
        }

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        multiply_avx512(acc,
                        reg30,
                        reg31,
                        reg32,
                        reg33,
                        reg34); // a = (a + m1)* r^4 -> eqn 1
        multiply_avx512(msg_temp_2,
                        reg30,
                        reg31,
                        reg32,
                        reg33,
                        reg34); // m2 = m2* r^4 -> eqn 2
        multiply_avx512(msg_temp_2 + 5,
                        reg30,
                        reg31,
                        reg32,
                        reg33,
                        reg34); // m3 = m3* r^4 -> eqn 3
        multiply_avx512(msg_temp_2 + 10,
                        reg30,
                        reg31,
                        reg32,
                        reg33,
                        reg34); // m4 = m4* r^4 -> eqn 4

        // a = eqn1 + m5 -> eqn 5
        acc[0] += msg_temp_2[15];
        acc[1] += msg_temp_2[16];
        acc[2] += msg_temp_2[17];
        acc[3] += msg_temp_2[18];
        acc[4] += msg_temp_2[19];

        // m2 = eqn2 + m6 -> eqn 6
        msg_temp_2[0] += msg_temp_2[20];
        msg_temp_2[1] += msg_temp_2[21];
        msg_temp_2[2] += msg_temp_2[22];
        msg_temp_2[3] += msg_temp_2[23];
        msg_temp_2[4] += msg_temp_2[24];

        // m3 = eqn3 + m7 -> eqn 7
        msg_temp_2[5] += msg_temp_2[25];
        msg_temp_2[6] += msg_temp_2[26];
        msg_temp_2[7] += msg_temp_2[27];
        msg_temp_2[8] += msg_temp_2[28];
        msg_temp_2[9] += msg_temp_2[29];

        // m4 = eqn4 + m8 -> eqn 8
        msg_temp_2[10] += msg_temp_2[30];
        msg_temp_2[11] += msg_temp_2[31];
        msg_temp_2[12] += msg_temp_2[32];
        msg_temp_2[13] += msg_temp_2[33];
        msg_temp_2[14] += msg_temp_2[34];

        multiply_avx512(acc,
                        reg30,
                        reg31,
                        reg32,
                        reg33,
                        reg34); // a = eqn5 * r^4 -> eqn 9

        multiply_avx512(msg_temp_2,
                        reg20,
                        reg21,
                        reg22,
                        reg23,
                        reg24); // m2 = eqn6 * r^3 -> eqn 10

        multiply_avx512(msg_temp_2 + 5,
                        reg10,
                        reg11,
                        reg12,
                        reg13,
                        reg14); // m2 = eqn7 * r^2 -> eqn 11

        multiply_avx512(msg_temp_2 + 10,
                        reg0,
                        reg1,
                        reg2,
                        reg3,
                        reg4); // m3 = eqn8 * r -> eqn 12

        // a = eqn9 + eqn 10 -> eqn 13
        acc[0] += msg_temp_2[0];
        acc[1] += msg_temp_2[1];
        acc[2] += msg_temp_2[2];
        acc[3] += msg_temp_2[3];
        acc[4] += msg_temp_2[4];

        // m2 = eqn11 + eqn 12 -> eqn 14
        msg_temp_2[5] += msg_temp_2[10];
        msg_temp_2[6] += msg_temp_2[11];
        msg_temp_2[7] += msg_temp_2[12];
        msg_temp_2[8] += msg_temp_2[13];
        msg_temp_2[9] += msg_temp_2[14];

        // a = eqn13 + eqn 14 -> eqn 13
        acc[0] += msg_temp_2[5];
        acc[1] += msg_temp_2[6];
        acc[2] += msg_temp_2[7];
        acc[3] += msg_temp_2[8];
        acc[4] += msg_temp_2[9];

        msgLen -= 128;
    }
#endif

    // Process 1 Block at a time
    while (msgLen > 0) {

        // Message Extraction block
#if 0
        {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(msg_temp_0);
            for (int i = 0; i < 4; i += 1) {
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));

                msg_temp_0[i] &= 0x3ffffff;

                p_msg_8 += 3;
                p_msg_temp_8 += sizeof(Uint64);
            }
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[4] = (msg_temp_0[4] >> (2 * 4));

            msg_temp_0[4] |= cPadding;

            p_msg_8 += 3;
        }
#else
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
#endif

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r, s);
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

// Horner factor 2
Uint64
blkx4_new(Uint64      key[],
          const Uint8 pMsg[],
          Uint64      msgLen,
          Uint64      accumulator[],
          Uint64      r[10],
          Uint64      s[8])
{
    __m512i reg0, reg1, reg2, reg3, reg4;      // r
    __m512i reg10, reg11, reg12, reg13, reg14; // r ^ 2
    __m512i reg20, reg21, reg22, reg23, reg24; // r ^ 3
    __m512i reg30, reg31, reg32, reg33, reg34; // r ^ 4

    Uint64 acc[5]         = {};
    Uint32 msg_temp_0[5]  = {};
    Uint32 msg_temp_1[15] = {};
    Uint64 msg_temp_2[15] = {};
    bool   fold_needed    = false;

    const Uint8* p_msg_8  = pMsg;
    const Uint64 cPadding = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

    // r[0:5] <= r; r[5:10] <= r**2
    // s[0:4] <= r[1:5]*5; s[4:8] <= r[6:10]*5
    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4); // R
    create_multiplication_matrix(
        r + 5, s + 4, reg10, reg11, reg12, reg13, reg14); // R ^ 2
    create_multiplication_matrix(
        r + 10, s + 8, reg20, reg21, reg22, reg23, reg24); // R ^ 3
    create_multiplication_matrix(
        r + 15, s + 12, reg30, reg31, reg32, reg33, reg34); // R ^ 4

#if 1
    if (msgLen >= 128) {
        // debug_print("HERE!");
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Aggregate Accumulator
        for (int i = 0; i < 5; i++) {
            acc[i] += msg_temp_0[i];
        }

        for (int i = 0; i < 15; i++) {
            msg_temp_2[i] = msg_temp_1[i];
        }
        msgLen -= 64;
        fold_needed = true;
    }
    // Process 2 blocks at a time
    while (msgLen >= 64 && fold_needed) {
        // debug_print("HERE!");
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // multiply(acc, r + 5, s + 4);
        multiply_avx512(acc, reg30, reg31, reg32, reg33, reg34); // m0 * r^4
        // multiply(msg_temp_2, r + 5, s + 4);
        multiply_avx512(
            msg_temp_2, reg30, reg31, reg32, reg33, reg34); // m1 * r^4

        multiply_avx512(
            msg_temp_2 + 5, reg30, reg31, reg32, reg33, reg34); // m2 * r^4

        multiply_avx512(
            msg_temp_2 + 10, reg30, reg31, reg32, reg33, reg34); // m3 * r^4

        // Aggregate Accumulator
        for (int i = 0; i < 5; i++) {
            acc[i] += msg_temp_0[i];
        }

        for (int i = 0; i < 15; i++) {
            msg_temp_2[i] += msg_temp_1[i];
        }

        msgLen -= 64;
    }
    if (fold_needed) {

        // multiply(acc, r + 5, s + 4);
        multiply_avx512(acc, reg30, reg31, reg32, reg33, reg34); // m0 * r^4
        // multiply(msg_temp_2, r + 5, s + 4);
        multiply_avx512(
            msg_temp_2, reg20, reg21, reg22, reg23, reg24); // m1 * r^3

        multiply_avx512(
            msg_temp_2 + 5, reg10, reg11, reg12, reg13, reg14); // m2 * r^2

        multiply_avx512(
            msg_temp_2 + 10, reg0, reg1, reg2, reg3, reg4); // m3 * r^1

        // Fold into acc
        for (int i = 0; i < 3; i++) {
            acc[0] += msg_temp_2[(i * 5) + 0];
            acc[1] += msg_temp_2[(i * 5) + 1];
            acc[2] += msg_temp_2[(i * 5) + 2];
            acc[3] += msg_temp_2[(i * 5) + 3];
            acc[4] += msg_temp_2[(i * 5) + 4];
        }

        fold_needed = false;
    }
#endif

    // Process 1 Block at a time
    while (msgLen > 0) {
        // Message Extraction block
        {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(msg_temp_0);
            for (int i = 0; i < 4; i += 1) {
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));

                msg_temp_0[i] &= 0x3ffffff;

                p_msg_8 += 3;
                p_msg_temp_8 += sizeof(Uint32);
            }
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[4] = (msg_temp_0[4] >> (2 * 4));

            msg_temp_0[4] |= cPadding;

            p_msg_8 += 3;
        }

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r, s);
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

// Horner factor 2
Uint64
blkx4(Uint64      key[],
      const Uint8 pMsg[],
      Uint64      msgLen,
      Uint64      accumulator[],
      Uint64      r[10],
      Uint64      s[8])
{
    __m512i reg0, reg1, reg2, reg3, reg4;
    __m512i reg10, reg11, reg12, reg13, reg14;

    Uint64 acc[5]         = {};
    Uint32 msg_temp_0[5]  = {};
    Uint32 msg_temp_1[15] = {};
    Uint64 msg_temp_2[15] = {};

    const Uint8* p_msg_8  = pMsg;
    const Uint64 cPadding = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

    // r[0:5] <= r; r[5:10] <= r**2
    // s[0:4] <= r[1:5]*5; s[4:8] <= r[6:10]*5
    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4);
    create_multiplication_matrix(
        r + 5, s + 4, reg10, reg11, reg12, reg13, reg14);

#if 1
    // Process 2 blocks at a time
    while (msgLen >= 64) {
        // debug_print("HERE!");
        // Message 1
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 2
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 3
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 5]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 5] = (msg_temp_1[i + 5] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 5] &= 0x3ffffff;
            else {
                msg_temp_1[i + 5] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // Message 4
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i + 10]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i + 10] = (msg_temp_1[i + 10] >> (2 * i));
            if (i != 4)
                msg_temp_1[i + 10] &= 0x3ffffff;
            else {
                msg_temp_1[i + 10] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // FIXME: Find better way without hurting performance
        // Minor inconvienence copy
        for (int i = 0; i < 15; i++) {
            msg_temp_2[i] = msg_temp_1[i];
        }

        // ((m0+a0) * r**2 + m1*r) % p
        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r + 5, s + 4);
        multiply_avx512(acc, reg10, reg11, reg12, reg13, reg14); // a * r^2
        // multiply(msg_temp_2, r + 5, s + 4);
        multiply_avx512(
            msg_temp_2, reg10, reg11, reg12, reg13, reg14); // m1 * r^2

        // a += m2
        acc[0] += msg_temp_2[5];
        acc[1] += msg_temp_2[6];
        acc[2] += msg_temp_2[7];
        acc[3] += msg_temp_2[8];
        acc[4] += msg_temp_2[9];

        // multiply(acc, r + 5, s + 4);
        multiply_avx512(acc, reg10, reg11, reg12, reg13, reg14); // a * r^2

        // m1 += m3
        msg_temp_2[0] += msg_temp_2[10];
        msg_temp_2[1] += msg_temp_2[11];
        msg_temp_2[2] += msg_temp_2[12];
        msg_temp_2[3] += msg_temp_2[13];
        msg_temp_2[4] += msg_temp_2[14];

        multiply_avx512(msg_temp_2, reg0, reg1, reg2, reg3, reg4); // m1 * r
        // multiply(msg_temp_2, r, s);

        // a += m1
        acc[0] += msg_temp_2[0];
        acc[1] += msg_temp_2[1];
        acc[2] += msg_temp_2[2];
        acc[3] += msg_temp_2[3];
        acc[4] += msg_temp_2[4];

        msgLen -= 64;
    }
#endif

    // Process 1 Block at a time
    while (msgLen > 0) {

        // Message Extraction block
        {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(msg_temp_0);
            for (int i = 0; i < 4; i += 1) {
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));

                msg_temp_0[i] &= 0x3ffffff;

                p_msg_8 += 3;
                p_msg_temp_8 += sizeof(Uint32);
            }
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[4] = (msg_temp_0[4] >> (2 * 4));

            msg_temp_0[4] |= cPadding;

            p_msg_8 += 3;
        }

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r, s);
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

// Horner factor 2
Uint64
blkx2(Uint64      key[],
      const Uint8 pMsg[],
      Uint64      msgLen,
      Uint64      accumulator[],
      Uint64      r[10],
      Uint64      s[8])
{
    __m512i reg0, reg1, reg2, reg3, reg4;
    __m512i reg10, reg11, reg12, reg13, reg14;

    Uint64 acc[5]        = {};
    Uint32 msg_temp_0[5] = {};
    Uint32 msg_temp_1[5] = {};
    Uint64 msg_temp_2[5] = {};

    const Uint8* p_msg_8  = pMsg;
    const Uint64 cPadding = (msgLen >= 16) << 24;

    // Copy Accumulator into local variable
    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

    // r[0:5] <= r; r[5:10] <= r**2
    // s[0:4] <= r[1:5]*5; s[4:8] <= r[6:10]*5
    create_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4);
    create_multiplication_matrix(
        r + 5, s + 4, reg10, reg11, reg12, reg13, reg14);

#if 1
    // Process 2 blocks at a time
    while (msgLen >= 32) {
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_0[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));
            if (i != 4)
                msg_temp_0[i] &= 0x3ffffff;
            else {
                msg_temp_0[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp_1[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_1[i] = (msg_temp_1[i] >> (2 * i));
            if (i != 4)
                msg_temp_1[i] &= 0x3ffffff;
            else {
                msg_temp_1[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        p_msg_8 += 1;

        // FIXME: Find better way without hurting performance
        // Minor inconvienence copy
        for (int i = 0; i < 5; i++) {
            msg_temp_2[i] = msg_temp_1[i];
        }

        // ((m0+a0) * r**2 + m1*r) % p
        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        multiply_avx512(acc, reg10, reg11, reg12, reg13, reg14);
        multiply_avx512(msg_temp_2, reg0, reg1, reg2, reg3, reg4);

        acc[0] += msg_temp_2[0];
        acc[1] += msg_temp_2[1];
        acc[2] += msg_temp_2[2];
        acc[3] += msg_temp_2[3];
        acc[4] += msg_temp_2[4];

        msgLen -= 32;
    }
#endif

    // Process 1 Block at a time
    while (msgLen > 0) {

        // Message Extraction block
        {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(msg_temp_0);
            for (int i = 0; i < 4; i += 1) {
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp_0[i] = (msg_temp_0[i] >> (2 * i));

                msg_temp_0[i] &= 0x3ffffff;

                p_msg_8 += 3;
                p_msg_temp_8 += sizeof(Uint32);
            }
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp_0[4] = (msg_temp_0[4] >> (2 * 4));

            msg_temp_0[4] |= cPadding;

            p_msg_8 += 3;
        }

        acc[0] += msg_temp_0[0];
        acc[1] += msg_temp_0[1];
        acc[2] += msg_temp_0[2];
        acc[3] += msg_temp_0[3];
        acc[4] += msg_temp_0[4];

        // multiply(acc, r, s);
        multiply_avx512(acc, reg0, reg1, reg2, reg3, reg4);

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    return msgLen;
}

Status
update(Uint64      key[],
       const Uint8 pMsg[],
       Uint64      msgLen,
       Uint64      accumulator[],
       Uint8       msg_buffer[16],
       Uint64&     msg_buffer_len,
       Uint64      r[10],
       Uint64      s[8],
       bool        finalized)
{
    // debug_print("Here");
    Status status = StatusOk();

    if (finalized) {
        status.update(status::InternalError("Cannot update after finalized!"));
        return status;
    }

    if (msg_buffer_len != 0) {
        // We need to process the msg_buffer first
        Uint64 msg_buffer_left = (16 - msg_buffer_len);
        if (msgLen < msg_buffer_left) {
            std::copy(pMsg, pMsg + msgLen, msg_buffer + msg_buffer_len);
            msg_buffer_len += msgLen;
            // We ran out of the buffer to read
            return status;
        }
        std::copy(pMsg, pMsg + msg_buffer_left, msg_buffer + msg_buffer_len);

        pMsg += msg_buffer_left;
        msgLen -= msg_buffer_left;

        msg_buffer_len = 0;
        // blk(key, msg_buffer, 16, accumulator, r, s);
        // blkx2(key, msg_buffer, 16, accumulator, r, s);
        // blkx4(key, msg_buffer, 16, accumulator, r, s);
        blkx4_new(key, msg_buffer, 16, accumulator, r, s);
        // blkx8(key, msg_buffer, 16, accumulator, r, s);
        // blkx8_new(key, msg_buffer, 16, accumulator, r, s);
    }

    Uint64 overflow = msgLen % 16;

    // blk(key, pMsg, msgLen - overflow, accumulator, r, s);
    // blkx2(key, pMsg, msgLen - overflow, accumulator, r, s);
    // blkx4(key, pMsg, msgLen - overflow, accumulator, r, s);
    blkx4_new(key, pMsg, msgLen - overflow, accumulator, r, s);
    // blkx8(key, pMsg, msgLen - overflow, accumulator, r, s);
    // blkx8_new(key, pMsg, msgLen - overflow, accumulator, r, s);
    if (overflow) {
        std::copy(pMsg + msgLen - overflow, pMsg + msgLen, msg_buffer);
        msg_buffer_len = overflow;
    }

    return status;
}

Status
finish(Uint64      key[],
       const Uint8 pMsg[],
       Uint64      msgLen,
       Uint64      accumulator[],
       Uint8       msg_buffer[16],
       Uint64&     msg_buffer_len,
       Uint64      r[10],
       Uint64      s[8],
       bool&       finalized)
{
    Status status = StatusOk();
    if (finalized) {
        status.update(status::InternalError("Cannot update after finalized!"));
        return status;
    }

    if (msgLen) {
        // s.update(update(pMsg, msgLen));
        status.update(update(key,
                             pMsg,
                             msgLen,
                             accumulator,
                             msg_buffer,
                             msg_buffer_len,
                             r,
                             s,
                             finalized));
    }

    if (msg_buffer_len) {
        msg_buffer[msg_buffer_len] = 0x01;
        std::fill(msg_buffer + msg_buffer_len + 1, msg_buffer + 16, 0);
        // blk(msg_buffer, msg_buffer_len);
        blk(key, msg_buffer, msg_buffer_len, accumulator, r, s);
        // update(msg_buffer, msg_buffer_len);
    }

    Uint64        acc[5]  = {};
    Uint64        temp[5] = {};
    Uint64        f;
    Uint64        carry;
    const Uint32* p_key_32 = reinterpret_cast<Uint32*>(key);

    for (int i = 0; i < 5; i++) {
        acc[i] = accumulator[i];
    }

    // Propagate carry from 1 to finish carry propation of addition
    carry  = acc[1] >> 26;
    acc[1] = acc[1] & 0x3ffffff;
    acc[2] += carry;
    carry  = acc[2] >> 26;
    acc[2] = acc[2] & 0x3ffffff;
    acc[3] += carry;
    carry  = acc[3] >> 26;
    acc[3] = acc[3] & 0x3ffffff;
    acc[4] += carry;
    carry  = acc[4] >> 26;
    acc[4] = acc[4] & 0x3ffffff;
    acc[0] += carry * 5;
    carry  = acc[0] >> 26;
    acc[0] = acc[0] & 0x3ffffff;
    acc[1] += carry;

    // acc -= (1<<130 -5) -> acc = acc - 1<<130 + 5
    // (1<<130-5) + 5 => (1<<130)
    temp[0] = acc[0] + 5;
    carry   = temp[0] >> 26;
    temp[0] &= 0x3ffffff;
    temp[1] = acc[1] + carry;
    carry   = temp[1] >> 26;
    temp[1] &= 0x3ffffff;
    temp[2] = acc[2] + carry;
    carry   = temp[2] >> 26;
    temp[2] &= 0x3ffffff;
    temp[3] = acc[3] + carry;
    carry   = temp[3] >> 26;
    temp[3] &= 0x3ffffff;
    // acc-(1<<130)
    temp[4] = acc[4] + carry - (1UL << 26);

    if ((temp[4] >> 63) == 0) {
        for (int i = 0; i < 5; i++) {
            acc[i] = temp[i];
        }
    }

    acc[0] = ((acc[0]) | (acc[1] << 26)) & 0xffffffff;
    acc[1] = ((acc[1] >> 6) | (acc[2] << 20)) & 0xffffffff;
    acc[2] = ((acc[2] >> 12) | (acc[3] << 14)) & 0xffffffff;
    acc[3] = ((acc[3] >> 18) | (acc[4] << 8)) & 0xffffffff;

    // digest = acc + s;
    f      = acc[0] + p_key_32[4];
    acc[0] = f;
    f      = acc[1] + p_key_32[5] + (f >> 32);
    acc[1] = f;
    f      = acc[2] + p_key_32[6] + (f >> 32);
    acc[2] = f;
    f      = acc[3] + p_key_32[7] + (f >> 32);
    acc[3] = f;

    for (int i = 0; i < 5; i++) {
        accumulator[i] = acc[i];
    }

    finalized = true;

    return status;
}

Status
copy(Uint8 digest[], Uint64 len, Uint64 accumulator[], bool m_finalized)
{
    Status s = StatusOk();
    if (!m_finalized) {
        s.update(status::InternalError("Not finalized yet!"));
        return s;
    }
    if (len != 16) {
        s.update(status::InvalidArgument("Invalid Size for Poly1305"));
        return s;
    }

    const Uint8* p_accumulator_8 = reinterpret_cast<Uint8*>(accumulator);

    std::copy(p_accumulator_8, p_accumulator_8 + 4, digest);
    std::copy(p_accumulator_8 + 8, p_accumulator_8 + 12, digest + 4);
    std::copy(p_accumulator_8 + 16, p_accumulator_8 + 20, digest + 8);
    std::copy(p_accumulator_8 + 24, p_accumulator_8 + 28, digest + 12);

    return s;
}

// Radix44 Implementation

void
new_new_multiply(Uint64 a[3], Uint64 r[3], Uint64 s[2])
{
    /*
        d0 = a0r0 + a1s2 + a2s1
        d1 = a0r1 + a1r0 + a2s2
        d2 = a0r2 + a1r1 + a2r0

        reg0 = r0, r1, r2,..... * a0
        reg1 = s2, r0, r1...... * a1
        reg2 = s1, s2, r0...... * a2

        reg0 + reg1 + reg2 = {d0, d1, d2,....}
    */
    // Load r
    __m512i r_reg = _mm512_maskz_loadu_epi64(0x07, r);
    // Load s
    __m512i s_reg = _mm512_maskz_loadu_epi64(0x03, s);
    // Reg0 is same as r_reg
    __m512i reg0 = r_reg;
    // Permute using _mm512_mask_permutex2var_epi64 to generate reg1 from r_reg
    // and s_reg
    __m512i idx  = _mm512_setr_epi64(1 << 3 | 1, 0, 1, 6, 6, 6, 6, 6);
    __m512i reg1 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    // Permute using _mm512_mask_permutex2var_epi64 to generate reg2 from r_reg
    // and s_reg
    idx          = _mm512_setr_epi64(1 << 3 | 0, 1 << 3 | 1, 0, 6, 6, 6, 6, 6);
    __m512i reg2 = _mm512_mask_permutex2var_epi64(r_reg, 0xFF, idx, s_reg);
    // Broadcast a[0] to a 512 bit register
    __m512i regtemp = _mm512_set1_epi64(a[0]);
    // Multiply using _mm512_madd52hi_epu64 and _mm512_madd52lo_epu64 instuction
    // with r_reg with reg0 and save it to t_reg1_lo and t_reg1_hi
    __m512i t_reg1_lo =
        _mm512_madd52lo_epu64(_mm512_setzero_si512(), regtemp, reg0);
    __m512i t_reg1_hi =
        _mm512_madd52hi_epu64(_mm512_setzero_si512(), regtemp, reg0);
    // Broadcast a[1] to a 512 bit register
    regtemp = _mm512_set1_epi64(a[1]);
    // Multiply using _mm512_madd52hi_epu64 and _mm512_madd52lo_epu64 instuction
    // with r_reg with reg1 and save it to t_reg2_lo and t_reg2_hi
    __m512i t_reg2_lo = _mm512_madd52lo_epu64(t_reg1_lo, regtemp, reg1);
    __m512i t_reg2_hi = _mm512_madd52hi_epu64(t_reg1_hi, regtemp, reg1);
    // Broadcast a[2] to a 512 bit register
    regtemp = _mm512_set1_epi64(a[2]);
    // Multiply using _mm512_madd52hi_epu64 and _mm512_madd52lo_epu64 instuction
    // with r_reg with reg2 and save it to t_reg3_lo and t_reg3_hi
    t_reg1_lo = _mm512_madd52lo_epu64(t_reg2_lo, regtemp, reg2);
    t_reg1_hi = _mm512_madd52hi_epu64(t_reg2_hi, regtemp, reg2);

    // Carry propagation
    // Store t_reg1_lo and t_reg1_hi to temp
    // At this point in time we have t_reg1_lo, t_reg1_hi which contains
    // d0,d1,d2. Shift t_reg1_lo by 44 bits to the right and save it to regtemp
    idx     = _mm512_setr_epi64(44, 44, 42, 0, 0, 0, 0, 0);
    regtemp = _mm512_srlv_epi64(t_reg1_lo, idx); // High bits
    // Shift t_reg1_hi by 8 bits to the left and do an "or" with regtemp and
    // save it to t_reg1_hi
    idx       = _mm512_setr_epi64(8, 8, 10, 0, 0, 0, 0, 0);
    t_reg1_hi = _mm512_sllv_epi64(t_reg1_hi, idx);
    t_reg1_hi = _mm512_or_epi64(t_reg1_hi, regtemp);
    // Truncate t_reg1_lo to 44 bits and save it to t_reg1_lo
    idx = _mm512_setr_epi64(
        0xfffffffffff, 0xfffffffffff, 0x3ffffffffff, 0, 0, 0, 0, 0);
    t_reg1_lo = _mm512_and_epi64(t_reg1_lo, idx);
    // Shuffle t_reg1_hi from (0,1,2,3,4,5,6,7) to (6,0,1,2,6,6,6,6) and save it
    // to regtemp
    idx       = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp   = _mm512_permutexvar_epi64(idx, t_reg1_hi);
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 should be 44 bits, but d1 and d2 can be more than 44 bits

    // Mask 0xfffff00000000000,0xfffff00000000000,0xfffffc0000000000,0,0,0,0,0;
    // to regtemp
    //      d0                  d1                 d2               , excess
    regtemp = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);
    // Compute carry regtemp = regtemp and t_reg1_lo
    regtemp = _mm512_and_epi64(regtemp, t_reg1_lo);
    // Shuffle regtemp from (0,1,2,3,4,5,6,7) to (6,0,1,2,6,6,6,6) and save it
    // to regtemp
    idx     = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp = _mm512_permutexvar_epi64(idx, regtemp);
    // Add regtemp and t_reg1_lo and save it to t_reg1_lo
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 and d1 should be 44 bits, d2 can be more than 44 bits

    // Mask 0xfffff00000000000,0xfffff00000000000,0xfffffc0000000000,0,0,0,0,0;
    // to regtemp
    //      d0                  d1                 d2               , excess
    regtemp = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);
    // Compute carry regtemp = regtemp and t_reg1_lo
    regtemp = _mm512_and_epi64(regtemp, t_reg1_lo);
    // Shuffle regtemp from (0,1,2,3,4,5,6,7) to (6,0,1,2,6,6,6,6) and save it
    // to regtemp
    idx     = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp = _mm512_permutexvar_epi64(idx, regtemp);
    // Add regtemp and t_reg1_lo and save it to t_reg1_lo
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // Only excess is left to be processed
    // Take excess out of t_reg1_lo and save it to regtemp, to do that we need
    // to shuffle t_reg1_lo from (0,1,2,3,4,5,6,7) to (3,6,6,6,6,6,6,6)
    idx     = _mm512_setr_epi64(3, 6, 6, 6, 6, 6, 6, 6);
    regtemp = _mm512_permutexvar_epi64(idx, t_reg1_lo);
    // Multiply excess with 5 and save it to regtemp
    regtemp = _mm512_mullo_epi64(regtemp, _mm512_set1_epi64(5)); // Modulo Trick
    // Add excess to t_reg1_lo and save it to t_reg1_lo
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // Carry propagate
    // Mask 0xfffff00000000000,0xfffff00000000000,0xfffffc0000000000,0,0,0,0,0;
    // to regtemp
    //      d0                  d1                 d2               , excess
    regtemp = _mm512_set_epi64(0xfffff00000000000UL,
                               0xfffff00000000000UL,
                               0xfffffc0000000000UL,
                               0,
                               0,
                               0,
                               0,
                               0);
    // Compute carry regtemp = regtemp and t_reg1_lo
    regtemp = _mm512_and_epi64(regtemp, t_reg1_lo);
    // Shuffle regtemp from (0,1,2,3,4,5,6,7) to (6,0,1,2,6,6,6,6) and save it
    // to regtemp
    idx     = _mm512_setr_epi64(6, 0, 1, 2, 6, 6, 6, 6);
    regtemp = _mm512_permutexvar_epi64(idx, regtemp);
    // Add regtemp and t_reg1_lo and save it to t_reg1_lo
    t_reg1_lo = _mm512_add_epi64(t_reg1_lo, regtemp);

    // d0 should be 44 bits, but d1 and d2 can be more than 44 bits
    // Stopping carry propagation here for now.

    // Masked store first 3 values of t_reg1_lo to a
    _mm512_mask_storeu_epi64(a, 0x7, t_reg1_lo);
}

int
loadx1_message_radix44_avx512(const Uint8* p_msg,
                              __m512i&     m0,
                              __m512i&     m1,
                              __m512i&     m2)
{
    // Load 128 bits from p_msg into m0 using _mm512_maskz_loadu_epi64
    m0 = _mm512_maskz_loadu_epi64(0x03, p_msg);
    // Unpack 64 bit integers from m0 and m1 and save it to m0 and m1
    m1 = _mm512_unpackhi_epi64(m0, m0);
    m0 = _mm512_unpacklo_epi64(m0, m0);
    // Radix first value calculation
    // Truncate to 44 bits
    __m512i lo_masked = _mm512_and_epi64(m0, _mm512_set1_epi64(0xfffffffffff));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    __m512i lo_shifted = _mm512_srlv_epi64(m0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    __m512i hi_shifted = _mm512_sllv_epi64(m1, _mm512_set1_epi64(20));
    // Or lo_shifted and hi_shifted and save it to lo_or
    __m512i lo_or = _mm512_or_epi64(lo_shifted, hi_shifted);
    // Truncate to 44 bits
    lo_or = _mm512_and_epi64(lo_or, _mm512_set1_epi64(0xfffffffffff));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    __m512i hi_shifted_40 = _mm512_srlv_epi64(m1, _mm512_set1_epi64(24));
    // Truncate to 42 bits
    hi_shifted_40 =
        _mm512_and_epi64(hi_shifted_40, _mm512_set1_epi64(0x3ffffffffff));

    hi_shifted_40 =
        _mm512_or_epi64(hi_shifted_40, _mm512_set1_epi64(1UL << 40));

    m0 = lo_masked;
    m1 = lo_or;
    m2 = hi_shifted_40;
    return 128;
}

int
loadx1_message_radix44_nopad_avx512(const Uint8* p_msg,
                                    __m512i&     m0,
                                    __m512i&     m1,
                                    __m512i&     m2)
{
    // Load 128 bits from p_msg into m0 using _mm512_maskz_loadu_epi64
    m0 = _mm512_maskz_loadu_epi64(0x03, p_msg);
    // Unpack 64 bit integers from m0 and m1 and save it to m0 and m1
    m1 = _mm512_unpackhi_epi64(m0, m0);
    m0 = _mm512_unpacklo_epi64(m0, m0);
    // Radix first value calculation
    // Truncate to 44 bits
    __m512i lo_masked = _mm512_and_epi64(m0, _mm512_set1_epi64(0xfffffffffff));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    __m512i lo_shifted = _mm512_srlv_epi64(m0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    __m512i hi_shifted = _mm512_sllv_epi64(m1, _mm512_set1_epi64(20));
    // Or lo_shifted and hi_shifted and save it to lo_or
    __m512i lo_or = _mm512_or_epi64(lo_shifted, hi_shifted);
    // Truncate to 44 bits
    lo_or = _mm512_and_epi64(lo_or, _mm512_set1_epi64(0xfffffffffff));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    __m512i hi_shifted_40 = _mm512_srlv_epi64(m1, _mm512_set1_epi64(24));
    // Truncate to 42 bits
    hi_shifted_40 =
        _mm512_and_epi64(hi_shifted_40, _mm512_set1_epi64(0x3ffffffffff));

    m0 = lo_masked;
    m1 = lo_or;
    m2 = hi_shifted_40;
    return 128;
}

inline int
loadx8_message_radix44_avx512(const Uint8* p_msg,
                              __m512i&     m0,
                              __m512i&     m1,
                              __m512i&     m2)
{
    __m512i temp0, temp1, temp2, temp3;
    // Load 512 bits from p_msg into m0 and m1 using _mm512_loadu_si512
    m0 = _mm512_loadu_si512(p_msg);
    m1 = _mm512_loadu_si512(p_msg + 64);

    // Unpack 64 bit integers from m0 and m1 and save it to temp0 and temp1
    temp0 = _mm512_unpacklo_epi64(m0, m1);
    temp1 = _mm512_unpackhi_epi64(m0, m1);

    // Radix first value calculation
    // Truncate to 44 bits
    m0 = _mm512_and_epi64(temp0, _mm512_set1_epi64(0xfffffffffff));
    // Radix second value calculation
    // Take out 44 bits which has been consumed by 1st part of radix
    temp2 = _mm512_srlv_epi64(temp0, _mm512_set1_epi64(44));
    // Make space for 20 bits from lo, which combined with 24 bits from hi will
    // make 44 bits
    temp3 = _mm512_sllv_epi64(temp1, _mm512_set1_epi64(20));
    // Or temp2 and temp3 to create radix second value
    temp2 = _mm512_or_epi64(temp2, temp3);
    // Truncate to 44 bits
    m1 = _mm512_and_epi64(temp2, _mm512_set1_epi64(0xfffffffffff));
    // Shift hi by 24 bits to the right, 24 bits has been consumed by 2nd part
    // of radix
    temp3 = _mm512_srlv_epi64(temp1, _mm512_set1_epi64(24));
    // Truncate to 44 bits
    m2 = _mm512_and_epi64(temp3, _mm512_set1_epi64(0xfffffffffff));
    m2 = _mm512_or_epi64(m2, _mm512_set1_epi64(1UL << 40));

    return 512;
}

// Function to broadcast r value to reg0, reg1, reg2 which are 512 bit registers
void
broadcast_r(const Uint64 r[3], __m512i& reg0, __m512i& reg1, __m512i& reg2)
{
    // Broadcast r[0] to reg0
    reg0 = _mm512_set1_epi64(r[0]);
    // Broadcast r[1] to reg1
    reg1 = _mm512_set1_epi64(r[1]);
    // Broadcast r[2] to reg2
    reg2 = _mm512_set1_epi64(r[2]);
}

inline void
poly1305_calculate_modulo_trick_value(const __m512i reg1,
                                      const __m512i reg2,
                                      __m512i&      sreg1,
                                      __m512i&      sreg2)
{
    // Calculate sreg1 and sreg2 using modulo trick
    // sreg1 = reg1 * 5 * 4
    sreg1 = _mm512_mullo_epi64(reg1, _mm512_set1_epi64(5 * 4));
    // sreg2 = reg2 * 5 * 4
    sreg2 = _mm512_mullo_epi64(reg2, _mm512_set1_epi64(5 * 4));
}

inline void
multiplyx8_radix44_avx512(__m512i& a0,
                          __m512i& a1,
                          __m512i& a2,
                          __m512i  r0,
                          __m512i  r1,
                          __m512i  r2,
                          __m512i  s1,
                          __m512i  s2)
{
    // Multiply
    __m512i extra;
    __m512i d0l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r0);
    __m512i d0h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r0);
    __m512i d1l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r1);
    __m512i d1h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r1);
    __m512i d2l = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a0, r2);
    __m512i d2h = _mm512_madd52hi_epu64(_mm512_setzero_si512(), a0, r2);

    d0l = _mm512_madd52lo_epu64(d0l, a1, s2);
    d0h = _mm512_madd52hi_epu64(d0h, a1, s2);
    d1l = _mm512_madd52lo_epu64(d1l, a1, r0);
    d1h = _mm512_madd52hi_epu64(d1h, a1, r0);
    d2l = _mm512_madd52lo_epu64(d2l, a1, r1);
    d2h = _mm512_madd52hi_epu64(d2h, a1, r1);

    d0l = _mm512_madd52lo_epu64(d0l, a2, s1);
    d0h = _mm512_madd52hi_epu64(d0h, a2, s1);
    d1l = _mm512_madd52lo_epu64(d1l, a2, s2);
    d1h = _mm512_madd52hi_epu64(d1h, a2, s2);
    d2l = _mm512_madd52lo_epu64(d2l, a2, r0);
    d2h = _mm512_madd52hi_epu64(d2h, a2, r0);

    // Bit Adjust
    extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(0xfffffffffff));
    d0h   = _mm512_sllv_epi64(d0h, _mm512_set1_epi64(8));
    d0h   = _mm512_add_epi64(d0h, extra);

    extra = _mm512_srlv_epi64(d1l, _mm512_set1_epi64(44));
    d1l   = _mm512_and_epi64(d1l, _mm512_set1_epi64(0xfffffffffff));
    d1h   = _mm512_sllv_epi64(d1h, _mm512_set1_epi64(8));
    d1h   = _mm512_add_epi64(d1h, extra);

    extra = _mm512_srlv_epi64(d2l, _mm512_set1_epi64(42));
    d2l   = _mm512_and_epi64(d2l, _mm512_set1_epi64(0x3ffffffffff));
    d2h   = _mm512_sllv_epi64(d2h, _mm512_set1_epi64(10));
    d2h   = _mm512_add_epi64(d2h, extra);

    d1l = _mm512_add_epi64(d0h, d1l);
    d2l = _mm512_add_epi64(d1h, d2l);

// Optimization value *=5 can be writen as value = (value * 4 + value)
#if 1
    extra = _mm512_sllv_epi64(d2h, _mm512_set1_epi64(2));
    d2h   = _mm512_add_epi64(extra, d2h);
    d0l   = _mm512_add_epi64(d2h, d0l);
#else
    d0l = _mm512_add_epi64(_mm512_mullo_epi64(d2h, _mm512_set1_epi64(5)), d0l);
#endif

    // Propagrate carry
    extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(0xfffffffffff));
    d1l   = _mm512_add_epi64(d1l, extra);
    extra = _mm512_srlv_epi64(d1l, _mm512_set1_epi64(44));
    d1l   = _mm512_and_epi64(d1l, _mm512_set1_epi64(0xfffffffffff));
    d2l   = _mm512_add_epi64(d2l, extra);
    extra = _mm512_srlv_epi64(d2l, _mm512_set1_epi64(42));
    d2l   = _mm512_and_epi64(d2l, _mm512_set1_epi64(0x3ffffffffff));
    d0h   = _mm512_sllv_epi64(extra, _mm512_set1_epi64(2));
    extra = _mm512_add_epi64(extra, d0h);
    d0l   = _mm512_add_epi64(d0l, extra);

    // extra = _mm512_srlv_epi64(d0l, _mm512_set1_epi64(44));
    // d0l   = _mm512_and_epi64(d0l, _mm512_set1_epi64(0xfffffffffff));
    // d1l   = _mm512_add_epi64(d1l, extra);

    // Store d0l, d1l, d2l to a0, a1, a2
    a0 = d0l;
    a1 = d1l;
    a2 = d2l;
}

void
multiply_radix44_avx512_standalone(const Uint64 a[3],
                                   const Uint64 b[3],
                                   Uint64       out[3])
{
    __m512i reg0, reg1, reg2;
    __m512i m0, m1, m2;
    // Compute out = a*b
    broadcast_r(b, reg0, reg1, reg2);

    broadcast_r(a, m0, m1, m2);

    // Compute s value
    __m512i s1, s2;
    poly1305_calculate_modulo_trick_value(reg1, reg2, s1, s2);

    // Multiply reg0, reg1, reg2 with m0, m1, m2
    multiplyx8_radix44_avx512(m0, m1, m2, reg0, reg1, reg2, s1, s2);

    // Store m0, m1, m2 to out
    _mm512_mask_storeu_epi64(out, 0x01, m0);
    _mm512_mask_storeu_epi64(out + 1, 0x01, m1);
    _mm512_mask_storeu_epi64(out + 2, 0x01, m2);
}

// Function to broadcast r value to reg0, reg1, reg2 which are 512 bit registers
inline void
broadcast_r(Uint64 r[3], __m512i& reg0, __m512i& reg1, __m512i& reg2)
{
    // Broadcast r[0] to reg0
    reg0 = _mm512_set1_epi64(r[0]);
    // Broadcast r[1] to reg1
    reg1 = _mm512_set1_epi64(r[1]);
    // Broadcast r[2] to reg2
    reg2 = _mm512_set1_epi64(r[2]);
}

void
load_all_r(Uint64   r[3],
           Uint64   r2[3],
           Uint64   r3[3],
           Uint64   r4[3],
           Uint64   r5[3],
           Uint64   r6[3],
           Uint64   r7[3],
           Uint64   r8[3],
           __m512i& reg0,
           __m512i& reg1,
           __m512i& reg2)
{
    // FIXME: Order of r, r2, r3, r4, r5, r6, r7, r8 is wrong
    reg0 = _mm512_setr_epi64(
        r8[0], r4[0], r7[0], r3[0], r6[0], r2[0], r5[0], r[0]);
    reg1 = _mm512_setr_epi64(
        r8[1], r4[1], r7[1], r3[1], r6[1], r2[1], r5[1], r[1]);
    reg2 = _mm512_setr_epi64(
        r8[2], r4[2], r7[2], r3[2], r6[2], r2[2], r5[2], r[2]);
}

void
poly1305_block_finalx8_avx512(__m512i& a0,
                              __m512i& a1,
                              __m512i& a2,
                              Uint64   r[3],
                              Uint64   r2[3],
                              Uint64   r3[3],
                              Uint64   r4[3],
                              Uint64   r5[3],
                              Uint64   r6[3],
                              Uint64   r7[3],
                              Uint64   r8[3])
{
    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;
    load_all_r(r, r2, r3, r4, r5, r6, r7, r8, reg_r0, reg_r1, reg_r2);

    // acc *= r,r2,r3,r4,r5,r6,r7,r8
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    multiplyx8_radix44_avx512(
        a0, a1, a2, reg_r0, reg_r1, reg_r2, reg_s1, reg_s2);

    // Horizontal addition
    // Downgrade to avx2, a0_256_0 and a0_256_1, a1_256_0 and a1_256_1 and
    // a2_256_0 and a2_256_1
    __m256i a0_256_0 = _mm512_extracti64x4_epi64(a0, 0);
    __m256i a0_256_1 = _mm512_extracti64x4_epi64(a0, 1);
    __m256i a1_256_0 = _mm512_extracti64x4_epi64(a1, 0);
    __m256i a1_256_1 = _mm512_extracti64x4_epi64(a1, 1);
    __m256i a2_256_0 = _mm512_extracti64x4_epi64(a2, 0);
    __m256i a2_256_1 = _mm512_extracti64x4_epi64(a2, 1);
    // Add a0_256_0 and a0_256_1 and save it to a0_256_0
    a0_256_0 = _mm256_add_epi64(a0_256_0, a0_256_1);
    // Add a1_256_0 and a1_256_1 and save it to a1_256_0
    a1_256_0 = _mm256_add_epi64(a1_256_0, a1_256_1);
    // Add a2_256_0 and a2_256_1 and save it to a2_256_0
    a2_256_0 = _mm256_add_epi64(a2_256_0, a2_256_1);

    // Downgrade to SSE, a0_128_0, a0_128_1, a1_128_0, a1_128_1, a2_128_0,
    // a2_128_1
    __m128i a0_128_0 = _mm256_extracti128_si256(a0_256_0, 0);
    __m128i a0_128_1 = _mm256_extracti128_si256(a0_256_0, 1);
    __m128i a1_128_0 = _mm256_extracti128_si256(a1_256_0, 0);
    __m128i a1_128_1 = _mm256_extracti128_si256(a1_256_0, 1);
    __m128i a2_128_0 = _mm256_extracti128_si256(a2_256_0, 0);
    __m128i a2_128_1 = _mm256_extracti128_si256(a2_256_0, 1);
    // Add a0_128_0 and a0_128_1 and save it to a0_128_0
    a0_128_0 = _mm_add_epi64(a0_128_0, a0_128_1);
    // Add a1_128_0 and a1_128_1 and save it to a1_128_0
    a1_128_0 = _mm_add_epi64(a1_128_0, a1_128_1);
    // Add a2_128_0 and a2_128_1 and save it to a2_128_0
    a2_128_0 = _mm_add_epi64(a2_128_0, a2_128_1);

    // Fold a0_128_0, a1_128_0, a2_128_0 to a0, a1, a2
    Uint64 _a0, _a1, _a2;
    _a0 = a0_128_0[0] + a0_128_0[1];
    _a1 = a1_128_0[0] + a1_128_0[1];
    _a2 = a2_128_0[0] + a2_128_0[1];

    // Save back _a0, _a1, _a2 to a0, a1, a2, set all other values to 0
    a0 = _mm512_setr_epi64(_a0, 0, 0, 0, 0, 0, 0, 0);
    a1 = _mm512_setr_epi64(_a1, 0, 0, 0, 0, 0, 0, 0);
    a2 = _mm512_setr_epi64(_a2, 0, 0, 0, 0, 0, 0, 0);

    // Optimization: Use 64 bit math to calculate a0, a1, a2 than using 512 bit
    // math. Carry propagation with modulo Right shift a0 by 44 bits
    __m512i carry = _mm512_srlv_epi64(a0, _mm512_set1_epi64(44));
    // Mask 0xfffffffffff (44 bits) to a0
    a0 = _mm512_and_epi64(a0, _mm512_set1_epi64(0xfffffffffff));
    // Add carry to a1
    a1 = _mm512_add_epi64(a1, carry);
    // Right shift a1 by 44 bits
    carry = _mm512_srlv_epi64(a1, _mm512_set1_epi64(44));
    // Mask 0xfffffffffff (44 bits) to a1
    a1 = _mm512_and_epi64(a1, _mm512_set1_epi64(0xfffffffffff));
    // Add carry to a2
    a2 = _mm512_add_epi64(a2, carry);
    // Right shift a2 by 42 bits
    carry = _mm512_srlv_epi64(a2, _mm512_set1_epi64(42));
    // Mask 0x3ffffffffff (42 bits) to a2
    a2 = _mm512_and_epi64(a2, _mm512_set1_epi64(0x3ffffffffff));
    // Add carry to a0
    a0 = _mm512_add_epi64(a0, _mm512_mullo_epi64(carry, _mm512_set1_epi64(5)));
    // Right shift a0 by 44 bits
    carry = _mm512_srlv_epi64(a0, _mm512_set1_epi64(44));
    // Mask 0xfffffffffff (44 bits) to a0
    a0 = _mm512_and_epi64(a0, _mm512_set1_epi64(0xfffffffffff));
    // Add carry to a1
    a1 = _mm512_add_epi64(a1, carry);
}

void
add_s(Uint64 a0[3], Uint64 a1[3], Uint64 a2[3], const Uint64 s[3])
{
    Uint64 carry = 0;
    a0[0] += s[0];
    carry = a0[0] >> 44;
    a0[0] &= 0xfffffffffff;
    a0[1] += s[1] + carry;
    carry = a0[1] >> 44;
    a0[1] &= 0xfffffffffff;
    a0[2] += s[2] + carry;
    a0[2] &= 0x3ffffffffff;
    a1[0] += a0[2] * 5;
    carry = a1[0] >> 44;
    a1[0] &= 0xfffffffffff;
    a1[1] += carry;
}

void
poly1305_init_radix44(Poly1305State44& state, const Uint8 key[32])
{
    Uint8 r[16];
    Uint8 s[16];

    std::memcpy(r, key, 16);
    std::memcpy(s, key + 16, 16);

    clamp(r);

    // Save RADIX44(r) to state->r
    radix44(r, state.r);
    // Save RADIX44(s) to state.s
    radix44(s, state.s);

    // FIXME: Use new_new_multiply_multi to optimize
    // Compute r**2..r**3..r**4..r**5..r**6..r**7..r**8
    // Multiply r1_key with r1_key and save it to r2_key
    // R Square
    multiply_radix44_avx512_standalone(state.r, state.r, state.r2);
    // R Cube
    multiply_radix44_avx512_standalone(state.r2, state.r, state.r3);
    // R Biquadrate / Quartic
    multiply_radix44_avx512_standalone(state.r3, state.r, state.r4);
    // R Sursolid / Quintic
    multiply_radix44_avx512_standalone(state.r4, state.r, state.r5);
    // R Zenzicube / Sextic
    multiply_radix44_avx512_standalone(state.r5, state.r, state.r6);
    // R Second Sursolid / Septic
    multiply_radix44_avx512_standalone(state.r6, state.r, state.r7);
    // R Zenzizenzizenzic / Octic
    multiply_radix44_avx512_standalone(state.r7, state.r, state.r8);
}

inline void
poly1305_blocksx8_radix44(Poly1305State44& state,
                          const Uint8*&    pMsg,
                          Uint64&          len)
{
    __m512i reg_msg0, reg_msg1, reg_msg2;
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;

    // Length should be >256
    assert(len > 256);
    if (state.fold == false) {
        state.fold = true;
        broadcast_r(state.r8, reg_r0, reg_r1, reg_r2);
        poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);
        // Load Initial Message
        loadx8_message_radix44_avx512(pMsg, reg_msg0, reg_msg1, reg_msg2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);
        len -= 128;
        pMsg += 128;
    }
    while ((len >= 128) && state.fold) {
        loadx8_message_radix44_avx512(pMsg, reg_msg0, reg_msg1, reg_msg2);

        multiplyx8_radix44_avx512(reg_acc0,
                                  reg_acc1,
                                  reg_acc2,
                                  reg_r0,
                                  reg_r1,
                                  reg_r2,
                                  reg_s1,
                                  reg_s2);

        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

        len -= 128;
        pMsg += 128;
    }

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

inline void
poly1305_blocksx1_radix44(Poly1305State44& state,
                          const Uint8*&    pMsg,
                          Uint64&          len)
{
    __m512i reg_msg0, reg_msg1, reg_msg2;
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;
    if (state.fold) {
        poly1305_block_finalx8_avx512(reg_acc0,
                                      reg_acc1,
                                      reg_acc2,
                                      state.r,
                                      state.r2,
                                      state.r3,
                                      state.r4,
                                      state.r5,
                                      state.r6,
                                      state.r7,
                                      state.r8);
        state.fold = false;
    }
    broadcast_r(state.r, reg_r0, reg_r1, reg_r2);
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    while (len >= 16) {
        loadx1_message_radix44_avx512(pMsg, reg_msg0, reg_msg1, reg_msg2);
        // Add m0, m1, m2 to a0, a1, a2
        reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
        reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
        reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

        pMsg += 16;
        len -= 16;

        multiplyx8_radix44_avx512(reg_acc0,
                                  reg_acc1,
                                  reg_acc2,
                                  reg_r0,
                                  reg_r1,
                                  reg_r2,
                                  reg_s1,
                                  reg_s2);
    }
    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

void
poly1305_partial_blocks(Poly1305State44& state)
{
    __m512i reg_msg0, reg_msg1, reg_msg2;
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);

    __m512i reg_r0, reg_r1, reg_r2;
    __m512i reg_s1, reg_s2;

    Uint8* pMsg = state.msg_buffer;

    assert(state.msg_buffer_len < 16);
    if (state.fold == true) {
        poly1305_block_finalx8_avx512(reg_acc0,
                                      reg_acc1,
                                      reg_acc2,
                                      state.r,
                                      state.r2,
                                      state.r3,
                                      state.r4,
                                      state.r5,
                                      state.r6,
                                      state.r7,
                                      state.r8);
        state.fold = false;
    }

    // Padding
    pMsg[state.msg_buffer_len] = 0x01;
    for (int i = state.msg_buffer_len + 1; i < 16; i++) {
        pMsg[i] = 0x00;
    }

    loadx1_message_radix44_nopad_avx512(pMsg, reg_msg0, reg_msg1, reg_msg2);

    // Setup R and S
    broadcast_r(state.r, reg_r0, reg_r1, reg_r2);
    poly1305_calculate_modulo_trick_value(reg_r1, reg_r2, reg_s1, reg_s2);

    // Add m0, m1, m2 to a0, a1, a2
    reg_acc0 = _mm512_add_epi64(reg_acc0, reg_msg0);
    reg_acc1 = _mm512_add_epi64(reg_acc1, reg_msg1);
    reg_acc2 = _mm512_add_epi64(reg_acc2, reg_msg2);

    state.msg_buffer_len = 0; // Reset message buffer

    multiplyx8_radix44_avx512(
        reg_acc0, reg_acc1, reg_acc2, reg_r0, reg_r1, reg_r2, reg_s1, reg_s2);

    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);
}

bool
poly1305_update_radix44(Poly1305State44& state, const Uint8* pMsg, Uint64 len)
{
    if (state.finalized == true) {
        return false;
    }
    if (state.msg_buffer_len != 0) {
        Uint64 copyLen = len > (16 - state.msg_buffer_len)
                             ? (16 - state.msg_buffer_len)
                             : len;
        // Handle overhanging data
        std::copy(
            pMsg, pMsg + copyLen, state.msg_buffer + state.msg_buffer_len);
        len -= copyLen;
        state.msg_buffer_len += copyLen;

        const Uint8* temp_ptr = state.msg_buffer;
        Uint64       temp_len = 16;

        if (state.msg_buffer_len == 16) {
            poly1305_blocksx1_radix44(state, temp_ptr, temp_len);
            state.msg_buffer_len = 0;
        }
    }
    if (len > 256) {
        poly1305_blocksx8_radix44(state, pMsg, len);
    }
    if (len >= 16) {
        poly1305_blocksx1_radix44(state, pMsg, len);
    }
    if (len) {
        std::copy(pMsg, pMsg + len, state.msg_buffer);
        state.msg_buffer_len = len;
    }

    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc0[i] << " ";
    // }
    // std::cout << std::endl;
    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc1[i] << " ";
    // }
    // std::cout << std::endl;
    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc2[i] << " ";
    // }
    // std::cout << std::endl;
    return true;
}

bool
poly1305_finalize_radix44(Poly1305State44& state, const Uint8* pMsg, Uint64 len)
{
    if (state.finalized == true) {
        return false;
    }
#if 1
    // Implement Partial Blocks
    if (state.msg_buffer_len != 0) {
        if (((len + state.msg_buffer_len) >= 16)) {
            std::copy(pMsg,
                      pMsg + (16 - state.msg_buffer_len),
                      state.msg_buffer + state.msg_buffer_len);
            poly1305_update_radix44(state, state.msg_buffer, 16);
            state.msg_buffer_len = 0;
            len                  = len - (16 - state.msg_buffer_len);
        } else {
            std::copy(
                pMsg, pMsg + len, state.msg_buffer + state.msg_buffer_len);
            state.msg_buffer_len = (len + state.msg_buffer_len);
            len                  = 0;
            poly1305_partial_blocks(state);
        }
    }
#endif
    if (len) {
        poly1305_update_radix44(state, pMsg, len);
        len = 0;
    }
    // FIXME: Fix this code duplication
#if 1
    // Implement Partial Blocks
    if (state.msg_buffer_len != 0) {
        if (((len + state.msg_buffer_len) >= 16)) {
            std::copy(pMsg,
                      pMsg + (16 - state.msg_buffer_len),
                      state.msg_buffer + state.msg_buffer_len);
            poly1305_update_radix44(state, state.msg_buffer, 16);
            state.msg_buffer_len = 0;
            len                  = len - (16 - state.msg_buffer_len);
        } else {
            std::copy(
                pMsg, pMsg + len, state.msg_buffer + state.msg_buffer_len);
            state.msg_buffer_len = (len + state.msg_buffer_len);
            poly1305_partial_blocks(state);
        }
    }
#endif
    __m512i reg_acc0 = _mm512_load_epi64(state.acc0),
            reg_acc1 = _mm512_load_epi64(state.acc1),
            reg_acc2 = _mm512_load_epi64(state.acc2);
    if (state.fold) {
        poly1305_block_finalx8_avx512(reg_acc0,
                                      reg_acc1,
                                      reg_acc2,
                                      state.r,
                                      state.r2,
                                      state.r3,
                                      state.r4,
                                      state.r5,
                                      state.r6,
                                      state.r7,
                                      state.r8);
        state.fold = false;
    }

    reg_acc0 = _mm512_add_epi64(reg_acc0, _mm512_set1_epi64(state.s[0]));
    reg_acc1 = _mm512_add_epi64(reg_acc1, _mm512_set1_epi64(state.s[1]));
    reg_acc2 = _mm512_add_epi64(reg_acc2, _mm512_set1_epi64(state.s[2]));

    // Carry Propagation
    // carry = a0>>44
    __m512i carry = _mm512_srli_epi64(reg_acc0, 44);
    // a1 = a1 + carry
    reg_acc1 = _mm512_add_epi64(reg_acc1, carry);
    // a0 = a0 & 0xfffffffffff
    reg_acc0 = _mm512_and_epi64(reg_acc0, _mm512_set1_epi64(0xfffffffffff));

    // carry = reg_acc1>>44
    carry = _mm512_srli_epi64(reg_acc1, 44);
    // a2 = a2 + carry
    reg_acc2 = _mm512_add_epi64(reg_acc2, carry);
    // reg_acc1 = reg_acc1 & 0xfffffffffff
    reg_acc1 = _mm512_and_epi64(reg_acc1, _mm512_set1_epi64(0xfffffffffff));

    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc0[i] << " ";
    // }
    // std::cout << std::endl;
    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc1[i] << " ";
    // }
    // std::cout << std::endl;
    // for (int i = 0; i < 8; i++) {
    //     std::cout << std::hex << reg_acc2[i] << " ";
    // }
    // std::cout << std::endl;
    _mm512_store_epi64(state.acc0, reg_acc0);
    _mm512_store_epi64(state.acc1, reg_acc1);
    _mm512_store_epi64(state.acc2, reg_acc2);

    state.finalized = true;
    return true;
}

bool
poly1305_copy_radix44(Poly1305State44& state, Uint8* digest, Uint64 digest_len)
{
    if (state.finalized == false) {
        return false;
    }
    Uint64 hash[3];
    Uint64 digest_temp[2];

    hash[0] = state.acc0[0];
    hash[1] = state.acc1[0];
    hash[2] = state.acc2[0];

    digest_temp[0] = hash[0] | hash[1] << 44;
    digest_temp[1] = (hash[1] >> 20) | hash[2] << 24;

    std::copy(reinterpret_cast<Uint8*>(digest_temp),
              reinterpret_cast<Uint8*>(digest_temp) + 16,
              digest);

    return true;
}

} // namespace alcp::mac::poly1305::zen4