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

#include <array>
#include <immintrin.h>
#include <tuple>

#include "alcp/mac/poly1305_zen4.hh"

// #define DEBUG_PRINT

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

inline void
calculate_multiplication_matrix(const Uint64 r[5],
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

    std::copy(r, r + 5, r + 5);

    // Precompute r^2 value
    multiply(r + 5, r, s);

    // Precompute (r^2)*5 value
    for (int i = 0; i < 4; i++) {
        s[i + 4] = r[i + 1 + 5] * 5;
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
    calculate_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4);
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
    calculate_multiplication_matrix(r, s, reg0, reg1, reg2, reg3, reg4);
    calculate_multiplication_matrix(
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
    debug_print("Here");
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
        // blk(key, pMsg, 16, accumulator, r, s);
        blkx2(key, pMsg, 16, accumulator, r, s);
        // blkx4(key, pMsg, 16, accumulator, r, s);
    }

    Uint64 overflow = msgLen % 16;

    // blk(key, pMsg, msgLen - overflow, accumulator, r, s);
    blkx2(key, pMsg, msgLen - overflow, accumulator, r, s);
    // blkx4(key, pMsg, msgLen - overflow, accumulator, r, s);
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
        blkx2(key, msg_buffer, msg_buffer_len, accumulator, r, s);
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
} // namespace alcp::mac::poly1305::zen4