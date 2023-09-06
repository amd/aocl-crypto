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

#include "alcp/cipher/chacha20.hh"
#include <alcp/types.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#define UNROLL_8 _Pragma("GCC unroll 2")
#include <immintrin.h>
namespace alcp::cipher::zen4 {

inline void
RoundFunction(__m512i& regA, __m512i& regB, __m512i& regC, __m512i& regD)
{
    regA = _mm512_add_epi32(regA, regB);
    // d ^= a;
    regD = _mm512_xor_si512(regD, regA);
    // d << <= 16;
    regD = _mm512_rol_epi32(regD, 16);

    // c += d;
    regC = _mm512_add_epi32(regC, regD);
    // b ^= c;
    regB = _mm512_xor_si512(regB, regC);
    // b << <= 12;
    regB = _mm512_rol_epi32(regB, 12);

    // a += b;
    regA = _mm512_add_epi32(regA, regB);
    // d ^= a;
    regD = _mm512_xor_si512(regD, regA);
    // d <<<= 8;
    regD = _mm512_rol_epi32(regD, 8);

    // c += d;
    regC = _mm512_add_epi32(regC, regD);
    // b ^= c;
    regB = _mm512_xor_si512(regB, regC);
    // b <<<= 7;
    regB = _mm512_rol_epi32(regB, 7);
}

inline void
handleLastBlocks(__m128i&       stateReg,
                 Uint64         plaintextLength,
                 Uint64         totalBlocks,
                 const __m128i& shuffleReg,
                 const Uint8*   plaintext,
                 Uint8*         ciphertext)
{
    Uint8 temp[16];
    stateReg = _mm_shuffle_epi8(stateReg, shuffleReg);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(temp), stateReg);

    for (Uint64 j = 0; j < plaintextLength - totalBlocks * 16; j++) {
        *(ciphertext + totalBlocks * 16 + j) =
            temp[j] ^ *(plaintext + totalBlocks * 16 + j);
    }
}
#define XOR_MESSAGE_KEYSTREAM_STORE(state_register, index)                     \
    reg_state = _mm512_extracti64x2_epi64(state_register, index);              \
    if (i == blocks_128bits) {                                                 \
        if ((((plaintextLength - (blocks_128bits * 16)) > 0))) {               \
            handleLastBlocks(reg_state,                                        \
                             plaintextLength,                                  \
                             blocks_128bits,                                   \
                             shuffle_reg,                                      \
                             plaintext,                                        \
                             ciphertext);                                      \
            return ALC_ERROR_NONE;                                             \
        } else {                                                               \
            return ALC_ERROR_NONE;                                             \
        }                                                                      \
    }                                                                          \
    reg_128_msg = _mm_loadu_si128(p_plaintext_128);                            \
    reg_128_msg = _mm_shuffle_epi8(reg_128_msg, shuffle_reg);                  \
    reg_128_msg = _mm_xor_si128(reg_state, reg_128_msg);                       \
    reg_128_msg = _mm_shuffle_epi8(reg_128_msg, shuffle_reg);                  \
    _mm_store_si128(p_ciphertext_128, reg_128_msg);                            \
    i++;                                                                       \
    p_plaintext_128++;                                                         \
    p_ciphertext_128++;

alc_error_t
ProcessInput(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             const Uint8 plaintext[],
             Uint64      plaintextLength,
             Uint8       ciphertext[])
{
    // -- Setup Registers for First Row Round Function
    // a
    __m512i reg_state_1_0_3_2_save = _mm512_broadcast_i32x4(
        *reinterpret_cast<const __m128i*>(ChaCha20::Chacha20Constants));
    // b
    __m512i reg_state_5_4_7_6_save =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(key));
    // c
    __m512i reg_state_9_8_11_10_save =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(key + 16));
    // d
    __m512i reg_state_13_12_15_14_save =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(iv));

    __m512i reg_state_1_0_3_2, reg_state_5_4_7_6, reg_state_9_8_11_10,
        reg_state_13_12_15_14, counter_reg;

    __m128i reg_state;
    __m128i reg_128_msg;
    // clang-format off
    const __m128i shuffle_reg      = _mm_setr_epi8(0x04, 0x05, 0x06,0x07, 0x00,
                                        0x01,0x02,0x03,0x0c,0x0d,0x0e,0x0f,0x08,0x09,0xa,0x0b);
        counter_reg = _mm512_setr_epi32(0x0 ,0x0,0x0,0x0,
                                        0x1 ,0x0,0x0,0x0,
                                        0x2 ,0x0,0x0,0x0,
                                        0x3 ,0x0,0x0,0x0);
    const __m512i inc_reg = _mm512_setr_epi32(0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0);
    // clang-format on

    auto     p_plaintext_128  = reinterpret_cast<const __m128i*>(plaintext);
    auto     p_ciphertext_128 = reinterpret_cast<__m128i*>(ciphertext);
    Uint64   n                = (plaintextLength / 256) + 1;
    __m512i* state[4]         = { &reg_state_1_0_3_2,
                                  &reg_state_5_4_7_6,
                                  &reg_state_9_8_11_10,
                                  &reg_state_13_12_15_14 };
    for (Uint64 k = 0; k < n; k++) {

        // Restoring the registers to last Round State
        reg_state_1_0_3_2     = reg_state_1_0_3_2_save;
        reg_state_5_4_7_6     = reg_state_5_4_7_6_save;
        reg_state_9_8_11_10   = reg_state_9_8_11_10_save;
        reg_state_13_12_15_14 = reg_state_13_12_15_14_save;

        reg_state_13_12_15_14 =
            _mm512_add_epi32(reg_state_13_12_15_14, counter_reg);
        auto reg_state_13_12_15_14_save = reg_state_13_12_15_14;
        for (int i = 0; i < 10; i++) {

            // -- Row Round Register Setup Complete.

            RoundFunction(reg_state_1_0_3_2,
                          reg_state_5_4_7_6,
                          reg_state_9_8_11_10,
                          reg_state_13_12_15_14);
            // -- Row Round Function Complete
            // --- Setting up Register for Column Round Function
            // 6547
            reg_state_5_4_7_6 = _mm512_shuffle_epi32(reg_state_5_4_7_6,
                                                     (_MM_PERM_ENUM)0b00111001);
            // 10,11,8,9 -> 11,10,9,8
            reg_state_9_8_11_10 = _mm512_shuffle_epi32(
                reg_state_9_8_11_10, (_MM_PERM_ENUM)0b01001110);
            // 15,12,13,14 -> 12,15,14,13
            reg_state_13_12_15_14 = _mm512_shuffle_epi32(
                reg_state_13_12_15_14, (_MM_PERM_ENUM)0b10010011);

            // Column Round Function

            RoundFunction(reg_state_1_0_3_2,
                          reg_state_5_4_7_6,
                          reg_state_9_8_11_10,
                          reg_state_13_12_15_14);

            //   Reshuffle it back for next Row operation
            // 6547 -> 5_4_7_6
            reg_state_5_4_7_6 = _mm512_shuffle_epi32(reg_state_5_4_7_6,
                                                     (_MM_PERM_ENUM)0b10010011);
            // 11,10,9,8 -> 9_8_11_10
            reg_state_9_8_11_10 = _mm512_shuffle_epi32(
                reg_state_9_8_11_10, (_MM_PERM_ENUM)0b01001110);
            // 12,15,14,13 -> 13_12_15_14
            reg_state_13_12_15_14 = _mm512_shuffle_epi32(
                reg_state_13_12_15_14, (_MM_PERM_ENUM)0b00111001);
        }

        reg_state_1_0_3_2 =
            _mm512_add_epi32(reg_state_1_0_3_2, reg_state_1_0_3_2_save);
        reg_state_5_4_7_6 =
            _mm512_add_epi32(reg_state_5_4_7_6, reg_state_5_4_7_6_save);
        reg_state_9_8_11_10 =
            _mm512_add_epi32(reg_state_9_8_11_10, reg_state_9_8_11_10_save);
        reg_state_13_12_15_14 =
            _mm512_add_epi32(reg_state_13_12_15_14, reg_state_13_12_15_14_save);
        // a
        reg_state_1_0_3_2 =
            _mm512_shuffle_epi32(reg_state_1_0_3_2, (_MM_PERM_ENUM)0b10110001);

        // b
        reg_state_5_4_7_6 =
            _mm512_shuffle_epi32(reg_state_5_4_7_6, (_MM_PERM_ENUM)0b10110001);

        // c
        reg_state_9_8_11_10 = _mm512_shuffle_epi32(reg_state_9_8_11_10,
                                                   (_MM_PERM_ENUM)0b10110001);

        // d
        reg_state_13_12_15_14 = _mm512_shuffle_epi32(reg_state_13_12_15_14,
                                                     (_MM_PERM_ENUM)0b10110001);

        Uint64 blocks_128bits = plaintextLength / 16;

        Uint64 i = 0;

        for (int p = 0; p < 4; p++) {
            for (int j = 0; j < 4; j++) {
                XOR_MESSAGE_KEYSTREAM_STORE(*state[j], p)
            }
        }

        plaintext += 256;
        plaintextLength -= 256;
        ciphertext += 256;
        counter_reg = _mm512_add_epi32(counter_reg, inc_reg);
    }
    return ALC_ERROR_NONE;
}
} // namespace alcp::cipher::zen4
