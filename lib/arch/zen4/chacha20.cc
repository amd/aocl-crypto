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
display_state(Uint32 state[16])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(8)
                      << +state[i * 4 + j] << " ";
        }
        std::cout << std::endl;
    }
}
inline Uint32
RotateLeft(Uint32 value, Uint32 count)
{
    return value << count | value >> (32 - count);
}

inline void
QuarterRound(Uint32& a, Uint32& b, Uint32& c, Uint32& d)
{
    a += b;
    d ^= a;
    d = RotateLeft(d, 16);
    c += d;
    b ^= c;
    b = RotateLeft(b, 12);
    a += b;
    d ^= a;
    d = RotateLeft(d, 8);
    c += d;
    b ^= c;
    b = RotateLeft(b, 7);
}

inline void
QuarterRoundState(Uint32               state[16],
                  const unsigned short index1,
                  const unsigned short index2,
                  const unsigned short index3,
                  const unsigned short index4)
{

    QuarterRound(state[index1], state[index2], state[index3], state[index4]);
}

inline void
inner_block(Uint32 state[16])
{
    QuarterRoundState(state, 0, 4, 8, 12);
    QuarterRoundState(state, 1, 5, 9, 13);
    QuarterRoundState(state, 2, 6, 10, 14);
    QuarterRoundState(state, 3, 7, 11, 15);
    QuarterRoundState(state, 0, 5, 10, 15);
    QuarterRoundState(state, 1, 6, 11, 12);
    QuarterRoundState(state, 2, 7, 8, 13);
    QuarterRoundState(state, 3, 4, 9, 14);
}

inline void
add_state(Uint32 state1[16], Uint32 state2[16])
{
    for (int i = 0; i < 16; i++) {
        state2[i] = state1[i] + state2[i];
    }
}
inline int
SetKey(Uint32 m_state[16], const Uint8* key, Uint64 keylen)
{
    if ((keylen != (256 / 8))) {
        return 0;
    }
    memcpy(m_state + 4, key, keylen);
    return 1;
}
inline int
SetIv(Uint32* m_state, const Uint8* iv, Uint64 ivlen)
{
    if (ivlen != 16) {
        return 0;
    }
    memcpy(m_state + 12, iv, ivlen);
    return 1;
}
inline int
CreateInitialState(Uint32 state[16],
                   Uint8* key,
                   Uint64 keylen,
                   Uint8* iv,
                   Uint64 ivlen,
                   Uint32 counter)
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    //  state = constants | key | counter | nonce
    if (!SetKey(state, key, keylen)) {
        return 0;
    };
    if (!SetIv(state, iv, ivlen)) {
        return 0;
    };
    state[12] = counter;
    return 1;
}

typedef union
{
    __m128i  reg;
    uint64_t u64[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t  u8[16];
} reg_128;

typedef union
{
    __m256i  reg;
    uint64_t u64[4];
    uint32_t u32[8];
    uint16_t u16[16];
    uint8_t  u8[32];
} reg_256;

typedef union
{
    __m512i  reg;
    uint64_t u64[8];
    uint32_t u32[16];
    uint16_t u16[32];
    uint8_t  u8[64];
} reg_512;

std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    // return "something";
    return ss.str();
}

void
print(reg_128 reg)
{
    for (int i = 15; i > -1; i--) {
        std::cout << parseBytesToHexStr((const uint8_t*)&(reg.u8) + i, 1);
    }
    std::cout << std::endl;
}

void
print(reg_256 reg)
{
    for (int i = 31; i > -1; i--) {
        std::cout << parseBytesToHexStr((const uint8_t*)&(reg.u8) + i, 1);
    }
    std::cout << std::endl;
}

void
print(reg_512 reg)
{
    for (int i = 53; i > -1; i--) {
        std::cout << parseBytesToHexStr((const uint8_t*)&(reg.u8) + i, 1);
    }
    std::cout << std::endl;
}

int
ProcessInput(Uint32       m_state[16],
             Uint8*       key,
             Uint64       keylen,
             Uint8*       iv,
             Uint64       ivlen,
             const Uint8* plaintext,
             Uint64       plaintext_length,
             Uint8*       ciphertext)
{
    // -- Setup Registers for Row Round Function
    // a
    auto reg_state_1_0_3_2 =
        _mm512_broadcast_i32x4(*reinterpret_cast<__m128i*>(Chacha20Constants));
    // b
    auto reg_state_5_4_7_6 =
        _mm512_broadcast_i32x4(*reinterpret_cast<__m128i*>(key));
    // c
    auto reg_state_9_8_11_10 =
        _mm512_broadcast_i32x4(*reinterpret_cast<__m128i*>(key + 16));
    // d
    auto reg_state_13_12_15_14 =
        _mm512_broadcast_i32x4(*reinterpret_cast<__m128i*>(iv));

    auto counter_reg = _mm512_setr_epi32(0x0,
                                         0x0,
                                         0x0,
                                         0x0,
                                         0x1,
                                         0x0,
                                         0x0,
                                         0x0,
                                         0x2,
                                         0x0,
                                         0x0,
                                         0x0,
                                         0x3,
                                         0x0,
                                         0x0,
                                         0x0);
    reg_state_13_12_15_14 =
        _mm512_add_epi32(reg_state_13_12_15_14, counter_reg);
    for (int i = 0; i < 10; i++) {

        // -- Row Round Register Setup Complete.

        //  Perform Row Round Function
        // a += b;
        reg_state_1_0_3_2 =
            _mm512_add_epi32(reg_state_1_0_3_2, reg_state_5_4_7_6);
        // d ^= a;
        reg_state_13_12_15_14 =
            _mm512_xor_si512(reg_state_13_12_15_14, reg_state_1_0_3_2);
        // d << <= 16;
        reg_state_13_12_15_14 = _mm512_rol_epi32(reg_state_13_12_15_14, 16);

        // c += d;
        reg_state_9_8_11_10 =
            _mm512_add_epi32(reg_state_9_8_11_10, reg_state_13_12_15_14);
        // b ^= c;
        reg_state_5_4_7_6 =
            _mm512_xor_si512(reg_state_5_4_7_6, reg_state_9_8_11_10);
        // b << <= 12;
        reg_state_5_4_7_6 = _mm512_rol_epi32(reg_state_5_4_7_6, 12);

        // a += b;
        reg_state_1_0_3_2 =
            _mm512_add_epi32(reg_state_1_0_3_2, reg_state_5_4_7_6);
        // d ^= a;
        reg_state_13_12_15_14 =
            _mm512_xor_si512(reg_state_13_12_15_14, reg_state_1_0_3_2);
        // d <<<= 8;
        reg_state_13_12_15_14 = _mm512_rol_epi32(reg_state_13_12_15_14, 8);

        // c += d;
        reg_state_9_8_11_10 =
            _mm512_add_epi32(reg_state_9_8_11_10, reg_state_13_12_15_14);
        // b ^= c;
        reg_state_5_4_7_6 =
            _mm512_xor_si512(reg_state_5_4_7_6, reg_state_9_8_11_10);
        // b <<<= 7;
        reg_state_5_4_7_6 = _mm512_rol_epi32(reg_state_5_4_7_6, 7);

        // -- Row Round Function Complete
        // --- Setting up Register for Column Round Function
        // 6547
        reg_state_5_4_7_6 = _mm512_shuffle_epi32(reg_state_5_4_7_6, 0b00111001);
        // 10,11,8,9 -> 11,10,9,8
        reg_state_9_8_11_10 =
            _mm512_shuffle_epi32(reg_state_9_8_11_10, 0b01001110);
        // 15,12,13,14 -> 12,15,14,13
        reg_state_13_12_15_14 =
            _mm512_shuffle_epi32(reg_state_13_12_15_14, 0b10010011);

        // Column Round Function
        // a += b;
        reg_state_1_0_3_2 =
            _mm512_add_epi32(reg_state_1_0_3_2, reg_state_5_4_7_6);
        // d ^= a;
        reg_state_13_12_15_14 =
            _mm512_xor_si512(reg_state_13_12_15_14, reg_state_1_0_3_2);
        // d << <= 16;
        reg_state_13_12_15_14 = _mm512_rol_epi32(reg_state_13_12_15_14, 16);

        // c += d;
        reg_state_9_8_11_10 =
            _mm512_add_epi32(reg_state_9_8_11_10, reg_state_13_12_15_14);
        // b ^= c;
        reg_state_5_4_7_6 =
            _mm512_xor_si512(reg_state_5_4_7_6, reg_state_9_8_11_10);
        // b << <= 12;
        reg_state_5_4_7_6 = _mm512_rol_epi32(reg_state_5_4_7_6, 12);

        // a += b;
        reg_state_1_0_3_2 =
            _mm512_add_epi32(reg_state_1_0_3_2, reg_state_5_4_7_6);
        // d ^= a;
        reg_state_13_12_15_14 =
            _mm512_xor_si512(reg_state_13_12_15_14, reg_state_1_0_3_2);
        // d <<<= 8;
        reg_state_13_12_15_14 = _mm512_rol_epi32(reg_state_13_12_15_14, 8);

        // c += d;
        reg_state_9_8_11_10 =
            _mm512_add_epi32(reg_state_9_8_11_10, reg_state_13_12_15_14);
        // b ^= c;
        reg_state_5_4_7_6 =
            _mm512_xor_si512(reg_state_5_4_7_6, reg_state_9_8_11_10);
        // b <<<= 7;
        reg_state_5_4_7_6 = _mm512_rol_epi32(reg_state_5_4_7_6, 7);
    }
    return 1;
}
} // namespace alcp::cipher::zen4
