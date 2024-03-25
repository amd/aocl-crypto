/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include <cstring>
#include <immintrin.h>

namespace alcp::cipher::chacha20::zen4 {

// Reference: Vectorization on ChaCha Stream Cipher
// Authors: Martin Goll and Shay Gueron
// https://ieeexplore.ieee.org/document/6822267

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

template<int index>
inline void
XorMessageKeyStreamStore(__m512i         stateRegister,
                         const __m128i*& pPlaintext128,
                         __m128i*&       pCiphertext128)
{
    __m128i reg128State = _mm512_extracti64x2_epi64(stateRegister, index);
    __m128i reg128Msg   = _mm_loadu_si128(pPlaintext128);
    reg128Msg           = _mm_xor_si128(reg128Msg, reg128State);
    _mm_storeu_si128(pCiphertext128, reg128Msg);
    pPlaintext128++;
    pCiphertext128++;
}

template<int index>
inline void
XorMessageKeyStreamStorePartial(__m512i&        stateRegister,
                                const __m128i*& pPlaintext128,
                                __m128i*&       pCiphertext128,
                                Uint64          len,
                                const Uint8*&   pInputText,
                                Uint8*&         pOutputText)
{
    if (len > 0) {
        alignas(64) Uint8 key_stream[16];
        __m128i reg128State = _mm512_extracti64x2_epi64(stateRegister, index);
        _mm_store_si128(reinterpret_cast<__m128i*>(key_stream), reg128State);
        for (Uint64 n = 0; n < len; n++) {
            pOutputText[n] = key_stream[n] ^ pInputText[n];
        }
        pInputText += len;
        pOutputText += len;
    }
}

inline void
PermuteRegisters1(__m512i& reg0,
                  __m512i& reg1,
                  __m512i  reg2,
                  __m512i& reg3,
                  __m512i& reg4,
                  __m512i  reg5)
{
    // reg0 and reg1 are the input registers where in every 32 bit packed value
    // is a part of the keystream belonging to seperate blocks

    // Using Unpack Instruction lower 32 bits of keystream into 64 bits
    reg4 = _mm512_unpacklo_epi32(reg0,
                                 reg1); // combine 32 bits from reg0 and 32 bits
                                        // reg1 for the first 8 32 bit values
    reg5 = _mm512_unpacklo_epi32(reg2,
                                 reg3); // combine 32 bits from reg2 and 32 bits
                                        // reg3 for the first 8 32 bit values

    // Using Unpack Instruction high 32 bits of keystream into 64 bits
    reg0 = _mm512_unpackhi_epi32(reg0,
                                 reg1); // combine 32 bits from reg0 and 32 bits
                                        // reg1 for the last 8 32 bit values
    reg2 = _mm512_unpackhi_epi32(reg2,
                                 reg3); // combine 32 bits from reg2 and 32 bits
                                        // reg3 for the last 8 32 bit values

    // At this point we have all the values we need as combined 64 bits in reg4,
    // reg5, reg0 and reg2. Hence reg1 can be reused.

    // Using 64bit unpacking combine low 64 bits of keystream into 128 bits
    reg1 = _mm512_unpacklo_epi64(
        reg4,
        reg5); // Take alternate low 64 bit from reg4 and 64 bit from reg5 into
               // reg1.
               // {reg4[0]reg4[1]reg5[0]reg5[1]},{[reg4[4]reg4[5]reg5[4]reg5[5]}....{reg4[12]reg4[13]reg5[12]reg5[13]}
    reg4 = _mm512_unpackhi_epi64(
        reg4,
        reg5); // Take alternate high 64 bit from reg4 and 64 bit from reg5 into
               // reg4
               //{reg4[1]reg4[2]reg5[1]reg5[2]},{[reg4[5]reg4[6]reg5[5]reg5[6]}....{reg4[14]reg4[15]reg5[14]reg5[15]}

    // Using 64bit unpacking combine high 64 bits of keystream into 128 bits
    reg3 = _mm512_unpacklo_epi64(
        reg0,
        reg2); // Take alternate low 64 bit from reg0 and 64 bit from reg2 into
               // reg3.
               // {reg0[0]reg0[1]reg2[0]reg2[1]},{[reg0[4]reg0[5]reg2[4]reg2[5]}....{reg0[12]reg0[13]reg2[12]reg2[13]}5]}

    reg0 = _mm512_unpackhi_epi64(
        reg0,
        reg2); // Take alternate high 64 bit from reg0 and 64 bit from reg2 into
               // reg0.
               //{reg0[1]reg0[2]reg2[1]reg2[2]},{[reg0[5]reg0[6]reg2[5]reg2[6]}....{reg0[14]reg0[15]reg2[14]reg2[15]}
}

inline void
shuffleRegisters(__m512i& z1, __m512i z2, __m512i& z3)
{
    // Lets consider values z1 and z2 into blocks of 128 bits for ease of 128
    // bit shuffling.
    // z1 = a0a1a2a3 and z2 = b0b1b2b3
    z3 = _mm512_shuffle_i32x4(
        z1, z2, 0x44); // mask= 0x44,= 0b 01 00 01 00, z3 = a1a0b1b0
    z1 = _mm512_shuffle_i32x4(
        z1, z2, 0xee); // mask= 0xee,= 0b 11 10 11 10, z1 = a3a2b3b2
}

inline void
shuffleRegisters2(__m512i z1, __m512i& z2, __m512i& z3)
{
    // Consider z1 = a0a1a2a3, z2 = b0b1b2b3, divided into 4 128 bit blocks
    z3 = _mm512_shuffle_i32x4(
        z2, z1, 0x22); // mask = 0x22 => 0b 00 10 00 10, z3 = a0a2b0b2
    z2 = _mm512_shuffle_i32x4(
        z2, z1, 0x77); // mask = 0x77 => 0b 01 11 01 11, z2 = a1a3b1b3
}
inline void
PermuteRegistersByShuffling2(__m512i  s0,
                             __m512i& s1,
                             __m512i& s2,
                             __m512i& s3,
                             __m512i& s4,
                             __m512i& s5,
                             __m512i  s6,
                             __m512i& s7,
                             __m512i& t0,
                             __m512i& t1)
{

    // s0 and s6 can be reused after this function call
    shuffleRegisters(s5, s1, t1);
    shuffleRegisters(s2, t0, s1);
    shuffleRegisters(s7, s3, t0);
    shuffleRegisters(s4, s0, s3);
}
inline void
XorKeyStoreNew(const __m512i*& p_in_512, __m512i key_512, __m512i*& p_out_512)
{
    __m512i input_512;

    input_512 = _mm512_loadu_si512(p_in_512);
    key_512   = _mm512_xor_si512(key_512, input_512);
    _mm512_storeu_si512(p_out_512, key_512);
    p_in_512++;
    p_out_512++;
}

inline void
Chacha20ParallelBlocks4(__m512i&      s_1_0_3_2,
                        __m512i&      s_5_4_7_6,
                        __m512i&      s_9_8_11_10,
                        __m512i&      s_13_12_15_14,
                        const __m512i s_1_0_3_2_prev,
                        const __m512i s_5_4_7_6_prev,
                        const __m512i s_9_8_11_10_prev,
                        const __m512i s_13_12_15_14_prev)
{
    for (int i = 0; i < 10; i++) {

        // -- Row Round Register Setup Complete.

        RoundFunction(s_1_0_3_2, s_5_4_7_6, s_9_8_11_10, s_13_12_15_14);
        // -- Row Round Function Complete
        // --- Setting up Register for Column Round Function
        // 6547
        s_5_4_7_6 = _mm512_shuffle_epi32(s_5_4_7_6, (_MM_PERM_ENUM)0b00111001);
        // 10,11,8,9 -> 11,10,9,8
        s_9_8_11_10 =
            _mm512_shuffle_epi32(s_9_8_11_10, (_MM_PERM_ENUM)0b01001110);
        // 15,12,13,14 -> 12,15,14,13
        s_13_12_15_14 =
            _mm512_shuffle_epi32(s_13_12_15_14, (_MM_PERM_ENUM)0b10010011);

        // Column Round Function

        RoundFunction(s_1_0_3_2, s_5_4_7_6, s_9_8_11_10, s_13_12_15_14);

        //   Reshuffle it back for next Row operation
        // 6547 -> 5_4_7_6
        s_5_4_7_6 = _mm512_shuffle_epi32(s_5_4_7_6, (_MM_PERM_ENUM)0b10010011);
        // 11,10,9,8 -> 9_8_11_10
        s_9_8_11_10 =
            _mm512_shuffle_epi32(s_9_8_11_10, (_MM_PERM_ENUM)0b01001110);
        // 12,15,14,13 -> 13_12_15_14
        s_13_12_15_14 =
            _mm512_shuffle_epi32(s_13_12_15_14, (_MM_PERM_ENUM)0b00111001);
    }

    s_1_0_3_2     = _mm512_add_epi32(s_1_0_3_2, s_1_0_3_2_prev);
    s_5_4_7_6     = _mm512_add_epi32(s_5_4_7_6, s_5_4_7_6_prev);
    s_9_8_11_10   = _mm512_add_epi32(s_9_8_11_10, s_9_8_11_10_prev);
    s_13_12_15_14 = _mm512_add_epi32(s_13_12_15_14, s_13_12_15_14_prev);
}

inline void
SetChacha2016BlockParallelConstants(__m512i& s1,
                                    __m512i& s2,
                                    __m512i& s3,
                                    __m512i& s4)
{
    constexpr Uint32 chacha20_constants1 = 0x61707865;
    constexpr Uint32 chacha20_constants2 = 0x3320646e;
    constexpr Uint32 chacha20_constants3 = 0x79622d32;
    constexpr Uint32 chacha20_constants4 = 0x6b206574;
    s1 = _mm512_set1_epi32(chacha20_constants1);
    s2 = _mm512_set1_epi32(chacha20_constants2);
    s3 = _mm512_set1_epi32(chacha20_constants3);
    s4 = _mm512_set1_epi32(chacha20_constants4);
}

inline void
SetChacha2016BlockParallelKey(const Uint8 key[],
                              __m512i&    s1,
                              __m512i&    s2,
                              __m512i&    s3,
                              __m512i&    s4,
                              __m512i&    s5,
                              __m512i&    s6,
                              __m512i&    s7,
                              __m512i&    s8)
{
    const Uint32* pKey = reinterpret_cast<const Uint32*>(key);
    // b
    s1 = _mm512_set1_epi32(*(pKey));
    s2 = _mm512_set1_epi32(*(pKey + 1));
    s3 = _mm512_set1_epi32(*(pKey + 2));
    s4 = _mm512_set1_epi32(*(pKey + 3));
    // c
    s5 = _mm512_set1_epi32(*(pKey + 4));
    s6 = _mm512_set1_epi32(*(pKey + 5));
    s7 = _mm512_set1_epi32(*(pKey + 6));
    s8 = _mm512_set1_epi32(*(pKey + 7));
}

inline void
SetChacha2016BlockParallelIv(
    Uint8 iv[], __m512i& s1, __m512i& s2, __m512i& s3, __m512i& s4)
{
    Uint32* pIv = reinterpret_cast<Uint32*>(iv);
    // d
    s1 = _mm512_set1_epi32(*(pIv));
    s2 = _mm512_set1_epi32(*(pIv + 1));
    s3 = _mm512_set1_epi32(*(pIv + 2));
    s4 = _mm512_set1_epi32(*(pIv + 3));
}

inline void
XorKeyStoreCombinedNew(const __m512i* p_in_512,
                       __m512i        s2,
                       __m512i        s5,
                       __m512i        s7,
                       __m512i        s4,

                       __m512i* p_out_512)
{

    __m512i input_512_1 = _mm512_loadu_si512(p_in_512);
    __m512i input_512_2 = _mm512_loadu_si512(p_in_512 + 1);
    __m512i input_512_3 = _mm512_loadu_si512(p_in_512 + 2);
    __m512i input_512_4 = _mm512_loadu_si512(p_in_512 + 3);

    s5 = _mm512_xor_si512(s5, input_512_1);
    s2 = _mm512_xor_si512(s2, input_512_2);
    s7 = _mm512_xor_si512(s7, input_512_3);
    s4 = _mm512_xor_si512(s4, input_512_4);

    _mm512_storeu_si512(p_out_512, s5);
    _mm512_storeu_si512(p_out_512 + 1, s2);
    _mm512_storeu_si512(p_out_512 + 2, s7);
    _mm512_storeu_si512(p_out_512 + 3, s4);
}

inline void
ProcessChacha20ParallelBlocks16(Uint64&       blocks,
                                const Uint8   key[],
                                Uint8         iv[],
                                const Uint8*& pInputText,
                                Uint8*&       pOutputText)
{

    __m512i s_prev[16], s[16];

    // -- Setup Registers for First Row Round Function
    // a
    SetChacha2016BlockParallelConstants(
        s_prev[0], s_prev[1], s_prev[2], s_prev[3]);

    SetChacha2016BlockParallelKey(key,
                                  s_prev[4],
                                  s_prev[5],
                                  s_prev[6],
                                  s_prev[7],
                                  s_prev[8],
                                  s_prev[9],
                                  s_prev[10],
                                  s_prev[11]);

    SetChacha2016BlockParallelIv(
        iv, s_prev[12], s_prev[13], s_prev[14], s_prev[15]);

    const __m512i inc_512 = _mm512_setr_epi32(
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16);
    s_prev[12] = _mm512_add_epi32(
        s_prev[12],
        _mm512_setr_epi32(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
    // s_prev[16] values will never change inside the loop except for
    // s_prev[12] which is used to save the counter value
    // clang-format on
    while (blocks >= 16) {
        // Restoring the registers to last Round State

        for (int i = 0; i < 16; i++) {
            s[i] = s_prev[i];
        }
        for (int i = 0; i < 10; i++) {

            // -- Row Round Register Setup Complete.

            RoundFunction(s[0], s[4], s[8], s[12]);
            RoundFunction(s[1], s[5], s[9], s[13]);
            RoundFunction(s[2], s[6], s[10], s[14]);
            RoundFunction(s[3], s[7], s[11], s[15]);

            // Column Round Function

            RoundFunction(s[0], s[5], s[10], s[15]);
            RoundFunction(s[1], s[6], s[11], s[12]);
            RoundFunction(s[2], s[7], s[8], s[13]);
            RoundFunction(s[3], s[4], s[9], s[14]);
        }

        for (int i = 0; i < 16; i++) {
            s[i] = _mm512_add_epi32(s[i], s_prev[i]);
        }

        __m512i temp[2];

        // Once call is complete, only registers
        // s[0],s[1],s[3],temp[0] are required.
        // Registers s[2] and temp[1] can be reused
        PermuteRegisters1(s[0], s[1], s[2], s[3], temp[0], temp[1]);

        // Registers s[6] and s[2] can be reused
        PermuteRegisters1(s[4],
                          s[5],
                          s[6],
                          s[7],
                          s[2], // Reusing s[2] and temp[1]
                          temp[1]);

        // Registers s[0],s[6] can be reused
        PermuteRegistersByShuffling2(
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], temp[0], temp[1]);
        // Registers s[10] and s[0] can be reused
        PermuteRegisters1(s[8], s[9], s[10], s[11], s[6], s[0]);

        // Registers s[14] and s[0] can be reused
        PermuteRegisters1(s[12], s[13], s[14], s[15], s[10], s[0]);
        // s[8] and s[14] can be reused
        PermuteRegistersByShuffling2(
            s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[6], s[0]);

        __m512i output_512[2];
        // temp[1]=block 4 and output_512[0] = Block 0
        shuffleRegisters2(s[0], temp[1], output_512[0]);

        // s[5]=Block 12 and s[0]= Block 8
        shuffleRegisters2(s[13], s[5], s[0]);

        // output_512[1] = Block 1 and s[1] = Block 5
        shuffleRegisters2(s[9], s[1], output_512[1]);

        // s[2] = Block 13 and s[9] = Block 9
        shuffleRegisters2(s[10], s[2], s[9]);

        // temp[0] = Block 6 and s[14] = Block 2
        shuffleRegisters2(s[6], temp[0], s[14]);

        // s[7]= Block 14 and s[6] = Block 10
        shuffleRegisters2(s[15], s[7], s[6]);

        //  s[3] = Block 7 and  s[8] = Block 3
        shuffleRegisters2(s[11], s[3], s[8]);

        // s[4] = Block 15 and  s[11] = Block 11
        shuffleRegisters2(s[12], s[4], s[11]);

        auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
        auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);

        // __m512i input_512;
        XorKeyStoreNew(p_in_512, output_512[0], p_out_512);
        XorKeyStoreNew(p_in_512, output_512[1], p_out_512);
        XorKeyStoreNew(p_in_512, s[14], p_out_512);
        XorKeyStoreNew(p_in_512, s[8], p_out_512);
        XorKeyStoreNew(p_in_512, temp[1], p_out_512);
        XorKeyStoreNew(p_in_512, s[1], p_out_512);
        XorKeyStoreNew(p_in_512, temp[0], p_out_512);
        XorKeyStoreNew(p_in_512, s[3], p_out_512);
        XorKeyStoreNew(p_in_512, s[0], p_out_512);
        XorKeyStoreNew(p_in_512, s[9], p_out_512);
        XorKeyStoreNew(p_in_512, s[6], p_out_512);
        XorKeyStoreNew(p_in_512, s[11], p_out_512);

        // Loads 4 512 bits first, XORs with key and then store 4 512 bits
        // at the end.
        XorKeyStoreCombinedNew(p_in_512, s[2], s[5], s[7], s[4], p_out_512);
        pInputText += 1024;
        pOutputText += 1024;
        s_prev[12] = _mm512_add_epi32(s_prev[12], inc_512);
        blocks -= 16;
    }
}

inline void
ProcessChacha20ParallelBlocks4(const Uint8   key[],
                               Uint8         iv[],
                               const Uint8*& pInputText,
                               Uint8*&       pOutputText,
                               Uint64        blocks,
                               int           remBytes)
{

    // 4 Block Parallelization

    // -- Setup Registers for First Row Round Function
    // a
    __m512i s_1_0_3_2_prev = _mm512_broadcast_i32x4(
        *reinterpret_cast<const __m128i*>(chacha20::Chacha20Constants));
    // b
    __m512i s_5_4_7_6_prev =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(key));
    // c
    __m512i s_9_8_11_10_prev =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(key + 16));
    // d
    __m512i s_13_12_15_14_prev =
        _mm512_broadcast_i32x4(*reinterpret_cast<const __m128i*>(iv));

    __m512i s_1_0_3_2, s_5_4_7_6, s_9_8_11_10, s_13_12_15_14, counter_512;

    // clang-format off
        counter_512 = _mm512_setr_epi32(0x0 ,0x0,0x0,0x0,
                                        0x1 ,0x0,0x0,0x0,
                                        0x2 ,0x0,0x0,0x0,
                                        0x3 ,0x0,0x0,0x0);
    const __m512i cInc512 = _mm512_setr_epi32(0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0);
    // clang-format on

    const __m128i* p_in_128  = reinterpret_cast<const __m128i*>(pInputText);
    __m128i*       p_out_128 = reinterpret_cast<__m128i*>(pOutputText);
    __m512i*       s_512[4]  = {
        &s_1_0_3_2, &s_5_4_7_6, &s_9_8_11_10, &s_13_12_15_14
    };

    while (blocks >= 4) {
        // Restoring the registers to last Round State
        s_1_0_3_2     = s_1_0_3_2_prev;
        s_5_4_7_6     = s_5_4_7_6_prev;
        s_9_8_11_10   = s_9_8_11_10_prev;
        s_13_12_15_14 = s_13_12_15_14_prev;

        s_13_12_15_14           = _mm512_add_epi32(s_13_12_15_14, counter_512);
        auto s_13_12_15_14_prev = s_13_12_15_14;
        Chacha20ParallelBlocks4(s_1_0_3_2,
                                s_5_4_7_6,
                                s_9_8_11_10,
                                s_13_12_15_14,
                                s_1_0_3_2_prev,
                                s_5_4_7_6_prev,
                                s_9_8_11_10_prev,
                                s_13_12_15_14_prev);

        XorMessageKeyStreamStore<0>(*s_512[0], p_in_128, p_out_128);

        XorMessageKeyStreamStore<0>(*s_512[1], p_in_128, p_out_128);
        XorMessageKeyStreamStore<0>(*s_512[2], p_in_128, p_out_128);
        XorMessageKeyStreamStore<0>(*s_512[3], p_in_128, p_out_128);
        XorMessageKeyStreamStore<1>(*s_512[0], p_in_128, p_out_128);
        XorMessageKeyStreamStore<1>(*s_512[1], p_in_128, p_out_128);
        XorMessageKeyStreamStore<1>(*s_512[2], p_in_128, p_out_128);
        XorMessageKeyStreamStore<1>(*s_512[3], p_in_128, p_out_128);
        XorMessageKeyStreamStore<2>(*s_512[0], p_in_128, p_out_128);
        XorMessageKeyStreamStore<2>(*s_512[1], p_in_128, p_out_128);
        XorMessageKeyStreamStore<2>(*s_512[2], p_in_128, p_out_128);
        XorMessageKeyStreamStore<2>(*s_512[3], p_in_128, p_out_128);
        XorMessageKeyStreamStore<3>(*s_512[0], p_in_128, p_out_128);
        XorMessageKeyStreamStore<3>(*s_512[1], p_in_128, p_out_128);
        XorMessageKeyStreamStore<3>(*s_512[2], p_in_128, p_out_128);
        XorMessageKeyStreamStore<3>(*s_512[3], p_in_128, p_out_128);

        pInputText += 256;

        pOutputText += 256;
        counter_512 = _mm512_add_epi32(counter_512, cInc512);
        blocks -= 4;
    }
    Uint64 totalbytes = blocks * CHACHA20_BLOCK_SIZE + remBytes;
    if (totalbytes > 0) {
        // Restoring the registers to last Round State
        s_1_0_3_2     = s_1_0_3_2_prev;
        s_5_4_7_6     = s_5_4_7_6_prev;
        s_9_8_11_10   = s_9_8_11_10_prev;
        s_13_12_15_14 = s_13_12_15_14_prev;

        s_13_12_15_14           = _mm512_add_epi32(s_13_12_15_14, counter_512);
        auto s_13_12_15_14_prev = s_13_12_15_14;
        Chacha20ParallelBlocks4(s_1_0_3_2,
                                s_5_4_7_6,
                                s_9_8_11_10,
                                s_13_12_15_14,
                                s_1_0_3_2_prev,
                                s_5_4_7_6_prev,
                                s_9_8_11_10_prev,
                                s_13_12_15_14_prev);
        if (totalbytes < 16) {
            XorMessageKeyStreamStorePartial<0>(*s_512[0],
                                               p_in_128,
                                               p_out_128,
                                               totalbytes,
                                               pInputText,
                                               pOutputText);
        } else {
            XorMessageKeyStreamStore<0>(*s_512[0], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;
            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<0>(*s_512[1],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<0>(*s_512[1], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<0>(*s_512[2],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<0>(*s_512[2], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;
            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<0>(*s_512[3],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<0>(*s_512[3], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;
            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<1>(*s_512[0],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<1>(*s_512[0], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;
            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<1>(*s_512[1],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<1>(*s_512[1], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<1>(*s_512[2],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<1>(*s_512[2], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<1>(*s_512[3],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<1>(*s_512[3], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<2>(*s_512[0],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<2>(*s_512[0], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<2>(*s_512[1],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<2>(*s_512[1], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<2>(*s_512[2],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<2>(*s_512[2], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<2>(*s_512[3],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<2>(*s_512[3], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<3>(*s_512[0],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<3>(*s_512[0], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<3>(*s_512[1],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<3>(*s_512[1], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<3>(*s_512[2],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<3>(*s_512[2], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                XorMessageKeyStreamStorePartial<3>(*s_512[3],
                                                   p_in_128,
                                                   p_out_128,
                                                   totalbytes,
                                                   pInputText,
                                                   pOutputText);
                return;
            }
            XorMessageKeyStreamStore<3>(*s_512[3], p_in_128, p_out_128);
            totalbytes -= 16;
            pInputText += 16;
            pOutputText += 16;

            if (totalbytes < 16) {
                return;
            }
        }
    }
}

alc_error_t
ProcessInput(const Uint8  key[],
             Uint64       keylen,
             Uint8        iv[],
             Uint64       ivlen,
             const Uint8* pInputText,
             Uint8*       pOutputText,
             Uint64       blocks,
             int          remBytes)
{
    // Preserving the initial number of blocks to be processed as it maybe
    // modified in ProcessChacha20ParallelBlocks16 and
    // ProcessChacha20ParallelBlocks4
    Uint64 temp_blocks = blocks;
    if (blocks >= 16) {
        ProcessChacha20ParallelBlocks16(
            blocks, key, iv, pInputText, pOutputText);
        (*(reinterpret_cast<Uint32*>(iv))) += (temp_blocks - blocks);
    }
    if ((blocks > 0) || (remBytes > 0)) {
        ProcessChacha20ParallelBlocks4(
            key, iv, pInputText, pOutputText, blocks, remBytes);
    }
    return ALC_ERROR_NONE;
}

alc_error_t
getKeyStream(const Uint8 key[],
             Uint64      keylen,
             Uint8       iv[],
             Uint64      ivlen,
             Uint8       outputKeyStream[],
             Uint64      keyStreamLength)
{
    Uint64 blocks   = keyStreamLength / CHACHA20_BLOCK_SIZE;
    Uint64 remBytes = keyStreamLength - (blocks * CHACHA20_BLOCK_SIZE);
    return ProcessInput(key,
                        keylen,
                        iv,
                        ivlen,
                        outputKeyStream,
                        outputKeyStream,
                        blocks,
                        remBytes);
}
} // namespace alcp::cipher::chacha20::zen4
