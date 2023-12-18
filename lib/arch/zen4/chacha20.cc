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
XorMessageKeyStreamStore(__m512i&        stateRegister,
                         __m128i&        reg128State,
                         __m128i&        reg128Msg,
                         const __m128i*& pPlaintext128,
                         __m128i*&       pCiphertext128)
{
    reg128State = _mm512_extracti64x2_epi64(stateRegister, index);
    reg128Msg   = _mm_loadu_si128(pPlaintext128);
    reg128Msg   = _mm_xor_si128(reg128Msg, reg128State);
    _mm_storeu_si128(pCiphertext128, reg128Msg);
    pPlaintext128++;
    pCiphertext128++;
}

void
ProcessParallelBlocks(const Uint8 key[],
                      Uint64      keylen,
                      const Uint8 iv[],
                      Uint64      ivlen,
                      const Uint8 plaintext[],
                      Uint64      plaintextLength,
                      Uint8       ciphertext[],
                      Uint64      chacha20ParallelBlocks)
{
    // -- Setup Registers for First Row Round Function
    // a
    __m512i reg_state_1_0_3_2_save = _mm512_broadcast_i32x4(
        *reinterpret_cast<const __m128i*>(chacha20::Chacha20Constants));
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

    __m128i reg_128_state;
    __m128i reg_128_msg;
    // clang-format off
        counter_reg = _mm512_setr_epi32(0x0 ,0x0,0x0,0x0,
                                        0x1 ,0x0,0x0,0x0,
                                        0x2 ,0x0,0x0,0x0,
                                        0x3 ,0x0,0x0,0x0);
    const __m512i cIncReg = _mm512_setr_epi32(0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0,
                                        0x4 ,0x0,0x0,0x0);
    // clang-format on

    const __m128i* p_plaintext_128 =
        reinterpret_cast<const __m128i*>(plaintext);
    __m128i* p_ciphertext_128 = reinterpret_cast<__m128i*>(ciphertext);
    __m512i* state[4]         = { &reg_state_1_0_3_2,
                                  &reg_state_5_4_7_6,
                                  &reg_state_9_8_11_10,
                                  &reg_state_13_12_15_14 };
    for (Uint64 k = 0; k < chacha20ParallelBlocks; k++) {

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

        XorMessageKeyStreamStore<0>(*state[0],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        XorMessageKeyStreamStore<0>(*state[1],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(*state[2],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(*state[3],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(*state[0],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(*state[1],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(*state[2],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(*state[3],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(*state[0],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(*state[1],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(*state[2],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(*state[3],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(*state[0],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(*state[1],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(*state[2],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(*state[3],
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        plaintext += 256;

        ciphertext += 256;
        counter_reg = _mm512_add_epi32(counter_reg, cIncReg);
    }
}

void
processParallelBlocks2(const Uint8 key[],
                       Uint64      keylen,
                       const Uint8 iv[],
                       Uint64      ivlen,
                       const Uint8 plaintext[],
                       Uint64      plaintextLength,
                       Uint8       ciphertext[],
                       Uint64      chacha20_parallel_blocks)
{

    Uint32 Chacha20Constants1[4] = { 0x61707865 };
    Uint32 Chacha20Constants2[4] = { 0x3320646e };
    Uint32 Chacha20Constants3[4] = { 0x79622d32 };
    Uint32 Chacha20Constants4[4] = { 0x6b206574 };

    __m512i reg_state_0_save, reg_state_1_save, reg_state_2_save,
        reg_state_3_save, reg_state_4_save, reg_state_5_save, reg_state_6_save,
        reg_state_7_save, reg_state_8_save, reg_state_9_save, reg_state_10_save,
        reg_state_11_save, reg_state_12_save, reg_state_13_save,
        reg_state_14_save, reg_state_15_save, counter_reg;

    __m512i reg_state_0, reg_state_1, reg_state_2, reg_state_3, reg_state_4,
        reg_state_5, reg_state_6, reg_state_7, reg_state_8, reg_state_9,
        reg_state_10, reg_state_11, reg_state_12, reg_state_13, reg_state_14,
        reg_state_15;
    // -- Setup Registers for First Row Round Function
    // a
    reg_state_0_save = _mm512_set1_epi32(*Chacha20Constants1);
    reg_state_1_save = _mm512_set1_epi32(*Chacha20Constants2);
    reg_state_2_save = _mm512_set1_epi32(*Chacha20Constants3);
    reg_state_3_save = _mm512_set1_epi32(*Chacha20Constants4);

    // b
    reg_state_4_save = _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key));
    reg_state_5_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 4));
    reg_state_6_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 8));
    reg_state_7_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 12));

    // c
    reg_state_8_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 16));
    reg_state_9_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 20));
    reg_state_10_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 24));
    reg_state_11_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(key + 28));
    // d
    reg_state_12_save = _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(iv));
    reg_state_13_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(iv + 4));
    reg_state_14_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(iv + 8));
    reg_state_15_save =
        _mm512_set1_epi32(*reinterpret_cast<const Uint32*>(iv + 12));

    counter_reg =
        _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    const __m512i inc_reg = _mm512_setr_epi32(
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16);
    __m128i reg_128_state;
    __m128i reg_128_msg;
#if 0

    __m512i reg_state_1_0, reg_state_5_4, reg_state_9_8, reg_state_13_12;

    __m512i reg_state_3_2, reg_state_7_6, reg_state_11_10, reg_state_15_14,
        counter_reg;

    // clang-format off

 #endif

    // clang-format on

    const __m128i* p_plaintext_128 =
        reinterpret_cast<const __m128i*>(plaintext);
    __m128i* p_ciphertext_128 = reinterpret_cast<__m128i*>(ciphertext);
    // __m512i* state[4]         = { &reg_state_1_0_3_2,
    //                               &reg_state_9_8_11_10,
    //                               &reg_state_13_12_15_14 };
    //                               &reg_state_5_4_7_6,
    for (Uint64 k = 0; k < chacha20_parallel_blocks; k++) {

        // Restoring the registers to last Round State
        reg_state_0  = reg_state_0_save;
        reg_state_1  = reg_state_1_save;
        reg_state_2  = reg_state_2_save;
        reg_state_3  = reg_state_3_save;
        reg_state_4  = reg_state_4_save;
        reg_state_5  = reg_state_5_save;
        reg_state_6  = reg_state_6_save;
        reg_state_7  = reg_state_7_save;
        reg_state_8  = reg_state_8_save;
        reg_state_9  = reg_state_9_save;
        reg_state_10 = reg_state_10_save;
        reg_state_11 = reg_state_11_save;
        reg_state_12 = reg_state_12_save;
        reg_state_13 = reg_state_13_save;
        reg_state_14 = reg_state_14_save;
        reg_state_15 = reg_state_15_save;

        reg_state_12           = _mm512_add_epi32(reg_state_12, counter_reg);
        auto reg_state_12_save = reg_state_12;
        auto reg_state_13_save = reg_state_13;
        auto reg_state_14_save = reg_state_14;
        auto reg_state_15_save = reg_state_15;

        for (int i = 0; i < 10; i++) {

            // -- Row Round Register Setup Complete.

            RoundFunction(reg_state_0, reg_state_4, reg_state_8, reg_state_12);
            RoundFunction(reg_state_1, reg_state_5, reg_state_9, reg_state_13);
            RoundFunction(reg_state_2, reg_state_6, reg_state_10, reg_state_14);
            RoundFunction(reg_state_3, reg_state_7, reg_state_11, reg_state_15);

            // Column Round Function

            RoundFunction(reg_state_0, reg_state_5, reg_state_10, reg_state_15);
            RoundFunction(reg_state_1, reg_state_6, reg_state_11, reg_state_12);
            RoundFunction(reg_state_2, reg_state_7, reg_state_8, reg_state_13);
            RoundFunction(reg_state_3, reg_state_4, reg_state_9, reg_state_14);
        }
        reg_state_0  = _mm512_add_epi32(reg_state_0, reg_state_0_save);
        reg_state_1  = _mm512_add_epi32(reg_state_1, reg_state_1_save);
        reg_state_2  = _mm512_add_epi32(reg_state_2, reg_state_2_save);
        reg_state_3  = _mm512_add_epi32(reg_state_3, reg_state_3_save);
        reg_state_4  = _mm512_add_epi32(reg_state_4, reg_state_4_save);
        reg_state_5  = _mm512_add_epi32(reg_state_5, reg_state_5_save);
        reg_state_6  = _mm512_add_epi32(reg_state_6, reg_state_6_save);
        reg_state_7  = _mm512_add_epi32(reg_state_7, reg_state_7_save);
        reg_state_8  = _mm512_add_epi32(reg_state_8, reg_state_8_save);
        reg_state_9  = _mm512_add_epi32(reg_state_9, reg_state_9_save);
        reg_state_10 = _mm512_add_epi32(reg_state_10, reg_state_10_save);
        reg_state_11 = _mm512_add_epi32(reg_state_11, reg_state_11_save);
        reg_state_12 = _mm512_add_epi32(reg_state_12, reg_state_12_save);
        reg_state_13 = _mm512_add_epi32(reg_state_13, reg_state_13_save);
        reg_state_14 = _mm512_add_epi32(reg_state_14, reg_state_14_save);
        reg_state_15 = _mm512_add_epi32(reg_state_15, reg_state_15_save);

        XorMessageKeyStreamStore<0>(reg_state_0,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        XorMessageKeyStreamStore<0>(reg_state_1,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(reg_state_2,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(reg_state_3,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        XorMessageKeyStreamStore<0>(reg_state_0,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        XorMessageKeyStreamStore<0>(reg_state_1,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(reg_state_2,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<0>(reg_state_3,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(reg_state_0,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(reg_state_1,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(reg_state_2,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<1>(reg_state_3,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(reg_state_0,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(reg_state_1,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(reg_state_2,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<2>(reg_state_3,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(reg_state_0,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(reg_state_1,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(reg_state_2,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);
        XorMessageKeyStreamStore<3>(reg_state_3,
                                    reg_128_state,
                                    reg_128_msg,
                                    p_plaintext_128,
                                    p_ciphertext_128);

        plaintext += 256;

        ciphertext += 256;
        counter_reg = _mm512_add_epi32(counter_reg, inc_reg);
    }
}

alc_error_t
ProcessInput(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             const Uint8 plaintext[],
             Uint64      plaintextLength,
             Uint8       ciphertext[])
{
    Uint64 chacha20_parallel_blocks = plaintextLength / 1024;
    Uint64 chacha20_non_parallel_bytes =
        plaintextLength - (chacha20_parallel_blocks * 1024);
    if (chacha20_parallel_blocks > 0) {
        processParallelBlocks2(key,
                               keylen,
                               iv,
                               ivlen,
                               plaintext,
                               plaintextLength,
                               ciphertext,
                               chacha20_parallel_blocks);
        plaintext += chacha20_parallel_blocks * 1024;
        ciphertext += chacha20_parallel_blocks * 1024;
    }

    if (chacha20_non_parallel_bytes > 0) {
        Uint8 chacha20_key_stream[1024] = {};
        Uint8 iv_copy[24];
        memcpy(iv_copy, iv, 24);
        if (chacha20_parallel_blocks > 0) {
            (*(reinterpret_cast<Uint32*>(iv_copy))) +=
                4 * chacha20_parallel_blocks;
        }
        processParallelBlocks2(key,
                               keylen,
                               iv_copy,
                               ivlen,
                               chacha20_key_stream,
                               1024,
                               chacha20_key_stream,
                               1);
        for (Uint64 i = 0; i < chacha20_non_parallel_bytes; i++) {
            *(ciphertext) = chacha20_key_stream[i] ^ *(plaintext);
            plaintext++;
            ciphertext++;
        }
    }
    return ALC_ERROR_NONE;
}

alc_error_t
getKeyStream(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             Uint8       outputKeyStream[],
             Uint64      keyStreamLength)
{
    return ProcessInput(key,
                        keylen,
                        iv,
                        ivlen,
                        outputKeyStream,
                        keyStreamLength,
                        outputKeyStream);
}
} // namespace alcp::cipher::chacha20::zen4
