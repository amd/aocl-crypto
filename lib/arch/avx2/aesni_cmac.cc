/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

// #include "error.hh"
#include "cipher/aesni.hh"
#include "mac/cmac.hh"
#include <immintrin.h>
#include <iostream>

namespace alcp::mac { namespace avx2 {

    void left_shift_1(reg_128& reg_input, reg_128& reg_output)
    {
        reg_output.reg =
            _mm_slli_epi64(reg_input.reg, 1); // Left Shift each 64 bit once
        int       mask_bit = _mm_movemask_epi8(reg_input.reg);
        const int cLostBit = mask_bit & 0x80;

        if (cLostBit) {
            reg_output.reg = _mm_add_epi64(
                reg_output.reg,
                _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0));
        }
    }

    void processChunk(Uint8*       temp_enc_result,
                      Uint8*       storage_buffer,
                      const Uint8* encrypt_keys,
                      const int    n_rounds)
    {

        reg_128 temp_enc_result_reg;
        temp_enc_result_reg.reg =
            _mm_xor_si128(_mm_loadu_si128((__m128i*)temp_enc_result),
                          _mm_loadu_si128((__m128i*)storage_buffer));
        alcp::cipher::aesni::AesEncrypt(
            &temp_enc_result_reg.reg, (const __m128i*)encrypt_keys, n_rounds);
        _mm_storeu_si128((__m128i*)temp_enc_result, temp_enc_result_reg.reg);
    }

    void get_subkeys(std::vector<Uint8>& k1,
                     std::vector<Uint8>& k2,
                     const Uint8*        encrypt_keys,
                     const int           n_rounds)
    {

        // Subkey Derivation Algorithm
        // [defined in NIST Special Publication 800-38B Section 6.1]
        // Optimized by avx2 intrinsics
        uint32_t L[] = { 0x0, 0x0, 0x0, 0x0 };
        reg_128  L_reg;
        L_reg.reg = _mm_loadu_si128((__m128i*)L);

        // Let L = CIPHK(0b)
        alcp::cipher::aesni::AesEncrypt(
            &L_reg.reg, (const __m128i*)encrypt_keys, n_rounds);

        reg_128 L_left_shift_1, shuffle_mask;
        // Shuffling is necessary since _mm_slli_epi64 left shifts data as word
        // size integers
        shuffle_mask.reg =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        L_reg.reg = _mm_shuffle_epi8(L_reg.reg, shuffle_mask.reg);
        left_shift_1(L_reg, L_left_shift_1);

        // Rb is a predefined constant for the algorithm
        reg_128 rb;
        rb.reg = _mm_set_epi16(0, 0, 0, 0, 0, 0, 0, 0x87);

        reg_128 k1_reg;
        int     msb = _mm_movemask_epi8(L_reg.reg) & 0x8000;
        if (msb) {
            // If MSB1(L) = 1, then K1 = (L << 1) ⊕ Rb
            k1_reg.reg = _mm_xor_si128(rb.reg, L_left_shift_1.reg);
        } else {
            // If MSB1(L) = 0, then K1 = L << 1
            k1_reg.reg = L_left_shift_1.reg;
        }
        // Store key1 to memory pointed by k1
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&k1[0]),
                         _mm_shuffle_epi8(k1_reg.reg, shuffle_mask.reg));

        reg_128 k1_ls1_reg;
        left_shift_1(k1_reg, k1_ls1_reg);

        reg_128 k2_reg;
        msb = _mm_movemask_epi8(k1_reg.reg) & 0x8000;
        if (msb) {
            // If MSB1(K1) = 0, then K2 = (K1 << 1) ⊕ Rb
            k2_reg.reg = _mm_xor_si128(rb.reg, k1_ls1_reg.reg);
        } else {
            // If MSB1(K1) = 0, then K2 = K1 << 1
            k2_reg.reg = k1_ls1_reg.reg;
        }
        // Store key2 to memory pointed by k2
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&k2[0]),
                         _mm_shuffle_epi8(k2_reg.reg, shuffle_mask.reg));
    }
}} // namespace alcp::mac::avx2