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

#include "cipher/aesni.hh"
#include "mac/cmac.hh"
#include <immintrin.h>
#include <iostream>

namespace alcp::mac { namespace avx2 {

    inline void left_shift_1(reg_128& reg_input, reg_128& reg_output)
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
    inline void shuffle_for_shifting(reg_128& reg_input, reg_128& reg_output)
    {
        reg_128 shuffle_mask;
        shuffle_mask.reg =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        reg_output.reg = _mm_shuffle_epi8(reg_input.reg, shuffle_mask.reg);
    }

    void load_and_left_shift_1(const Uint8* input, Uint8* output)
    {
        reg_128 reg1, reg2;
        reg1.reg = _mm_loadu_si128((__m128i*)&input[0]);
        shuffle_for_shifting(reg1, reg1);
        left_shift_1(reg1, reg2);
        shuffle_for_shifting(reg2, reg2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output), reg2.reg);
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

    inline void subkey_derive_singlestep(reg_128&            test_reg,
                                         reg_128&            rb,
                                         reg_128&            key_reg,
                                         std::vector<Uint8>& key)
    {
        reg_128 left_shift_reg;
        left_shift_1(test_reg, left_shift_reg);
        int msb = _mm_movemask_epi8(test_reg.reg) & 0x8000;
        if (msb) {
            // If MSB1(test_reg) = 1, then key = (test_reg << 1) ⊕ Rb
            key_reg.reg = _mm_xor_si128(rb.reg, left_shift_reg.reg);
        } else {
            // If MSB1(test_reg) = 0, then key = test_reg << 1
            key_reg.reg = left_shift_reg.reg;
        }
        reg_128 temp_storage_reg;
        shuffle_for_shifting(key_reg, temp_storage_reg);
        // Store key to memory
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&key[0]),
                         temp_storage_reg.reg);
    }

    void get_subkeys(std::vector<Uint8>& k1,
                     std::vector<Uint8>& k2,
                     const Uint8*        encrypt_keys,
                     const int           n_rounds)
    {

        /*Subkey Derivation Algorithm
            - defined in NIST Special Publication 800-38B Section 6.1
            - Optimized by avx2 intrinsics */

        // Rb is a predefined constant for the algorithm
        reg_128 rb;
        rb.reg = _mm_set_epi16(0, 0, 0, 0, 0, 0, 0, 0x87);

        reg_128 L_reg;
        L_reg.reg =
            _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        // Let L = CIPHK(0b)
        alcp::cipher::aesni::AesEncrypt(
            &L_reg.reg, (const __m128i*)encrypt_keys, n_rounds);

        // Shuffling is necessary since _mm_slli_epi64 left shifts data as word
        // size integers
        shuffle_for_shifting(L_reg, L_reg);
        reg_128 k1_reg;
        subkey_derive_singlestep(L_reg, rb, k1_reg, k1);
        reg_128 k2_reg;
        subkey_derive_singlestep(k1_reg, rb, k2_reg, k2);
    }

    void update(const Uint8* plaintext, int plaintext_size,Uint8 storage_buffer[],
                int &storage_buffer_offset,const Uint8 encrypt_keys[],Uint8 temp_enc_result[],Uint32 rounds){
          /*Combined Bytes to be Processed including any data remainining in
         * storage buffer and data user has provided in the current update
         * function call */
        int total_bytes_to_be_processed =
            storage_buffer_offset + plaintext_size;

        /* To keep track of the total processed bytes combining data from
         * storage buffer and current update function call */
        int total_bytes_processed_so_far = 0;

        // To keep track of the remaining number of total bytes to be
        // processed combining storage buffer and plaintext buffer
        int bytes_left_to_process =
            total_bytes_to_be_processed - total_bytes_processed_so_far;

        // To keep track of only the plaintext bytes processed so far
        int plaintext_bytes_processed_so_far = 0;

        /* Buffer contains data only for single processing. This block is copied
           to temporary storage buffer so it can be processed either in finalize
           or subsequent updates
         */
        if (total_bytes_to_be_processed <= 16) {
            assert(plaintext_size <= 16);
            utils::CopyBytes(storage_buffer + storage_buffer_offset,
                             plaintext,
                             plaintext_size);
            storage_buffer_offset = storage_buffer_offset + plaintext_size;
            return;
        } 
        // If total remaining bytes to be processed is less than or equal to
        // 128 bits, break and copy the remaining data into temporary
        // storage buffer
        reg_128 temp_enc_result_reg;
        temp_enc_result_reg.reg = _mm_setzero_si128();
         int bytes_to_be_copied = 16 - storage_buffer_offset ;
        while (bytes_left_to_process > 16) {
            assert(bytes_to_be_copied >= 0);
            // Copy some data from plaintext buffer into temporary storage
            // buffer but only enough to perform one Cipher Operation, ie.
            // 128 bits
            if (bytes_to_be_copied > 0) {
                utils::CopyBytes(storage_buffer + storage_buffer_offset,
                                    plaintext
                                        + plaintext_bytes_processed_so_far,
                                    bytes_to_be_copied);
                plaintext_bytes_processed_so_far += bytes_to_be_copied;
                storage_buffer_offset += bytes_to_be_copied;
                bytes_to_be_copied =0;

            }
            if(bytes_left_to_process==total_bytes_to_be_processed){
                            temp_enc_result_reg.reg =
            _mm_xor_si128(_mm_loadu_si128((__m128i*)temp_enc_result),
                          _mm_loadu_si128((__m128i*)storage_buffer));
            }
            else{
                 temp_enc_result_reg.reg =
                _mm_xor_si128( temp_enc_result_reg.reg,
                          _mm_loadu_si128((__m128i*)(plaintext
                                        + plaintext_bytes_processed_so_far)));
                plaintext_bytes_processed_so_far += 16;
            }
        // Temporary storage buffer is full. Process it.
        alcp::cipher::aesni::AesEncrypt(
            &temp_enc_result_reg.reg, (const __m128i*)encrypt_keys, rounds);



            storage_buffer_offset = 0;

            // 128 bits was processed
            total_bytes_processed_so_far += 16;
            // combined bytes still left to process
            bytes_left_to_process =
                total_bytes_to_be_processed - total_bytes_processed_so_far;



        }
    
        utils::CopyBytes(storage_buffer + storage_buffer_offset,
                         plaintext + plaintext_bytes_processed_so_far,
                         bytes_left_to_process);
        _mm_storeu_si128((__m128i*)temp_enc_result, temp_enc_result_reg.reg);
        storage_buffer_offset += bytes_left_to_process;
    }
}} // namespace alcp::mac::avx2