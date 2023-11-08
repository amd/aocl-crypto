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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "alcp/types.h"
#include "alcp/utils/copy.hh"
#include <immintrin.h>
namespace alcp::mac { namespace avx2 {

    void get_k0_xor_opad(Uint32 m_input_block_length,
                         Uint8* m_pK0,
                         Uint8* m_pK0_xor_ipad,
                         Uint8* m_pK0_xor_opad)
    {

        constexpr int register_size = 128, // sizeof(__m128i)*8
            no_optimized_xor =
                2; // No. of XORs performed inside the for loop below

        // Fixed values from the specification
        constexpr Uint64 opad_value = 0x5c5c, ipad_value = 0x3636;

        const int input_block_length_bits = m_input_block_length * 8;

        // No of optimized xor output bits that will result from each iteration
        // in the loop
        const int optimized_bits_per_xor = no_optimized_xor * register_size;
        const int no_of_xor_operations =
            input_block_length_bits / optimized_bits_per_xor;

        __m128i* pi_k0          = reinterpret_cast<__m128i*>(m_pK0);
        __m128i* pi_k0_xor_ipad = reinterpret_cast<__m128i*>(m_pK0_xor_ipad);
        __m128i* pi_k0_xor_opad = reinterpret_cast<__m128i*>(m_pK0_xor_opad);
        __m128i  reg_k0_1;
        __m128i  reg_k0_xor_ipad_1;
        __m128i  reg_k0_xor_opad_1;
        __m128i  reg_k0_2;
        __m128i  reg_k0_xor_ipad_2;
        __m128i  reg_k0_xor_opad_2;

        const __m128i reg_opad = _mm_set_epi16(opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value);
        const __m128i reg_ipad = _mm_set_epi16(ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value);

        /** TODO: Consider adding more optimized XOR Operations and reducing the
        register usage */
        for (int i = 0; i < no_of_xor_operations; i += 1) {
            // Load 128 bit key
            reg_k0_1 = _mm_load_si128(pi_k0);
            // Load the next 128 bit key
            reg_k0_2 = _mm_load_si128(pi_k0 + 1);

            // Perform XOR
            reg_k0_xor_ipad_1 = _mm_xor_si128(reg_k0_1, reg_ipad);
            reg_k0_xor_opad_1 = _mm_xor_si128(reg_k0_1, reg_opad);
            reg_k0_xor_ipad_2 = _mm_xor_si128(reg_k0_2, reg_ipad);
            reg_k0_xor_opad_2 = _mm_xor_si128(reg_k0_2, reg_opad);

            // Store the XOR Result
            _mm_store_si128(pi_k0_xor_ipad, reg_k0_xor_ipad_1);
            _mm_store_si128(pi_k0_xor_opad, reg_k0_xor_opad_1);
            _mm_store_si128((pi_k0_xor_ipad + 1), reg_k0_xor_ipad_2);
            _mm_store_si128(pi_k0_xor_opad + 1, reg_k0_xor_opad_2);

            // Increment for the next 256 bits
            pi_k0_xor_ipad += no_optimized_xor;
            pi_k0_xor_opad += no_optimized_xor;
            pi_k0 += no_optimized_xor;
        }

        /**
         *  Obtain Uint8* pointers from the register pointers for remaining
         * unoptimized xor
         */
        Uint8* current_temp_k0_xor_ipad =
            reinterpret_cast<Uint8*>(pi_k0_xor_ipad);
        Uint8* current_temp_k0_xor_opad =
            reinterpret_cast<Uint8*>(pi_k0_xor_opad);
        auto            p_k0 = reinterpret_cast<Uint8*>(pi_k0);
        constexpr Uint8 ipad = 0x36;
        constexpr Uint8 opad = 0x5c;

        // Calculating unoptimized xor_operations based on completed optimized
        // xor operation
        const int xor_operations_left =
            (input_block_length_bits
             - no_of_xor_operations * (optimized_bits_per_xor))
            / 8;

        // Unoptimized XOR operation
        for (int i = 0; i < xor_operations_left; i++) {
            *current_temp_k0_xor_ipad = *p_k0 ^ ipad;
            *current_temp_k0_xor_opad = *p_k0 ^ opad;
            p_k0++;
            current_temp_k0_xor_ipad++;
            current_temp_k0_xor_opad++;
        }
    }
    void copyData(Uint8* destination, const Uint8* source, int len)
    {
        utils::CopyBlock<Uint64>(destination, source, len);
    }

}} // namespace alcp::mac::avx2