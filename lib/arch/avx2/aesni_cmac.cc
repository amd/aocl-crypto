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

#include "alcp/cipher/aesni.hh"
#include "alcp/mac/cmac.hh"
#include <immintrin.h>
#include <iostream>

namespace alcp::mac { namespace avx2 {

    inline void left_shift_1(__m128i& in, __m128i& out)
    {
        // Left Shift each 64 bit once
        out                = _mm_slli_epi64(in, 1);
        int       mask_bit = _mm_movemask_epi8(in);
        const int cLostBit = mask_bit & 0x80;

        if (cLostBit) {
            out = _mm_add_epi64(
                out,
                _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0));
        }
    }

    inline void shuffle_for_shifting(__m128i& in, __m128i& out)
    {
        __m128i shuffle_mask;
        shuffle_mask =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        out = _mm_shuffle_epi8(in, shuffle_mask);
    }

    inline void subkey_derive_singlestep(__m128i& test,
                                         __m128i& rb,
                                         __m128i& k,
                                         Uint8*   key)
    {
        __m128i temp;
        left_shift_1(test, temp);
        int msb = _mm_movemask_epi8(test) & 0x8000;
        if (msb) {
            // If MSB1(test) = 1, then key = (test << 1) ⊕ Rb
            k = _mm_xor_si128(rb, temp);
        } else {
            // If MSB1(test) = 0, then key = test << 1
            k = temp;
        }

        shuffle_for_shifting(k, temp);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(key), temp);
    }

    void get_subkeys(Uint8*       k1,
                     Uint8*       k2,
                     const Uint8* pEncryptKeys,
                     const Uint32 cNRounds)
    {

        /*Subkey Derivation Algorithm
            - defined in NIST Special Publication 800-38B Section 6.1
            - Optimized by avx2 intrinsics */

        __m128i k1_reg, k2_reg;

        // Rb is a predefined constant for the algorithm
        __m128i rb = _mm_set_epi16(0, 0, 0, 0, 0, 0, 0, 0x87);
        __m128i l  = _mm_set_epi32(0, 0, 0, 0);

        // Let L = CIPHK(0b)
        alcp::cipher::aesni::AesEncrypt(
            &l, (const __m128i*)pEncryptKeys, cNRounds);

        // Shuffling is necessary since _mm_slli_epi64 left shifts data as word
        // size integers
        shuffle_for_shifting(l, l);
        subkey_derive_singlestep(l, rb, k1_reg, k1);
        subkey_derive_singlestep(k1_reg, rb, k2_reg, k2);
    }

    void update(const Uint8* pPlaintext,
                Uint8*       pBuffer,
                const Uint8* pEncryptKeys,
                Uint8*       pEnc,
                Uint32       rounds,
                const Uint32 cNBlocks)
    {
        auto p_plaintext = reinterpret_cast<const __m128i*>(pPlaintext);
        auto p_buff      = reinterpret_cast<const __m128i*>(pBuffer);
        auto p_key       = reinterpret_cast<const __m128i*>(pEncryptKeys);
        auto p_temp_enc  = reinterpret_cast<__m128i*>(pEnc);

        __m128i a0 = _mm_load_si128(p_buff);
        __m128i a1 = _mm_load_si128(p_temp_enc);
        a1         = _mm_xor_si128(a1, a0);
        cipher::aesni::AesEncrypt(&a1, p_key, rounds);
        for (Uint32 i = 0; i < cNBlocks; i++) {
            a0 = _mm_loadu_si128(p_plaintext);
            a1 = _mm_xor_si128(a1, a0);
            cipher::aesni::AesEncrypt(&a1, p_key, rounds);
            p_plaintext++;
        }
        _mm_store_si128(p_temp_enc, a1);
    }

    void finalize(Uint8*       pBuff,
                  Uint32       buff_offset,
                  const Uint32 cBlockSize,
                  const Uint8* pSubKey1,
                  const Uint8* pSubKey2,
                  const Uint32 cRounds,
                  Uint8*       pEnc,
                  const Uint8* pEncryptKeys)
    {
        __m128i a0, b0, c0;
        auto    pBuff_128 = reinterpret_cast<__m128i*>(pBuff);
        auto    pEnc_128  = reinterpret_cast<__m128i*>(pEnc);

        // Check if storage_buffer is complete ie, Cipher Block Size bits
        if (buff_offset == cBlockSize) {
            a0          = _mm_load_si128(pBuff_128);
            auto reg_k1 = _mm_load_si128((__m128i*)pSubKey1);
            // Since the final block was complete, ie Cipher Block Size bit len,
            // xor storage buffer with k1 before final block processing
            b0 = _mm_xor_si128(reg_k1, a0);
        }
        // else: storage buffer is not complete. Pad it with 100000... to make
        // it complete
        else {
            /**
             * Set the first bit of the first byte of the unfilled bytes in
             * storage buffer as 1 and the remaining as zero
             */
            *(pBuff + buff_offset) = 0x80;
            buff_offset += 1;
            memset(pBuff + buff_offset, 0x00, cBlockSize - buff_offset);
            __m128i key2 = _mm_load_si128((__m128i*)pSubKey2);
            // Since the Final Block was Incomplete xor the already padded
            // storage buffer with k2 before final block processing.
            a0 = _mm_load_si128(pBuff_128);
            b0 = _mm_xor_si128(key2, a0);
        }
        // Process the Final Block
        c0 = _mm_load_si128((pEnc_128));
        c0 = _mm_xor_si128(c0, b0);
        alcp::cipher::aesni::AesEncrypt(
            &c0, (const __m128i*)pEncryptKeys, cRounds);
        _mm_store_si128(pEnc_128, c0);
    }

}} // namespace alcp::mac::avx2