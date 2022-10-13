/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include <cstdint>

#include <immintrin.h>

#include "avx512.hh"
#include "cipher/aesni.hh"
#include "error.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

namespace alcp::cipher { namespace vaes512 {

    alc_error_t DecryptCfbAvx512(const uint8_t* pSrc,
                                 uint8_t*       pDest,
                                 uint64_t       len,
                                 const uint8_t* pKey,
                                 int            nRounds,
                                 const uint8_t* pIv)
    {
        alc_error_t err       = ALC_ERROR_NONE;
        auto        pkey128   = reinterpret_cast<const __m128i*>(pKey);
        auto        p_in_128  = reinterpret_cast<const __m128i*>(pSrc);
        auto        p_out_128 = reinterpret_cast<__m128i*>(pDest);

        __m512i a1, a2, a3, a4;
        __m512i b1, b2, b3, b4;
        __m512i _a1;

        uint64_t blocks = len / Rijndael::cBlockSize;

        __m512i key_512_0, key_512_1, key_512_2, key_512_3, key_512_4,
            key_512_5, key_512_6, key_512_7, key_512_8, key_512_9, key_512_10,
            key_512_11, key_512_12, key_512_13, key_512_14;
        alcp_load_key_zmm(pkey128,
                          key_512_0,
                          key_512_1,
                          key_512_2,
                          key_512_3,
                          key_512_4,
                          key_512_5,
                          key_512_6,
                          key_512_7,
                          key_512_8,
                          key_512_9,
                          key_512_10,
                          key_512_11,
                          key_512_12,
                          key_512_13,
                          key_512_14);

        // IV load 128 into lower 128 bits of 512 bit register.
        b1 = alcp_loadu_128((const __m512i*)pIv);

        if (blocks >= 1) {
            a1 = alcp_loadu_128((const __m512i*)p_in_128);

            vaes512::AesEncryptNoLoad_1x512(b1,
                                            key_512_0,
                                            key_512_1,
                                            key_512_2,
                                            key_512_3,
                                            key_512_4,
                                            key_512_5,
                                            key_512_6,
                                            key_512_7,
                                            key_512_8,
                                            key_512_9,
                                            key_512_10,
                                            key_512_11,
                                            key_512_12,
                                            key_512_13,
                                            key_512_14,
                                            nRounds);

            a1 = alcp_xor(a1, b1);

            alcp_storeu_128((__m512i*)p_out_128, a1);
            p_in_128++;
            p_out_128++;
            blocks--;
        }

        for (; blocks >= 16; blocks -= 16) {

            // Load a(cipher text) to xor
            a1 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 0);
            a2 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 1);
            a3 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 2);
            a4 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 3);

            // Load b(cipher text offset -1) to reencrypt and xor
            b1 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 0);
            b2 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 1);
            b3 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 2);
            b4 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 3);

            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
                                            key_512_0,
                                            key_512_1,
                                            key_512_2,
                                            key_512_3,
                                            key_512_4,
                                            key_512_5,
                                            key_512_6,
                                            key_512_7,
                                            key_512_8,
                                            key_512_9,
                                            key_512_10,
                                            key_512_11,
                                            key_512_12,
                                            key_512_13,
                                            key_512_14,
                                            nRounds);

            // Xor reencrypted previous cipher text with current cipher text
            a1 = alcp_xor(a1, b1);
            a2 = alcp_xor(a2, b2);
            a3 = alcp_xor(a3, b3);
            a4 = alcp_xor(a4, b4);

            // Store the decrypted cipher text back
            alcp_storeu((__m512i*)p_out_128, a1);
            alcp_storeu(((__m512i*)p_out_128) + 1, a2);
            alcp_storeu(((__m512i*)p_out_128) + 2, a3);
            alcp_storeu(((__m512i*)p_out_128) + 3, a4);
            p_in_128 += 16;
            p_out_128 += 16;
        }

        for (; blocks >= 8; blocks -= 8) {

            // Load a(cipher text) to xor
            a1 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 0);
            a2 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 1);

            // Load b(cipher text offset -1) to reencrypt and xor
            b1 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 0);
            b2 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 1);

            vaes512::AesEncryptNoLoad_2x512(b1,
                                            b2,
                                            key_512_0,
                                            key_512_1,
                                            key_512_2,
                                            key_512_3,
                                            key_512_4,
                                            key_512_5,
                                            key_512_6,
                                            key_512_7,
                                            key_512_8,
                                            key_512_9,
                                            key_512_10,
                                            key_512_11,
                                            key_512_12,
                                            key_512_13,
                                            key_512_14,
                                            nRounds);

            // Xor reencrypted previous cipher text with current cipher text
            a1 = alcp_xor(a1, b1);
            a2 = alcp_xor(a2, b2);

            // Store the decrypted cipher text back
            alcp_storeu((__m512i*)p_out_128, a1);
            alcp_storeu(((__m512i*)p_out_128) + 1, a2);
            p_in_128 += 8;
            p_out_128 += 8;
        }

        for (; blocks >= 4; blocks -= 4) {

            // Load a(cipher text) to xor
            a1 = alcp_loadu(((const __m512i*)(p_in_128 - 0)) + 0);

            // Load b(cipher text offset -1) to reencrypt and xor
            b1 = alcp_loadu(((const __m512i*)(p_in_128 - 1)) + 0);

            vaes512::AesEncryptNoLoad_1x512(b1,
                                            key_512_0,
                                            key_512_1,
                                            key_512_2,
                                            key_512_3,
                                            key_512_4,
                                            key_512_5,
                                            key_512_6,
                                            key_512_7,
                                            key_512_8,
                                            key_512_9,
                                            key_512_10,
                                            key_512_11,
                                            key_512_12,
                                            key_512_13,
                                            key_512_14,
                                            nRounds);

            // Xor reencrypted previous cipher text with current cipher text
            a1 = alcp_xor(a1, b1);

            // Store the decrypted cipher text back
            alcp_storeu((__m512i*)p_out_128, a1);
            p_in_128 += 4;
            p_out_128 += 4;
        }

        // Load previous CT to b1 to chain block 1 by 1
        if (blocks >= 1) {
            b1 = alcp_loadu_128((const __m512i*)(p_in_128 - 1));
        }

        // Chain block individually and decrypt
        for (; blocks >= 1; blocks--) {
            a1 = _a1 = alcp_loadu_128((const __m512i*)p_in_128);

            vaes512::AesEncryptNoLoad_1x512(b1,
                                            key_512_0,
                                            key_512_1,
                                            key_512_2,
                                            key_512_3,
                                            key_512_4,
                                            key_512_5,
                                            key_512_6,
                                            key_512_7,
                                            key_512_8,
                                            key_512_9,
                                            key_512_10,
                                            key_512_11,
                                            key_512_12,
                                            key_512_13,
                                            key_512_14,
                                            nRounds);

            a1 = alcp_xor(a1, b1);

            b1 = _a1;
            alcp_storeu_128((__m512i*)p_out_128, a1);
            p_in_128++;
            p_out_128++;
        }

        // clear all keys in registers.
        key_512_0  = _mm512_setzero_si512();
        key_512_1  = _mm512_setzero_si512();
        key_512_2  = _mm512_setzero_si512();
        key_512_3  = _mm512_setzero_si512();
        key_512_4  = _mm512_setzero_si512();
        key_512_5  = _mm512_setzero_si512();
        key_512_6  = _mm512_setzero_si512();
        key_512_7  = _mm512_setzero_si512();
        key_512_8  = _mm512_setzero_si512();
        key_512_9  = _mm512_setzero_si512();
        key_512_10 = _mm512_setzero_si512();
        key_512_11 = _mm512_setzero_si512();
        key_512_12 = _mm512_setzero_si512();
        key_512_13 = _mm512_setzero_si512();
        key_512_14 = _mm512_setzero_si512();

        assert(blocks == 0);

        return err;
    }
}} // namespace alcp::cipher::vaes512
