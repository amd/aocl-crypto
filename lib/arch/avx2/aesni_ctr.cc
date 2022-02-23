/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include <wmmintrin.h>

#include "aesni_macros.hh"
#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "error.hh"
#include "key.hh"

namespace alcp::cipher::aesni {
alc_error_t
cryptCtr(const uint8_t* pPlainText,  // ptr to plaintext
         uint8_t*       pCipherText, // ptr to ciphertext
         uint64_t       len,         // message length in bytes
         const uint8_t* pKey,        // ptr to Key
         int            nRounds,     // No. of rounds
         const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err    = ALC_ERROR_NONE;
    uint64_t    blocks = len / Rijndael::cBlockSize;

    auto p_in_128  = reinterpret_cast<const __m128i*>(pPlainText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pCipherText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    __m128i a1, a2, a3, a4;
    __m128i ctr1, ctr2, ctr3, ctr4;

    // nonce counter
    ctr1              = _mm_loadu_si128((__m128i*)pIv);
    __m128i one_128   = _mm_set_epi32(0, 0, 0, 1);
    __m128i two_128   = _mm_set_epi32(0, 0, 0, 2);
    __m128i three_128 = _mm_set_epi32(0, 0, 0, 3);
    __m128i four_128  = _mm_set_epi32(0, 0, 0, 4);

    for (; blocks >= 4; blocks -= 4) {
        ctr2 = _mm_add_epi32(ctr1, one_128);
        ctr3 = _mm_add_epi32(ctr1, two_128);
        ctr4 = _mm_add_epi32(ctr1, three_128);

        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = _mm_loadu_si128(p_in_128 + 3);

        aesni::AesEncrypt(&ctr1, &ctr2, &ctr3, &ctr4, pkey128, nRounds);

        a1   = _mm_xor_si128(ctr1, a1);
        a2   = _mm_xor_si128(ctr2, a2);
        a3   = _mm_xor_si128(ctr3, a3);
        a4   = _mm_xor_si128(ctr4, a4);
        ctr1 = _mm_add_epi32(ctr1, four_128);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);
        _mm_storeu_si128(p_out_128 + 2, a3);
        _mm_storeu_si128(p_out_128 + 3, a4);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        a1 = _mm_loadu_si128(p_in_128);
        a2 = _mm_loadu_si128(p_in_128 + 1);

        aesni::AesEncrypt(&ctr1, &ctr2, pkey128, nRounds);

        a1   = _mm_xor_si128(ctr1, a1);
        a2   = _mm_xor_si128(ctr2, a2);
        ctr1 = _mm_add_epi32(ctr1, two_128);
        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        a1 = _mm_loadu_si128(p_in_128);

        aesni::AesEncrypt(&ctr1, pkey128, nRounds);
        a1   = _mm_xor_si128(ctr1, a1);
        ctr1 = _mm_add_epi32(ctr1, one_128);

        _mm_storeu_si128(p_out_128, a1);

        p_in_128++;
        p_out_128++;
    }

    return err;
}

alc_error_t
EncryptCtr(const uint8_t* pPlainText,  // ptr to plaintext
           uint8_t*       pCipherText, // ptr to ciphertext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptCtr(pPlainText,  // ptr to inputText
                   pCipherText, // ptr to outputtext
                   len,         // message length in bytes
                   pKey,        // ptr to Key
                   nRounds,     // No. of rounds
                   pIv);        // ptr to Initialization Vector
    return err;
}

alc_error_t
DecryptCtr(const uint8_t* pCipherText, // ptr to ciphertext
           uint8_t*       pPlainText,  // ptr to plaintext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptCtr(pCipherText, // ptr to inputText
                   pPlainText,  // ptr to outputtext
                   len,         // message length in bytes
                   pKey,        // ptr to Key
                   nRounds,     // No. of rounds
                   pIv);        // ptr to Initialization Vector

    return err;
}

} // namespace alcp::cipher::aesni
