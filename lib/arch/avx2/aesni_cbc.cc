/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aesni.hh"
#include "alcp/types.hh"
#include "avx2.hh"

#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher::aesni {

template<void AesEnc_1x128(__m128i* pBlk0, const __m128i* pKey, int nRounds)>
alc_error_t
EncryptCbc(const Uint8* pPlainText,  // ptr to plaintext
           Uint8*       pCipherText, // ptr to ciphertext
           Uint64       len,         // message length in bytes
           const Uint8* pKey,        // ptr to Key
           int          nRounds,     // No. of rounds
           Uint8*       pIv          // ptr to Initialization Vector
)
{
    alc_error_t err    = ALC_ERROR_NONE;
    Uint64      blocks = len / Rijndael::cBlockSize;
    __m128i     a1; // plaintext data
    __m128i     b1;

    auto p_in_128  = reinterpret_cast<const __m128i*>(pPlainText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pCipherText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    b1 = _mm_loadu_si128((__m128i*)pIv);

    for (; blocks >= 1; blocks--) {
        a1 = _mm_loadu_si128(p_in_128);
        b1 = _mm_xor_si128(a1, b1);

        AesEnc_1x128(&b1, pkey128, nRounds);

        _mm_storeu_si128(p_out_128, b1);
        p_in_128++;
        p_out_128++;
    }

    // IV is no longer needed hence we can write the old ciphertext back to IV
    alcp_storeu_128(reinterpret_cast<__m128i*>(pIv), b1);

    return err;
}

template<void AesDec_1x128(__m128i* pBlk0, const __m128i* pKey, int nRounds),
         void AesDec_2x128(
             __m128i* pBlk0, __m128i* pBlk1, const __m128i* pKey, int nRounds),
         void AesDec_4x128(__m128i*       pBlk0,
                           __m128i*       pBlk1,
                           __m128i*       pBlk2,
                           __m128i*       pBlk3,
                           const __m128i* pKey,
                           int            nRounds),
         void AesDec_8x128(__m128i*       pBlk0,
                           __m128i*       pBlk1,
                           __m128i*       pBlk2,
                           __m128i*       pBlk3,
                           __m128i*       pBlk4,
                           __m128i*       pBlk5,
                           __m128i*       pBlk6,
                           __m128i*       pBlk7,
                           const __m128i* pKey,
                           int            nRounds)>
alc_error_t
DecryptCbc(const Uint8* pCipherText, // ptr to ciphertext
           Uint8*       pPlainText,  // ptr to plaintext
           Uint64       len,         // message length in bytes
           const Uint8* pKey,        // ptr to Key
           int          nRounds,     // No. of rounds
           Uint8*       pIv          // ptr to Initialization Vector
)
{
    Uint64      blocks = len / Rijndael::cBlockSize;
    alc_error_t err    = ALC_ERROR_NONE;

    auto p_in_128  = reinterpret_cast<const __m128i*>(pCipherText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pPlainText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    __m128i input_128_a1, input_128_a2, input_128_a3, input_128_a4;
    __m128i a1, a2, a3, a4, b1;
    b1 = _mm_loadu_si128((__m128i*)pIv);

    __m128i a5, a6, a7, a8;
    __m128i input_128_a5, input_128_a6, input_128_a7, input_128_a8;
    for (; blocks >= 8; blocks -= 8) {
        a1 = input_128_a1 = _mm_loadu_si128(p_in_128);
        a2 = input_128_a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = input_128_a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = input_128_a4 = _mm_loadu_si128(p_in_128 + 3);

        a5 = input_128_a5 = _mm_loadu_si128(p_in_128 + 4);
        a6 = input_128_a6 = _mm_loadu_si128(p_in_128 + 5);
        a7 = input_128_a7 = _mm_loadu_si128(p_in_128 + 6);
        a8 = input_128_a8 = _mm_loadu_si128(p_in_128 + 7);

        AesDec_8x128(&a1, &a2, &a3, &a4, &a5, &a6, &a7, &a8, pkey128, nRounds);

        a1 = _mm_xor_si128(a1, b1);
        a2 = _mm_xor_si128(a2, input_128_a1);
        a3 = _mm_xor_si128(a3, input_128_a2);
        a4 = _mm_xor_si128(a4, input_128_a3);
        a5 = _mm_xor_si128(a5, input_128_a4);
        a6 = _mm_xor_si128(a6, input_128_a5);
        a7 = _mm_xor_si128(a7, input_128_a6);
        a8 = _mm_xor_si128(a8, input_128_a7);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);
        _mm_storeu_si128(p_out_128 + 2, a3);
        _mm_storeu_si128(p_out_128 + 3, a4);
        _mm_storeu_si128(p_out_128 + 4, a5);
        _mm_storeu_si128(p_out_128 + 5, a6);
        _mm_storeu_si128(p_out_128 + 6, a7);
        _mm_storeu_si128(p_out_128 + 7, a8);

        b1 = input_128_a8;
        p_in_128 += 8;
        p_out_128 += 8;
    }

    for (; blocks >= 4; blocks -= 4) {
        a1 = input_128_a1 = _mm_loadu_si128(p_in_128);
        a2 = input_128_a2 = _mm_loadu_si128(p_in_128 + 1);
        a3 = input_128_a3 = _mm_loadu_si128(p_in_128 + 2);
        a4 = input_128_a4 = _mm_loadu_si128(p_in_128 + 3);

        AesDec_4x128(&a1, &a2, &a3, &a4, pkey128, nRounds);

        a1 = _mm_xor_si128(a1, b1);
        a2 = _mm_xor_si128(a2, input_128_a1);
        a3 = _mm_xor_si128(a3, input_128_a2);
        a4 = _mm_xor_si128(a4, input_128_a3);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);
        _mm_storeu_si128(p_out_128 + 2, a3);
        _mm_storeu_si128(p_out_128 + 3, a4);

        b1 = input_128_a4;
        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        a1 = input_128_a1 = _mm_loadu_si128(p_in_128);
        a2 = input_128_a2 = _mm_loadu_si128(p_in_128 + 1);

        AesDec_2x128(&a1, &a2, pkey128, nRounds);

        a1 = _mm_xor_si128(a1, b1);
        a2 = _mm_xor_si128(a2, input_128_a1);

        _mm_storeu_si128(p_out_128, a1);
        _mm_storeu_si128(p_out_128 + 1, a2);

        b1 = input_128_a2;
        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        a1 = input_128_a1 = _mm_loadu_si128(p_in_128);

        AesDec_1x128(&a1, pkey128, nRounds);
        a1 = _mm_xor_si128(a1, b1);

        _mm_storeu_si128(p_out_128, a1);
        b1 = input_128_a1;
        p_in_128++;
        p_out_128++;
    }

    // IV is no longer needed hence we can write the old ciphertext back to IV
    alcp_storeu_128(reinterpret_cast<__m128i*>(pIv), b1);

    return err;
}

ALCP_API_EXPORT alc_error_t
EncryptCbc128(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return EncryptCbc<aesni::AesEncrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

ALCP_API_EXPORT alc_error_t
EncryptCbc192(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return EncryptCbc<aesni::AesEncrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

ALCP_API_EXPORT alc_error_t
EncryptCbc256(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return EncryptCbc<aesni::AesEncrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

// Decrypt Functions
alc_error_t
DecryptCbc128(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

alc_error_t
DecryptCbc192(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

alc_error_t
DecryptCbc256(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt,
                      aesni::AesDecrypt>(pSrc, pDest, len, pKey, nRounds, pIv);
}

} // namespace alcp::cipher::aesni
