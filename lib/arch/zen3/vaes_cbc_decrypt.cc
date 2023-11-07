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

#include "vaes.hh"

#include "alcp/cipher/aes.hh"
#include "alcp/types.hh"

#include <immintrin.h>

namespace alcp::cipher::vaes {

template<void AesDec_1x128(__m256i* pBlk0, const __m128i* pKey, int nRounds),
         void AesDec_2x128(
             __m256i* pBlk0, __m256i* pBlk1, const __m128i* pKey, int nRounds),
         void AesDec_4x128(__m256i*       pBlk0,
                           __m256i*       pBlk1,
                           __m256i*       pBlk2,
                           __m256i*       pBlk3,
                           const __m128i* pKey,
                           int            nRounds)>
alc_error_t
DecryptCbc(const Uint8* pCipherText, // ptr to ciphertext
           Uint8*       pPlainText,  // ptr to plaintext
           Uint64       len,         // message length in bytes
           const Uint8* pKey,        // ptr to Key
           int          nRounds,     // No. of rounds
           const Uint8* pIv          // ptr to Initialization Vector
)
{
    Uint64      blocks = len / Rijndael::cBlockSize;
    alc_error_t err    = ALC_ERROR_NONE;

    auto p_in_128  = reinterpret_cast<const __m128i*>(pCipherText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pPlainText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    // Mask for loading and storing half register
    __m256i mask_lo = _mm256_set_epi64x(0,
                                        0,
                                        static_cast<long long>(1UL) << 63,
                                        static_cast<long long>(1UL) << 63);

    __m256i input_128_a1;

    __m256i a1, a2, a3, a4;
    __m256i b1, b2, b3, b4;
    b1 = _mm256_maskload_epi64((long long*)pIv, mask_lo);

    // First block is an exception, it needs to be xord with IV
    if (blocks >= 1) {
        a1 = input_128_a1 =
            _mm256_maskload_epi64((long long*)p_in_128, mask_lo);

        vaes::AesDecrypt(&a1, pkey128, nRounds);
        a1 = _mm256_xor_si256(a1, b1);

        _mm256_maskstore_epi64((long long*)p_out_128, mask_lo, a1);
        b1 = input_128_a1;
        p_in_128++;
        p_out_128++;
        blocks--;
    }

    // Process 8 blocks at a time
    for (; blocks >= 8; blocks -= 8) {
        // Note below uses up 1 Kilobit of data, 128 bytes
        // Load in the format a1 = c1,c2.
        a1 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 0);
        a2 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 1);
        a3 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 2);
        a4 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 3);
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = input_128_a1 = _mm256_loadu_si256((__m256i*)(p_in_128 - 1) + 0);
        b2 = input_128_a1 = _mm256_loadu_si256(((__m256i*)(p_in_128 - 1)) + 1);
        b3 = input_128_a1 = _mm256_loadu_si256(((__m256i*)(p_in_128 - 1)) + 2);
        b4 = input_128_a1 = _mm256_loadu_si256(((__m256i*)(p_in_128 - 1)) + 3);

        AesDec_4x128(&a1, &a2, &a3, &a4, pkey128, nRounds);

        // Do xor with previous cipher text to complete decryption.
        a1 = _mm256_xor_si256(a1, b1);
        a2 = _mm256_xor_si256(a2, b2);
        a3 = _mm256_xor_si256(a3, b3);
        a4 = _mm256_xor_si256(a4, b4);

        // Store decrypted blocks.
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), a1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 1, a2);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 2, a3);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 3, a4);

        p_in_128 += 8;
        p_out_128 += 8;
    }

    // Process 4 blocks at a time
    for (; blocks >= 4; blocks -= 4) {
        // Note below uses up 0.5 Kilobit of data, 64 bytes
        // Load in the format a1 = c1,c2.
        a1 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 0);
        a2 = input_128_a1 = _mm256_loadu_si256(((__m256i*)p_in_128 - 0) + 1);
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = input_128_a1 = _mm256_loadu_si256((__m256i*)(p_in_128 - 1) + 0);
        b2 = input_128_a1 = _mm256_loadu_si256(((__m256i*)(p_in_128 - 1)) + 1);

        AesDec_2x128(&a1, &a2, pkey128, nRounds);

        // Do xor with previous cipher text to complete decryption.
        a1 = _mm256_xor_si256(a1, b1);
        a2 = _mm256_xor_si256(a2, b2);

        // Store decrypted blocks.
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), a1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 1, a2);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    // Process 2 blocks at a time
    for (; blocks >= 2; blocks -= 2) {
        // Note below uses up 0.25 Kilobit of data, 32 bytes
        // Load in the format a1 = c1,c2.
        a1 = input_128_a1 = _mm256_loadu_si256((__m256i*)p_in_128);
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = input_128_a1 = _mm256_loadu_si256((__m256i*)(p_in_128 - 1));

        AesDec_1x128(&a1, pkey128, nRounds);

        // Do xor with previous cipher text to complete decryption.
        a1 = _mm256_xor_si256(a1, b1);

        // Store decrypted blocks.
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), a1);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    // If more blocks are left, prepare b1 with cN-1 cuz need for xor
    if (blocks >= 1)
        b1 = _mm256_maskload_epi64((long long*)(p_in_128 - 1), mask_lo);

    for (; blocks >= 1; blocks -= 1) {
        // Load the Nth block
        a1 = input_128_a1 =
            _mm256_maskload_epi64((long long*)p_in_128, mask_lo);

        AesDec_1x128(&a1, pkey128, nRounds);

        // Do xor with previous cipher text to complete decryption.
        a1 = _mm256_xor_si256(a1, b1);

        // Store decrypted block.
        _mm256_maskstore_epi64((long long*)p_out_128, mask_lo, a1);

        b1 = input_128_a1;
        p_in_128++;
        p_out_128++;
    }

    return err;
}

ALCP_API_EXPORT alc_error_t
DecryptCbc128(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              const Uint8* pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<vaes::AesDecrypt, vaes::AesDecrypt, vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

ALCP_API_EXPORT alc_error_t
DecryptCbc192(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              const Uint8* pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<vaes::AesDecrypt, vaes::AesDecrypt, vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

ALCP_API_EXPORT alc_error_t
DecryptCbc256(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              const Uint8* pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<vaes::AesDecrypt, vaes::AesDecrypt, vaes::AesDecrypt>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

} // namespace alcp::cipher::vaes
