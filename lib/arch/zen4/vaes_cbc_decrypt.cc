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

#include "alcp/base.hh"

#include <cstdint>
#include <immintrin.h>

#include "alcp/cipher/aes.hh"
#include "avx512.hh"

#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

namespace alcp::cipher::vaes512 {

template<void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
         void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
         void AesEncNoLoad_4x512(
             __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
alc_error_t inline DecryptCbc(const Uint8* pCipherText, // ptr to ciphertext
                              Uint8*       pPlainText,  // ptr to plaintext
                              Uint64       len,     // message length in bytes
                              const Uint8* pKey,    // ptr to Key
                              int          nRounds, // No. of rounds
                              Uint8*       pIv // ptr to Initialization Vector
)
{
    Uint64      blocks = len / Rijndael::cBlockSize;
    alc_error_t err    = ALC_ERROR_NONE;

    auto p_in_128  = reinterpret_cast<const __m128i*>(pCipherText);
    auto p_out_128 = reinterpret_cast<__m128i*>(pPlainText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    __m512i input_128_a1;

    __m512i a1, a2, a3, a4;
    __m512i b1, b2, b3, b4;

    sKeys keys = {};

    alcp_load_key_zmm(pkey128, keys);

    // Load IV into b1 to process 1st block.
    b1 = alcp_loadu_128((const __m512i*)pIv);

    // First block is an exception, it needs to be xord with IV
    if (blocks >= 1) {
        a1 = input_128_a1 = alcp_loadu_128((const __m512i*)p_in_128);

        AesEncNoLoad_1x512(a1, keys);

        a1 = alcp_xor(a1, b1);

        alcp_storeu_128((__m512i*)p_out_128, a1);
        b1 = input_128_a1;
        p_in_128++;
        p_out_128++;
        blocks--;
    }
    // Process 16 (1x128x16) blocks at a time
    for (; blocks >= 16; blocks -= 16) {
        // Note below uses up 1 Kilobit of data, 128 bytes
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 0);
        b2 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 1);
        b3 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 2);
        b4 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 3);
        // Load in the format a1 = c1,c2.
        a1 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 0);
        a2 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 1);
        a3 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 2);
        a4 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 3);

        AesEncNoLoad_4x512(a1, a2, a3, a4, keys);

        // Do xor with previous cipher text to complete decryption.
        a1 = alcp_xor(a1, b1);
        a2 = alcp_xor(a2, b2);
        a3 = alcp_xor(a3, b3);
        a4 = alcp_xor(a4, b4);

        // Store decrypted blocks.
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 0, a1);
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 1, a2);
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 2, a3);
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 3, a4);

        p_in_128 += 16;
        p_out_128 += 16;
    }

    // Process 8 (1x128x8) blocks at a time
    for (; blocks >= 8; blocks -= 8) {
        // Note below uses up 1 Kilobit of data, 128 bytes
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 0);
        b2 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 1);
        // Load in the format a1 = c1,c2.
        a1 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 0);
        a2 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 1);

        AesEncNoLoad_2x512(a1, a2, keys);

        // Do xor with previous cipher text to complete decryption.
        a1 = alcp_xor(a1, b1);
        a2 = alcp_xor(a2, b2);

        // Store decrypted blocks.
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 0, a1);
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128) + 1, a2);

        p_in_128 += 8;
        p_out_128 += 8;
    }

    // Process 4 (1x128x4) blocks at a time
    for (; blocks >= 4; blocks -= 4) {
        // Note below uses up 1 Kilobit of data, 128 bytes
        // Load in the format b1 = c0,c1. Counting on cache to have data
        b1 = alcp_loadu(((__m512i*)(p_in_128 - 1)) + 0);
        // Load in the format a1 = c1,c2.
        a1 = alcp_loadu(((__m512i*)(p_in_128 - 0)) + 0);

        AesEncNoLoad_2x512(a1, a2, keys);

        // Do xor with previous cipher text to complete decryption.
        a1 = alcp_xor(a1, b1);

        // Store decrypted blocks.
        alcp_storeu(reinterpret_cast<__m512i*>(p_out_128), a1);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    // If more blocks are left, prepare b1 with cN-1 cuz need for xor
    if (blocks >= 1)
        b1 = alcp_loadu_128((const __m512i*)(p_in_128 - 1));

    for (; blocks >= 1; blocks -= 1) {
        // Load the Nth block
        a1 = input_128_a1 = alcp_loadu_128((const __m512i*)p_in_128);

        AesEncNoLoad_1x512(a1, keys);
        // Do xor with previous cipher text to complete decryption.
        a1 = alcp_xor(a1, b1);

        // Store decrypted block.
        alcp_storeu_128((__m512i*)p_out_128, a1);

        b1 = input_128_a1;
        p_in_128++;
        p_out_128++;
    }

#ifdef AES_MULTI_UPDATE
    // IV is no longer needed hence we can write the old ciphertext back to IV
    alcp_storeu_128(reinterpret_cast<__m512i*>(pIv), b1);
#endif

    alcp_clear_keys_zmm(keys);

    return err;
}

alc_error_t
DecryptCbc128(const Uint8* pSrc,    // ptr to ciphertext
              Uint8*       pDest,   // ptr to plaintext
              Uint64       len,     // message length in bytes
              const Uint8* pKey,    // ptr to Key
              int          nRounds, // No. of rounds
              Uint8*       pIv      // ptr to Initialization Vector
)
{
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds10,
                      AesDecryptNoLoad_2x512Rounds10,
                      AesDecryptNoLoad_4x512Rounds10,
                      alcp_load_key_zmm_10rounds,
                      alcp_clear_keys_zmm_10rounds>(
        pSrc, pDest, len, pKey, nRounds, pIv);
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
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds12,
                      AesDecryptNoLoad_2x512Rounds12,
                      AesDecryptNoLoad_4x512Rounds12,
                      alcp_load_key_zmm_12rounds,
                      alcp_clear_keys_zmm_12rounds>(
        pSrc, pDest, len, pKey, nRounds, pIv);
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
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds14,
                      AesDecryptNoLoad_2x512Rounds14,
                      AesDecryptNoLoad_4x512Rounds14,
                      alcp_load_key_zmm_14rounds,
                      alcp_clear_keys_zmm_14rounds>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

} // namespace alcp::cipher::vaes512
