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

#include "cipher/aes.hh"
#include "cipher/vaes.hh"

#include "error.hh"
#include "key.hh"
#include "types.hh"

namespace alcp::cipher::vaes {

typedef union
{
    __m256i  ymm;
    __m128i  xmm[2];
    uint64_t u64[4];
    uint32_t u32[8];
    uint16_t u16[16];
    uint8_t  u8[32];
} vect_256_t;

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

    __m256i    block0, block1, block2, block3;
    vect_256_t ctr1, ctr2, ctr3, ctr4;
    __m256i    b1, b2, b3, b4, swap_ctrx;

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctrx = _mm256_set_epi32(0x0c0d0e0f,
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100);

    // Mask for loading and storing half register
    __m256i mask_lo = _mm256_set_epi64x(0, 0, 1UL << 63, 1UL << 63);

    // Nonce Counter
    amd_mm256_broadcast_i64x2((__m128i*)pIv, &ctr1.ymm);

    // Incrementer registers
    __m256i onelo    = _mm256_setr_epi32(0, 0, 0, 1, 0, 0, 0, 0);
    __m256i onehi    = _mm256_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1);
    __m256i twohilo  = _mm256_setr_epi32(0, 0, 0, 2, 0, 0, 0, 2);
    __m256i fourhilo = _mm256_setr_epi32(0, 0, 0, 4, 0, 0, 0, 4);
    // __m256i sixhilo   = _mm256_setr_epi32(0, 0, 0, 6, 0, 0, 0, 6);
    __m256i eighthilo = _mm256_setr_epi32(0, 0, 0, 8, 0, 0, 0, 8);

    // Rearrange to add
    ctr1.ymm = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx);

    // Keep both counters ready
    ctr1.ymm = _mm256_add_epi32(ctr1.ymm, onehi);
    ctr2.ymm = _mm256_add_epi32(ctr1.ymm, twohilo);
    ctr3.ymm = _mm256_add_epi32(ctr2.ymm, twohilo);
    ctr4.ymm = _mm256_add_epi32(ctr3.ymm, twohilo);

    for (; blocks >= 8; blocks -= 8) {
        block0 = _mm256_loadu_si256((__m256i*)p_in_128);
        block1 = _mm256_loadu_si256((__m256i*)p_in_128 + 1);
        block2 = _mm256_loadu_si256((__m256i*)p_in_128 + 2);
        block3 = _mm256_loadu_si256((__m256i*)p_in_128 + 3);

        // re-arrange as per spec
        b1 = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx);
        b2 = _mm256_shuffle_epi8(ctr2.ymm, swap_ctrx);
        b3 = _mm256_shuffle_epi8(ctr3.ymm, swap_ctrx);
        b4 = _mm256_shuffle_epi8(ctr4.ymm, swap_ctrx);

        vaes::AESEncrypt(&(b1), &(b2), &(b3), &(b4), pkey128, nRounds);

        block0 = _mm256_xor_si256(b1, block0);
        block1 = _mm256_xor_si256(b2, block1);
        block2 = _mm256_xor_si256(b3, block2);
        block3 = _mm256_xor_si256(b4, block3);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, eighthilo);
        ctr2.ymm = _mm256_add_epi32(ctr2.ymm, eighthilo);
        ctr3.ymm = _mm256_add_epi32(ctr3.ymm, eighthilo);
        ctr4.ymm = _mm256_add_epi32(ctr4.ymm, eighthilo);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), block0);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 1, block1);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 2, block2);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 3, block3);

        p_in_128 += 8;
        p_out_128 += 8;
    }

    for (; blocks >= 4; blocks -= 4) {
        block0 = _mm256_loadu_si256((__m256i*)p_in_128);
        block1 = _mm256_loadu_si256((__m256i*)p_in_128 + 1);

        // re-arrange as per spec
        b1 = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx);
        b2 = _mm256_shuffle_epi8(ctr2.ymm, swap_ctrx);

        vaes::AESEncrypt(&(b1), &(b2), pkey128, nRounds);

        block0 = _mm256_xor_si256(b1, block0);
        block1 = _mm256_xor_si256(b2, block1);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, fourhilo);
        ctr2.ymm = _mm256_add_epi32(ctr2.ymm, fourhilo);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), block0);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 1, block1);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        block0 = _mm256_loadu_si256((__m256i*)p_in_128);

        // re-arrange as per spec
        b1 = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx);

        vaes::AESEncrypt(&(b1), pkey128, nRounds);

        block0 = _mm256_xor_si256(b1, block0);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, twohilo);

        _mm256_storeu_si256((__m256i*)p_out_128, block0);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        block0 = _mm256_maskload_epi64((long long*)p_in_128, mask_lo);

        // re-arrange as per spec
        b1 = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx);

        vaes::AESEncrypt(&(b1), pkey128, nRounds);

        block0 = _mm256_xor_si256(b1, block0);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, onelo);

        _mm256_maskstore_epi64((long long*)p_out_128, mask_lo, block0);

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

} // namespace alcp::cipher::vaes
