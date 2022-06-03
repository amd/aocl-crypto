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

    vect_256_t block0, block1;
    vect_256_t ctr1, ctr2, swap_ctrx;
    vect_256_t b1, b2;

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctrx.ymm = _mm256_set_epi32(0x0c0d0e0f,
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
    ctr1.ymm    = _mm256_maskload_epi64((long long*)pIv, mask_lo);
    ctr1.xmm[1] = ctr1.xmm[0]; // Replicate information

    // Incrementer registers
    __m256i onelo    = _mm256_setr_epi32(0, 0, 0, 1, 0, 0, 0, 0);
    __m256i onehi    = _mm256_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1);
    __m256i twohilo  = _mm256_setr_epi32(0, 0, 0, 2, 0, 0, 0, 2);
    __m256i fourhilo = _mm256_setr_epi32(0, 0, 0, 4, 0, 0, 0, 4);

    // Rearrange to add
    ctr1.ymm = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx.ymm);

    // Keep both counters ready
    ctr1.ymm = _mm256_add_epi32(ctr1.ymm, onehi);
    ctr2.ymm = _mm256_add_epi32(ctr1.ymm, twohilo);

    for (; blocks >= 4; blocks -= 4) {
        block0.ymm = _mm256_loadu_si256((__m256i*)p_in_128);
        block1.ymm = _mm256_loadu_si256((__m256i*)p_in_128 + 1);

        // re-arrange as per spec
        b1.ymm = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx.ymm);
        b2.ymm = _mm256_shuffle_epi8(ctr2.ymm, swap_ctrx.ymm);

        vaes::AESEncrypt(&(b1.ymm), &(b2.ymm), pkey128, nRounds);

        block0.ymm = _mm256_xor_si256(b1.ymm, block0.ymm);
        block1.ymm = _mm256_xor_si256(b2.ymm, block1.ymm);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, fourhilo);
        ctr2.ymm = _mm256_add_epi32(ctr2.ymm, fourhilo);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128), block0.ymm);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out_128) + 1,
                            block1.ymm);

        p_in_128 += 4;
        p_out_128 += 4;
    }

    for (; blocks >= 2; blocks -= 2) {
        block0.ymm = _mm256_loadu_si256((__m256i*)p_in_128);

        // re-arrange as per spec
        b1.ymm = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx.ymm);

        vaes::AESEncrypt(&(b1.ymm), pkey128, nRounds);

        block0.ymm = _mm256_xor_si256(b1.ymm, block0.ymm);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, twohilo);

        _mm256_storeu_si256((__m256i*)p_out_128, block0.ymm);

        p_in_128 += 2;
        p_out_128 += 2;
    }

    for (; blocks >= 1; blocks -= 1) {
        block0.ymm = _mm256_maskload_epi64((long long*)p_in_128, mask_lo);
        // print_ymm(ax);

        // re-arrange as per spec
        b1.ymm = _mm256_shuffle_epi8(ctr1.ymm, swap_ctrx.ymm);

        vaes::AESEncrypt(&(b1.ymm), pkey128, nRounds);
        // std::cout << "HERE" << std::endl;

        block0.ymm = _mm256_xor_si256(b1.ymm, block0.ymm);

        ctr1.ymm = _mm256_add_epi32(ctr1.ymm, onelo);

        _mm256_maskstore_epi64((long long*)p_out_128, mask_lo, block0.ymm);

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
