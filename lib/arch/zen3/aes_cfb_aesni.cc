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

#include "cipher/aes.hh"
#include "error.hh"
#include "key.hh"

namespace alcp::cipher::aesni {
#define AES_BLOCK_SIZE(x) ((x) / 8)

alc_error_t
DecryptCfb(const uint8_t* pCipherText, // ptr to ciphertext
           uint8_t*       pPlainText,  // ptr to plaintext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;

    uint64_t* pIv64   = (uint64_t*)pIv;
    __m128i*  pKey128 = (__m128i*)pKey;
    __m256i*  ct256_p = (__m256i*)pCipherText;
    __m256i*  pt256_p = (__m256i*)pPlainText;

    __m256i IV = _mm256_set_epi64x(0, 0, pIv64[1], pIv64[0]);

    int blocks = len / AES_BLOCK_SIZE(128);

    if ((8 * 2) <= blocks) {
        __m256i blk0 = _mm256_loadu_si256(ct256_p);
        __m256i blk1 = _mm256_loadu_si256(ct256_p + 1);
        __m256i blk2 = _mm256_loadu_si256(ct256_p + 2);
        __m256i blk3 = _mm256_loadu_si256(ct256_p + 3);

        __m256i y0 = _mm256_set_epi64x(blk0[1], blk0[0], 0, 0);
        __m256i y1 = _mm256_set_epi64x(blk1[1], blk1[0], 0, 0);
        __m256i y2 = _mm256_set_epi64x(blk2[1], blk2[0], 0, 0);
        __m256i y3 = _mm256_set_epi64x(blk3[1], blk3[0], 0, 0);

        y0 |= IV;
        y1 |= blk0;
        y2 |= blk1;
        y3 |= blk2;

        // update IV
        IV = _mm256_set_epi64x(0, 0, blk1[3], blk1[2]);

        aesni::AESEncrypt(&y0, &y1, &y2, &y3, pKey128, nRounds);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);
        blk2 = _mm256_xor_si256(blk2, y2);
        blk3 = _mm256_xor_si256(blk3, y3);

        _mm256_storeu_si256(pt256_p, blk0);
        _mm256_storeu_si256(pt256_p + 1, blk1);
        _mm256_storeu_si256(pt256_p + 2, blk2);
        _mm256_storeu_si256(pt256_p + 3, blk3);

        ct256_p += 4;
        pt256_p += 4;
        blocks -= (8 * 2);
    }

    if ((4 * 2) <= blocks) {
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(ct256_p);
        __m256i blk1 = _mm256_loadu_si256(ct256_p + 1);
        __m256i y0   = _mm256_set_epi64x(blk0[1], blk0[0], 0, 0);
        __m256i y1   = _mm256_set_epi64x(blk1[1], blk1[0], 0, 0);

        y0 |= IV;
        y1 |= blk0;

        // update IV
        IV = _mm256_set_epi64x(0, 0, blk1[3], blk1[2]);

        aesni::AESEncrypt(&y0, &y1, pKey128, nRounds);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);

        _mm256_storeu_si256(pt256_p, blk0);
        _mm256_storeu_si256(pt256_p + 1, blk1);

        ct256_p += 2;
        pt256_p += 2;
        blocks -= (2 * 4);
    }

    for (; blocks >= 2; blocks -= 2) {
        uint64_t* pIv64 = (uint64_t*)ct256_p;
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(ct256_p);

        __m256i y0 = _mm256_set_epi64x(pIv64[1], pIv64[0], 0, 0);

        y0 = (y0 | IV);

        // update IV
        IV = _mm256_set_epi64x(0, 0, blk0[3], blk0[2]);

        aesni::AESEncrypt(&y0, pKey128, nRounds);

        blk0 = _mm256_xor_si256(blk0, y0);

        _mm256_storeu_si256(pt256_p, blk0);

        ct256_p += 1;
        pt256_p += 1;
    }

    if (blocks) {
        /* There is one block left */
    }

    return err;
}

} // namespace alcp::cipher::aesni
