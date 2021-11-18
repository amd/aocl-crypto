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

#include "alcp/error.h"

#include "cipher/aes.hh"
#include "key.hh"

namespace alcp::cipher::vaes {

alc_error_t
DecryptCFB256(const uint8_t* pSrc,    // ptr to ciphertext
              uint8_t*       pDst,    // ptr to plaintext
              int            len,     // message length in bytes
              uint8_t*       pKey,    // ptr to Key
              int            nRounds, // No. of rounds
              const uint8_t* pIV      // ptr to Initialization Vector
)
{
    uint64_t* p64     = (uint64_t*)pIV;
    __m128i*  pRkey   = (__m128i*)pKey;
    __m256i*  pSrc256 = (__m256i*)pSrc;
    __m256i*  pDst256 = (__m256i*)pDst;

    __m256i IV = _mm256_set_epi64x(0, 0, p64[1], p64[0]);

    int blocks = len / MBS_RIJ128;

    if ((8 * 2) <= blocks) {
        __m256i blk0 = _mm256_loadu_si256(pSrc256);
        __m256i blk1 = _mm256_loadu_si256(pSrc256 + 1);
        __m256i blk2 = _mm256_loadu_si256(pSrc256 + 2);
        __m256i blk3 = _mm256_loadu_si256(pSrc256 + 3);

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

        vaes::AESEncrypt(&y0, &y1, &y2, &y3, pRkey, nRounds);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);
        blk2 = _mm256_xor_si256(blk2, y2);
        blk3 = _mm256_xor_si256(blk3, y3);

        _mm256_storeu_si256(pDst256, blk0);
        _mm256_storeu_si256(pDst256 + 1, blk1);
        _mm256_storeu_si256(pDst256 + 2, blk2);
        _mm256_storeu_si256(pDst256 + 3, blk3);

        pSrc256 += 4;
        pDst256 += 4;
        blocks -= (8 * 2);
    }

    if ((4 * 2) <= blocks) {
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(pSrc256);
        __m256i blk1 = _mm256_loadu_si256(pSrc256 + 1);
        __m256i y0   = _mm256_set_epi64x(blk0[1], blk0[0], 0, 0);
        __m256i y1   = _mm256_set_epi64x(blk1[1], blk1[0], 0, 0);

        y0 |= IV;
        y1 |= blk0;

        // update IV
        IV = _mm256_set_epi64x(0, 0, blk1[3], blk1[2]);

        vaes::AESEncrypt(&y0, &y1, pRkey, cipherRounds);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);

        _mm256_storeu_si256(pDst256, blk0);
        _mm256_storeu_si256(pDst256 + 1, blk1);

        pSrc256 += 2;
        pDst256 += 2;
        blocks -= (2 * 4);
    }

    for (; blocks >= 2; blocks -= 2) {
        uint64_t* p64src = (uint64_t*)pSrc256;
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(pSrc256);

        __m256i y0 = _mm256_set_epi64x(p64src[1], p64src[0], 0, 0);

        y0 = (y0 | IV);

        // update IV
        IV = _mm256_set_epi64x(0, 0, blk0[3], blk0[2]);

        vaes::AESEncrypt(&y0, pRkey, cipherRounds);

        blk0 = _mm256_xor_si256(blk0, y0);

        _mm256_storeu_si256(pDst256, blk0);

        pSrc256 += 1;
        pDst256 += 1;
    }

    if (blocks) {
        printf("Still blocks left ======= \n");
    }

    return ippStsNoErr;
}

} // namespace alcp::cipher::vaes
