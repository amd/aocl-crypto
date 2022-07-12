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
#include <sstream>
#include <string.h>

#include "cipher/aesni.hh"
#include "error.hh"

namespace alcp::cipher { namespace aesni {

    static inline void MultiplyAplhaByTwo(__m128i& alpha)
    {
        unsigned int res, carry;

        res = 0x87
              & (((int)(((uint32_t*)&alpha)[3]))
                 >> 31); // a0 | a1 | a2 | a3  if a3 sign bit high res = 0x87

        carry = (unsigned int)((((uint64_t*)&alpha)[0])
                               >> 63); // a0 | a1 if a0 sign bit high 1 else 0

        (((uint64_t*)&alpha)[0]) = ((((uint64_t*)&alpha)[0]) << 1) ^ res;
        (((uint64_t*)&alpha)[1]) = ((((uint64_t*)&alpha)[1]) << 1) | carry;
    }

    alc_error_t EncryptXts(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
        auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
        auto p_src128       = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128      = reinterpret_cast<__m128i*>(pDest);

        __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);

        uint64_t blocks          = len / Rijndael::cBlockSize;
        int      last_Round_Byte = len % Rijndael::cBlockSize;

        // iv encryption using tweak key to get alpha
        __m128i current_alpha = iv128;
        AesEncrypt(&current_alpha, p_tweak_key128, nRounds);

        // Encrypting all blocks except last 2 if extra bytes present in source
        // text
        while (blocks >= 2 || (blocks > 1 && (last_Round_Byte > 0))) {

            // Encrypting Text using EncKey
            __m128i tweaked_src_text =
                _mm_xor_si128(current_alpha, p_src128[0]);
            AesEncrypt(&tweaked_src_text, p_key128, nRounds);
            tweaked_src_text = _mm_xor_si128(tweaked_src_text, current_alpha);

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text);

            p_dest128++;
            p_src128++;

            // Increasing Aplha  for the next round
            MultiplyAplhaByTwo(current_alpha);

            blocks--;
        }

        //  if message blocks do not have any residue bytes no stealing takes
        //  place and direct results are stored to destination
        if (blocks == 1 && last_Round_Byte == 0) {

            __m128i tweaked_src_text =
                _mm_xor_si128(current_alpha, p_src128[0]);
            AesEncrypt(&tweaked_src_text, p_key128, nRounds);
            tweaked_src_text = _mm_xor_si128(current_alpha, tweaked_src_text);

            _mm_storeu_si128(p_dest128, tweaked_src_text);

            return ALC_ERROR_NONE;
        }

        __m128i tweaked_src_text = _mm_xor_si128(current_alpha, p_src128[0]);
        AesEncrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(current_alpha, tweaked_src_text);

        // stealing bytes from (m-1)th chiper message and storing it at mth
        // destinatIon on last line of code
        uint8_t* a = (uint8_t*)&tweaked_src_text;
        __m128i  b = _mm_set1_epi8(0);
        memcpy((uint8_t*)&b, a, last_Round_Byte);

        p_src128++;

        MultiplyAplhaByTwo(current_alpha);

        // appending 16-last_Round_Byte bytes to last message block to make it
        // complete block for encryption (Called Stealing of bytes in xts terms)
        __m128i temp = p_src128[0];
        memcpy((uint8_t*)&temp + last_Round_Byte,
               a + last_Round_Byte,
               16 - last_Round_Byte);

        tweaked_src_text = _mm_xor_si128(current_alpha, temp);
        AesEncrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(current_alpha, tweaked_src_text);

        _mm_storeu_si128(p_dest128, tweaked_src_text);

        p_dest128++;

        memcpy(((uint8_t*)p_dest128), (uint8_t*)&b, last_Round_Byte);

        return ALC_ERROR_NONE;
    }
    alc_error_t DecryptXts(const uint8_t* pSrc,
                           uint8_t*       pDest,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv)
    {
        auto    p_key128       = reinterpret_cast<const __m128i*>(pKey);
        auto    p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
        auto    p_src128       = reinterpret_cast<const __m128i*>(pSrc);
        auto    p_dest128      = reinterpret_cast<__m128i*>(pDest);
        __m128i iv128          = _mm_loadu_si128((const __m128i*)pIv);

        uint64_t blocks          = len / Rijndael::cBlockSize;
        int      last_Round_Byte = len % Rijndael::cBlockSize;

        // iv encryption using tweak key to get alpha
        __m128i current_alpha = iv128;
        AesEncrypt(&current_alpha, p_tweak_key128, nRounds);

        // Decrypting all blocks except last 2 if extra bytes present in source
        // text
        while (blocks >= 2 || (blocks > 1 && (last_Round_Byte > 0))) {

            // Decrypting Text using DecKey
            __m128i tweaked_src_text =
                _mm_xor_si128(current_alpha, p_src128[0]);
            AesDecrypt(&tweaked_src_text, p_key128, nRounds);
            tweaked_src_text = _mm_xor_si128(tweaked_src_text, current_alpha);

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text);

            p_dest128++;
            p_src128++;

            // Increasing Aplha  for the next round
            MultiplyAplhaByTwo(current_alpha);

            blocks--;
        }

        //  if message blocks do not have any residue bytes no stealing took
        //  place at encryption time so direct results are stored to destination
        if (blocks == 1 && last_Round_Byte == 0) {

            __m128i tweaked_src_text =
                _mm_xor_si128(current_alpha, p_src128[0]);
            AesDecrypt(&tweaked_src_text, p_key128, nRounds);
            tweaked_src_text = _mm_xor_si128(current_alpha, tweaked_src_text);

            _mm_storeu_si128(p_dest128, tweaked_src_text);

            return ALC_ERROR_NONE;
        }

        __m128i prevAlpha = current_alpha;

        MultiplyAplhaByTwo(current_alpha);

        __m128i tweaked_src_text = _mm_xor_si128(current_alpha, p_src128[0]);
        AesDecrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(current_alpha, tweaked_src_text);

        // stealing bytes from (m-1)th message block and storing it at mth
        // destinatIon on last line of code
        uint8_t* a = (uint8_t*)&tweaked_src_text;
        __m128i  b = _mm_set1_epi8(0);
        memcpy((uint8_t*)&b, a, last_Round_Byte);

        p_src128++;

        // appending 16-last_Round_Byte bytes to last chiper message block to
        // make it complete block for decryption and storing it to (m-1)th
        // destination
        __m128i temp = p_src128[0];
        memcpy((uint8_t*)&temp + last_Round_Byte,
               a + last_Round_Byte,
               16 - last_Round_Byte);

        tweaked_src_text = _mm_xor_si128(prevAlpha, temp);
        AesDecrypt(&tweaked_src_text, p_key128, nRounds);
        tweaked_src_text = _mm_xor_si128(prevAlpha, tweaked_src_text);

        _mm_storeu_si128(p_dest128, tweaked_src_text);

        p_dest128++;

        memcpy(((uint8_t*)p_dest128), (uint8_t*)&b, last_Round_Byte);

        return ALC_ERROR_NONE;
    }

}} // namespace alcp::cipher::aesni
