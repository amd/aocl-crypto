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
#include "cipher/aes.hh"
#include "cipher/vaes.hh"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "error.hh"
#include "key.hh"
#include "types.hh"

#define GF_POLYNOMIAL 0x87

namespace alcp::cipher::vaes {

static inline void
MultiplyAlphaByTwo(__m128i& alpha)
{
    Uint64 res, carry;

    Uint64* tmp_tweak = (Uint64*)&alpha;

    res   = (((long long)tmp_tweak[1]) >> 63) & GF_POLYNOMIAL;
    carry = (((long long)tmp_tweak[0]) >> 63) & 1;

    tmp_tweak[0] = ((tmp_tweak[0]) << 1) ^ res;
    tmp_tweak[1] = ((tmp_tweak[1]) << 1) | carry;
}

static inline __m256i
finalAlphaVal(__m128i& alpha)
{
    __m256i finalAlpha           = _mm256_setzero_si256();
    (((__m128i*)&finalAlpha)[0]) = alpha;
    MultiplyAlphaByTwo(alpha);
    (((__m128i*)&finalAlpha)[1]) = alpha;
    MultiplyAlphaByTwo(alpha);
    return finalAlpha;
}

alc_error_t
EncryptXts(const uint8_t* pSrc,
           uint8_t*       pDest,
           uint64_t       len,
           const uint8_t* pKey,
           const uint8_t* pTweakKey,
           int            nRounds,
           const uint8_t* pIv)
{

    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src256       = reinterpret_cast<const __m256i*>(pSrc);
    auto p_dest256      = reinterpret_cast<__m256i*>(pDest);

    __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);

    uint64_t blocks          = len / Rijndael::cBlockSize;
    int      last_Round_Byte = len % Rijndael::cBlockSize;
    uint64_t chunk           = 4 * 2;

    // iv encryption using tweak key to get alpha

    __m256i extendedIV = _mm256_set_epi64x(
        0, 0, ((long long*)&iv128)[1], ((long long*)&iv128)[0]);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m128i current_alpha = ((__m128i*)&extendedIV)[0];

    // Encrypting 4 source text blocks at a time
    while (blocks > chunk) {
        // Calulating Aplha for the next 4 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);
        __m256i current_alpha_2 = finalAlphaVal(current_alpha);
        __m256i current_alpha_3 = finalAlphaVal(current_alpha);
        __m256i current_alpha_4 = finalAlphaVal(current_alpha);

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, src_text_1);
        __m256i tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, src_text_2);
        __m256i tweaked_src_text_3 =
            _mm256_xor_si256(current_alpha_3, src_text_3);
        __m256i tweaked_src_text_4 =
            _mm256_xor_si256(current_alpha_4, src_text_4);

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, tweaked_src_text_2);
        tweaked_src_text_3 =
            _mm256_xor_si256(current_alpha_3, tweaked_src_text_3);
        tweaked_src_text_4 =
            _mm256_xor_si256(current_alpha_4, tweaked_src_text_4);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        p_dest256 += 4;
        p_src256 += 4;

        blocks -= chunk;
    }

    chunk = 2 * 2;

    // Encrypting 2*2 source text blocks at a time
    while (blocks > chunk) {
        // Calulating Aplha for the next 2*2 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);
        __m256i current_alpha_2 = finalAlphaVal(current_alpha);

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, src_text_1);
        __m256i tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, src_text_2);

        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, tweaked_src_text_2);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);

        p_dest256 += 2;
        p_src256 += 2;

        blocks -= chunk;
    }
    chunk = 2;

    // Encrypting 2 source text blocks at a time
    while (blocks > chunk || (blocks == chunk && last_Round_Byte == 0)) {
        // Calulating Aplha for the next 2*1 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i src1               = _mm256_loadu_si256(p_src256);
        __m256i tweaked_src_text_1 = _mm256_xor_si256(current_alpha_1, src1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;

        blocks -= chunk;
    }

    // Encrypt block of size 1 so that we can be left with last byte and some
    // bits
    while (blocks > 1) {
        // Calulating Aplha for the next 1 blocks
        __m128i prevAlpha = current_alpha;
        MultiplyAlphaByTwo(current_alpha);
        __m256i current_alpha_1 = _mm256_set_m128i(current_alpha, prevAlpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, _mm256_loadu_si256(p_src256));

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        blocks -= 1;
        p_dest256 = (__m256i*)(((__m128i*)p_dest256) + 1);
        p_src256  = (__m256i*)(((__m128i*)p_src256) + 1);
    }
    if (blocks == 0 && last_Round_Byte == 0) {
        return ALC_ERROR_NONE;
    }
    //  if message blocks do not have any residue bytes no stealing takes
    //  place and direct results are stored to destination
    else if (blocks == 1 && last_Round_Byte == 0) {
        __m256i current_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), (((__m128i*)p_src256)[0]));

        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm_store_si128((__m128i*)p_dest256,
                        (((__m128i*)&tweaked_src_text_1)[0]));

        return ALC_ERROR_NONE;
    } else if (blocks == 1 && last_Round_Byte > 0) {
        __m256i current_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), (((__m128i*)p_src256)[0]));

        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);
        MultiplyAlphaByTwo(current_alpha);

        __m128i second_last_message_block =
            (((__m128i*)&tweaked_src_text_1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src256)) + 16),
               last_Round_Byte);

        memcpy(((uint8_t*)&last_message_block) + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        __m256i temp_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i temp_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), last_message_block);

        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        AesEncrypt(&temp_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        _mm_store_si128((__m128i*)p_dest256, (((__m128i*)&temp_text_1)[0]));

        memcpy((((uint8_t*)p_dest256) + 16),
               ((uint8_t*)p_second_last_message_block),
               last_Round_Byte);

        return ALC_ERROR_NONE;
    } else if (blocks == 0 && last_Round_Byte > 0) {
        __m128i  second_last_message_block = ((((__m128i*)p_dest256) - 1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src256))),
               last_Round_Byte);
        memcpy((uint8_t*)&last_message_block + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        __m256i temp_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i temp_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), last_message_block);

        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        AesEncrypt(&temp_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        _mm_store_si128((((__m128i*)p_dest256) - 1),
                        (((__m128i*)&temp_text_1)[0]));

        memcpy(
            (uint8_t*)p_dest256, p_second_last_message_block, last_Round_Byte);

        return ALC_ERROR_NONE;
    }
    return ALC_ERROR_NONE;
}

alc_error_t
DecryptXts(const uint8_t* pSrc,
           uint8_t*       pDest,
           uint64_t       len,
           const uint8_t* pKey,
           const uint8_t* pTweakKey,
           int            nRounds,
           const uint8_t* pIv)
{
    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src256       = reinterpret_cast<const __m256i*>(pSrc);
    auto p_dest256      = reinterpret_cast<__m256i*>(pDest);

    __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);

    uint64_t blocks          = len / Rijndael::cBlockSize;
    int      last_Round_Byte = len % Rijndael::cBlockSize;
    uint64_t chunk           = 4 * 2;

    // iv encryption using tweak key to get alpha

    __m256i extendedIV = _mm256_set_epi64x(
        0, 0, ((long long*)&iv128)[1], ((long long*)&iv128)[0]);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m128i current_alpha = ((__m128i*)&extendedIV)[0];

    // Encrypting 4*2 source text blocks at a time
    while (blocks > chunk) {

        // Calulating Aplha for the next 4*2 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);
        __m256i current_alpha_2 = finalAlphaVal(current_alpha);
        __m256i current_alpha_3 = finalAlphaVal(current_alpha);
        __m256i current_alpha_4 = finalAlphaVal(current_alpha);

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, src_text_1);
        __m256i tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, src_text_2);
        __m256i tweaked_src_text_3 =
            _mm256_xor_si256(current_alpha_3, src_text_3);
        __m256i tweaked_src_text_4 =
            _mm256_xor_si256(current_alpha_4, src_text_4);

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, tweaked_src_text_2);
        tweaked_src_text_3 =
            _mm256_xor_si256(current_alpha_3, tweaked_src_text_3);
        tweaked_src_text_4 =
            _mm256_xor_si256(current_alpha_4, tweaked_src_text_4);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        p_dest256 += 4;
        p_src256 += 4;

        blocks -= chunk;
    }

    chunk = 2 * 2;

    // Encrypting 2*2 source text blocks at a time
    while (blocks > chunk) {

        // Calulating Aplha for the next 2*2 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);
        __m256i current_alpha_2 = finalAlphaVal(current_alpha);

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, src_text_1);
        __m256i tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, src_text_2);

        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm256_xor_si256(current_alpha_2, tweaked_src_text_2);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);

        p_dest256 += 2;
        p_src256 += 2;

        blocks -= chunk;
    }
    chunk = 2;

    // Encrypting 2 source text blocks at a time
    while (blocks > chunk || (blocks == chunk && last_Round_Byte == 0)) {

        // Calulating Aplha for the next 2*1 blocks
        __m256i current_alpha_1 = finalAlphaVal(current_alpha);
        __m256i src1            = _mm256_loadu_si256(p_src256);
        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = _mm256_xor_si256(current_alpha_1, src1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;

        blocks -= chunk;
    }

    // Making sure only last 2 bytes or 1byte and some bits are left to decrypt
    if (blocks == 2 && last_Round_Byte > 0) {

        __m256i current_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);
        MultiplyAlphaByTwo(current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), (((__m128i*)p_src256)[0]));

        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm_store_si128((__m128i*)p_dest256,
                        (((__m128i*)&tweaked_src_text_1)[0]));

        blocks -= 1;
        p_dest256 = (__m256i*)(((__m128i*)p_dest256) + 1);
        p_src256  = (__m256i*)(((__m128i*)p_src256) + 1);
        // return ALC_ERROR_NONE;
    }

    // Encrypting all blocks except last 2 if extra bytes present in source
    // text
    while (blocks > 1) {

        // Calulating Aplha for the next 2*1 blocks
        __m128i prevAlpha = current_alpha;
        MultiplyAlphaByTwo(current_alpha);
        __m256i current_alpha_1 = _mm256_set_m128i(current_alpha, prevAlpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, _mm256_loadu_si256(p_src256));

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        blocks -= 1;
        p_dest256 = (__m256i*)(((__m128i*)p_dest256) + 1);
        p_src256  = (__m256i*)(((__m128i*)p_src256) + 1);

        // return ALC_ERROR_NONE;
    }

    if (blocks == 0 && last_Round_Byte == 0) {
        return ALC_ERROR_NONE;
    }
    //  if message blocks do not have any residue bytes no stealing takes
    //  place and direct results are stored to destination
    else if (blocks == 1 && last_Round_Byte == 0) {

        __m256i current_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), (((__m128i*)p_src256)[0]));

        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm_store_si128((__m128i*)p_dest256,
                        (((__m128i*)&tweaked_src_text_1)[0]));

        return ALC_ERROR_NONE;
    } else if (blocks == 1 && last_Round_Byte > 0) {

        __m128i prevAlpha = current_alpha;
        MultiplyAlphaByTwo(current_alpha);

        __m256i current_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), (((__m128i*)p_src256)[0]));

        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm256_xor_si256(current_alpha_1, tweaked_src_text_1);

        __m128i second_last_message_block =
            (((__m128i*)&tweaked_src_text_1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src256)) + 16),
               last_Round_Byte);

        memcpy(((uint8_t*)&last_message_block) + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        __m256i temp_alpha_1 = _mm256_set_m128i(_mm_setzero_si128(), prevAlpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i temp_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), last_message_block);

        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        AesDecrypt(&temp_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        _mm_store_si128((__m128i*)p_dest256, (((__m128i*)&temp_text_1)[0]));

        memcpy((((__m128i*)p_dest256) + 1),
               p_second_last_message_block,
               last_Round_Byte);

        return ALC_ERROR_NONE;
    } else if (blocks == 0 && last_Round_Byte > 0) {

        __m128i  second_last_message_block = ((((__m128i*)p_dest256) - 1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src256))),
               last_Round_Byte);
        memcpy((uint8_t*)&last_message_block + last_Round_Byte,
               (p_second_last_message_block) + last_Round_Byte,
               16 - last_Round_Byte);

        __m256i temp_alpha_1 =
            _mm256_set_m128i(_mm_setzero_si128(), current_alpha);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i temp_text_1 =
            _mm256_set_m128i(_mm_setzero_si128(), last_message_block);

        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        AesDecrypt(&temp_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        temp_text_1 = _mm256_xor_si256(temp_alpha_1, temp_text_1);

        _mm_store_si128((((__m128i*)p_dest256) - 1),
                        (((__m128i*)&temp_text_1)[0]));

        memcpy((uint8_t*)p_dest256,
               (p_second_last_message_block),
               last_Round_Byte);

        return ALC_ERROR_NONE;
    }
    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes
