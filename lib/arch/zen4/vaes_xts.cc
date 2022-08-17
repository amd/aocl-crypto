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
#include "cipher/avx512.hh"
#include "cipher/vaes_avx512.hh"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "error.hh"
#include "key.hh"
#include "types.hh"

#define GF_POLYNOMIAL 0x87

namespace alcp::cipher::vaes {

static inline void
MultiplyAplhaByTwo(__m128i& alpha)
{
    unsigned long long res, carry;

    unsigned long long* tmp_tweak = (unsigned long long*)&alpha;

    res   = (((long long)tmp_tweak[1]) >> 63) & GF_POLYNOMIAL;
    carry = (((long long)tmp_tweak[0]) >> 63) & 1;

    tmp_tweak[0] = ((tmp_tweak[0]) << 1) ^ res;
    tmp_tweak[1] = ((tmp_tweak[1]) << 1) | carry;
}

static inline __m512i
finalAlphaVal(__m128i& alpha)
{
    __m512i finalAlpha = _mm512_setzero_si512();

    (((__m128i*)&finalAlpha)[0]) = alpha;
    MultiplyAplhaByTwo(alpha);
    (((__m128i*)&finalAlpha)[1]) = alpha;
    MultiplyAplhaByTwo(alpha);
    (((__m128i*)&finalAlpha)[2]) = alpha;
    MultiplyAplhaByTwo(alpha);
    (((__m128i*)&finalAlpha)[3]) = alpha;
    MultiplyAplhaByTwo(alpha);

    return finalAlpha;
}

alc_error_t
EncryptXtsAvx512(const uint8_t* pSrc,
                 uint8_t*       pDest,
                 uint64_t       len,
                 const uint8_t* pKey,
                 const uint8_t* pTweakKey,
                 int            nRounds,
                 const uint8_t* pIv)
{

    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src512       = reinterpret_cast<const __m512i*>(pSrc);
    auto p_dest512      = reinterpret_cast<__m512i*>(pDest);

    uint64_t blocks          = len / Rijndael::cBlockSize;
    int      last_Round_Byte = len % Rijndael::cBlockSize;
    uint64_t chunk           = 4 * 4;

    // iv encryption using tweak key to get alpha
    __m512i extendedIV = _mm512_setr_epi64(
        ((const uint64_t*)pIv)[0], ((const uint64_t*)pIv)[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m128i current_alpha = ((__m128i*)&extendedIV)[0];

    // Encrypting 4*4 source text blocks at a time
    while (blocks > chunk) {

        // Calulating Aplha for the next 4*4 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);
        __m512i current_alpha_2 = finalAlphaVal(current_alpha);
        __m512i current_alpha_3 = finalAlphaVal(current_alpha);
        __m512i current_alpha_4 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);
        __m512i tweaked_src_text_2 = alcp_xor(current_alpha_2, src_text_2);
        __m512i tweaked_src_text_3 = alcp_xor(current_alpha_3, src_text_3);
        __m512i tweaked_src_text_4 = alcp_xor(current_alpha_4, src_text_4);

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 = alcp_xor(current_alpha_2, tweaked_src_text_2);
        tweaked_src_text_3 = alcp_xor(current_alpha_3, tweaked_src_text_3);
        tweaked_src_text_4 = alcp_xor(current_alpha_4, tweaked_src_text_4);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        p_dest512 += 4;
        p_src512 += 4;

        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 4*2 source text blocks at a time
    while (blocks > chunk) {
        // Calulating Aplha for the next 4*2 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);
        __m512i current_alpha_2 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);
        __m512i tweaked_src_text_2 = alcp_xor(current_alpha_2, src_text_2);

        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 = alcp_xor(current_alpha_2, tweaked_src_text_2);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;

        blocks -= chunk;
    }
    chunk = 4;

    // Encrypting 4*1 source text blocks at a time
    while (blocks > chunk || (blocks == chunk && last_Round_Byte == 0)) {
        // Calulating Aplha for the next 4*1 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        p_dest512 += 1;
        p_src512 += 1;

        blocks -= chunk;
    }

    // Encrypt block of size greater than 1 so that we can be left with last
    // blocks and some bytes
    while (blocks > 1) {
        int     blocks_to_be_encrypted = blocks;
        __m128i Alphas[4]              = { _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4]       = { _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };
        // Calulating Aplha for the next blocks_to_be_encrypted
        for (int i = 0; i < blocks_to_be_encrypted; i++) {
            Alphas[i]        = current_alpha;
            temp_src_text[i] = ((__m128i*)p_src512)[i];
            MultiplyAplhaByTwo(current_alpha);
            blocks--;
        }

        __m512i src_text_1      = _mm512_loadu_si512(temp_src_text);
        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        for (int i = 0; i < blocks_to_be_encrypted; i++) {
            _mm_storeu_si128(((__m128i*)p_dest512) + i,
                             ((__m128i*)&tweaked_src_text_1)[i]);
        }
        p_dest512 = (__m512i*)(((__m128i*)p_dest512) + blocks_to_be_encrypted);
        p_src512  = (__m512i*)(((__m128i*)p_src512) + blocks_to_be_encrypted);
    }

    if (blocks == 0 && last_Round_Byte == 0) {

        return ALC_ERROR_NONE;
    }
    //  if message blocks do not have any residue bytes no stealing takes
    //  place and direct results are stored to destination
    else if (blocks == 1 && last_Round_Byte == 0) {

        __m128i Alphas[4] = { current_alpha,
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };

        __m128i temp_src_text[4] = { _mm_loadu_si128(((__m128i*)p_src512)),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        __m512i src_text_1      = _mm512_loadu_si512(temp_src_text);
        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm_storeu_si128(((__m128i*)p_dest512),
                         ((__m128i*)&tweaked_src_text_1)[0]);
        blocks--;

        p_dest512 = (__m512i*)(((__m128i*)p_dest512) + 1);
        p_src512  = (__m512i*)(((__m128i*)p_src512) + 1);
        return ALC_ERROR_NONE;
    } else if (blocks == 1 && last_Round_Byte > 0) {

        __m128i Alphas[4]        = { current_alpha,
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4] = { _mm_loadu_si128(((__m128i*)p_src512)),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = _mm512_loadu_si512(temp_src_text);

        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);
        MultiplyAplhaByTwo(current_alpha);

        __m128i second_last_message_block =
            (((__m128i*)&tweaked_src_text_1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src512)) + 16),
               last_Round_Byte);

        memcpy(((uint8_t*)&last_message_block) + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        Alphas[0] = current_alpha;

        current_alpha_1 = _mm512_loadu_si512(Alphas);

        temp_src_text[0] = last_message_block;

        // getting Tweaked Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_loadu_si512(temp_src_text);

        // getting Tweaked Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing a block of encrypted message
        _mm_store_si128((__m128i*)p_dest512,
                        (((__m128i*)&tweaked_src_text_1)[0]));

        memcpy((((uint8_t*)p_dest512) + 16),
               ((uint8_t*)p_second_last_message_block),
               last_Round_Byte);

        return ALC_ERROR_NONE;
    } else if (blocks == 0 && last_Round_Byte > 0) {

        __m128i  second_last_message_block = ((((__m128i*)p_dest512) - 1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = ((((__m128i*)p_src512))[0]);

        memcpy((uint8_t*)&last_message_block + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        __m128i Alphas[4]        = { current_alpha,
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4] = { last_message_block,
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i src_text_1      = _mm512_loadu_si512(temp_src_text);
        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        src_text_1 = alcp_xor(src_text_1, current_alpha_1);

        AesEncrypt(&src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        _mm_store_si128((((__m128i*)p_dest512) - 1),
                        (((__m128i*)&src_text_1)[0]));

        memcpy(
            (uint8_t*)p_dest512, p_second_last_message_block, last_Round_Byte);

        return ALC_ERROR_NONE;
    }
    return ALC_ERROR_NONE;
}

alc_error_t
DecryptXtsAvx512(const uint8_t* pSrc,
                 uint8_t*       pDest,
                 uint64_t       len,
                 const uint8_t* pKey,
                 const uint8_t* pTweakKey,
                 int            nRounds,
                 const uint8_t* pIv)
{
    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src512       = reinterpret_cast<const __m512i*>(pSrc);
    auto p_dest512      = reinterpret_cast<__m512i*>(pDest);

    uint64_t blocks          = len / Rijndael::cBlockSize;
    int      last_Round_Byte = len % Rijndael::cBlockSize;
    uint64_t chunk           = 4 * 4;

    // iv encryption using tweak key to get alpha
    __m512i extendedIV = _mm512_setr_epi64(
        ((const uint64_t*)pIv)[0], ((const uint64_t*)pIv)[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m128i current_alpha = ((__m128i*)&extendedIV)[0];

    // Encrypting 4 source text blocks at a time
    while (blocks > chunk) {
        // Calulating Aplha for the next 4 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);
        __m512i current_alpha_2 = finalAlphaVal(current_alpha);
        __m512i current_alpha_3 = finalAlphaVal(current_alpha);
        __m512i current_alpha_4 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);
        __m512i tweaked_src_text_2 = alcp_xor(current_alpha_2, src_text_2);
        __m512i tweaked_src_text_3 = alcp_xor(current_alpha_3, src_text_3);
        __m512i tweaked_src_text_4 = alcp_xor(current_alpha_4, src_text_4);

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 = alcp_xor(current_alpha_2, tweaked_src_text_2);
        tweaked_src_text_3 = alcp_xor(current_alpha_3, tweaked_src_text_3);
        tweaked_src_text_4 = alcp_xor(current_alpha_4, tweaked_src_text_4);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        p_dest512 += 4;
        p_src512 += 4;

        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 2*2 source text blocks at a time
    while (blocks > chunk) {
        // Calulating Aplha for the next 2*2 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);
        __m512i current_alpha_2 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);
        __m512i tweaked_src_text_2 = alcp_xor(current_alpha_2, src_text_2);

        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);
        tweaked_src_text_2 = alcp_xor(current_alpha_2, tweaked_src_text_2);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;

        blocks -= chunk;
    }
    chunk = 4;

    // Encrypting 2 source text blocks at a time
    while (blocks > chunk || (blocks == chunk && last_Round_Byte == 0)) {
        // Calulating Aplha for the next 2*1 blocks
        __m512i current_alpha_1 = finalAlphaVal(current_alpha);

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        p_dest512 += 1;
        p_src512 += 1;

        blocks -= chunk;
    }

    // Encrypt block of size 1 so that we can be left with last byte and some
    // bits
    while (blocks > 1) {
        int blocks_to_be_encrypted = blocks - 1 + (last_Round_Byte == 0);
        // Calulating Aplha for the next 1 blocks
        __m128i Alphas[4]        = { _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4] = { _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        for (int i = 0; i < blocks_to_be_encrypted; i++) {
            Alphas[i]        = current_alpha;
            temp_src_text[i] = ((__m128i*)p_src512)[i];
            MultiplyAplhaByTwo(current_alpha);
            blocks--;
        }

        __m512i src_text_1      = _mm512_loadu_si512(temp_src_text);
        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        for (int i = 0; i < blocks_to_be_encrypted; i++) {
            _mm_storeu_si128(((__m128i*)p_dest512) + i,
                             ((__m128i*)&tweaked_src_text_1)[i]);
        }
        p_dest512 = (__m512i*)(((__m128i*)p_dest512) + blocks_to_be_encrypted);
        p_src512  = (__m512i*)(((__m128i*)p_src512) + blocks_to_be_encrypted);
    }

    if (blocks == 0 && last_Round_Byte == 0) {
        return ALC_ERROR_NONE;
    }
    //  if message blocks do not have any residue bytes no stealing takes
    //  place and direct results are stored to destination
    else if (blocks == 1 && last_Round_Byte == 0) {

        __m128i Alphas[4]        = { current_alpha,
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4] = { _mm_loadu_si128(((__m128i*)p_src512)),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        __m512i src_text_1      = _mm512_loadu_si512(temp_src_text);
        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = alcp_xor(current_alpha_1, src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        // storing the results in destination
        _mm_storeu_si128(((__m128i*)p_dest512),
                         ((__m128i*)&tweaked_src_text_1)[0]);
        blocks--;

        p_dest512 = (__m512i*)(((__m128i*)p_dest512) + 1);
        p_src512  = (__m512i*)(((__m128i*)p_src512) + 1);
        return ALC_ERROR_NONE;
    } else if (blocks == 1 && last_Round_Byte > 0) {

        __m128i prevAlpha = current_alpha;
        MultiplyAplhaByTwo(current_alpha);

        __m128i Alphas[4]        = { current_alpha,
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0),
                              _mm_set1_epi32(0) };
        __m128i temp_src_text[4] = { _mm_loadu_si128(((__m128i*)p_src512)),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0),
                                     _mm_set1_epi32(0) };

        __m512i current_alpha_1 = _mm512_loadu_si512(Alphas);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = _mm512_loadu_si512(temp_src_text);

        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = alcp_xor(current_alpha_1, tweaked_src_text_1);

        __m128i second_last_message_block =
            (((__m128i*)&tweaked_src_text_1)[0]);
        uint8_t* p_second_last_message_block =
            (uint8_t*)&second_last_message_block;
        __m128i last_message_block = _mm_setzero_si128();
        memcpy(((uint8_t*)&last_message_block),
               (((uint8_t*)(p_src512)) + 16),
               last_Round_Byte);
        memcpy(((uint8_t*)&last_message_block) + last_Round_Byte,
               p_second_last_message_block + last_Round_Byte,
               16 - last_Round_Byte);

        Alphas[0] = prevAlpha;

        __m512i temp_alpha_1 = _mm512_loadu_si512(Alphas);

        temp_src_text[0] = last_message_block;

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i temp_text_1 = _mm512_loadu_si512(temp_src_text);

        temp_text_1 = alcp_xor(temp_alpha_1, temp_text_1);

        AesDecrypt(&temp_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        temp_text_1 = alcp_xor(temp_alpha_1, temp_text_1);

        _mm_store_si128((__m128i*)p_dest512, (((__m128i*)&temp_text_1)[0]));

        memcpy((((__m128i*)p_dest512) + 1),
               p_second_last_message_block,
               last_Round_Byte);

        return ALC_ERROR_NONE;
    }
    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes
