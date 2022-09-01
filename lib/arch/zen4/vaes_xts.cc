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
#include "cipher/aes_xts.hh"
#include "cipher/avx512.hh"
#include "cipher/vaes_avx512.hh"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "error.hh"
#include "key.hh"
#include "types.hh"

namespace alcp::cipher::vaes {

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

    uint64_t blocks                       = len / Rijndael::cBlockSize;
    uint64_t extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    uint64_t chunk                        = 8 * 4;

    // iv encryption using tweak key to get alpha
    __m512i extendedIV = _mm512_setr_epi64(
        ((const uint64_t*)pIv)[0], ((const uint64_t*)pIv)[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m512i tweakx8[8]; // 8*4 Tweak values stored inside this

    aes::init_alphax8(*((__m128i*)&extendedIV), (__m128i*)tweakx8);

    tweakx8[2] = aes::nextTweaks(tweakx8[0]);
    tweakx8[3] = aes::nextTweaks(tweakx8[1]);
    tweakx8[4] = aes::nextTweaks(tweakx8[2]);
    tweakx8[5] = aes::nextTweaks(tweakx8[3]);
    tweakx8[6] = aes::nextTweaks(tweakx8[4]);
    tweakx8[7] = aes::nextTweaks(tweakx8[5]);

    while (blocks >= chunk) {

        // Loading next 4*8 blocks of message
        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);
        __m512i src_text_5 = _mm512_loadu_si512(p_src512 + 4);
        __m512i src_text_6 = _mm512_loadu_si512(p_src512 + 5);
        __m512i src_text_7 = _mm512_loadu_si512(p_src512 + 6);
        __m512i src_text_8 = _mm512_loadu_si512(p_src512 + 7);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m512i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m512i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m512i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweakx8[0] ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweakx8[1] ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweakx8[2] ^ tweaked_src_text_3;
        tweaked_src_text_4 = tweakx8[3] ^ tweaked_src_text_4;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = aes::nextTweaks(tweakx8[6]);
        tweakx8[1] = aes::nextTweaks(tweakx8[7]);
        tweakx8[2] = aes::nextTweaks(tweakx8[0]);
        tweakx8[3] = aes::nextTweaks(tweakx8[1]);

        __m512i tweaked_src_text_5 = tweakx8[4] ^ src_text_5;
        __m512i tweaked_src_text_6 = tweakx8[5] ^ src_text_6;
        __m512i tweaked_src_text_7 = tweakx8[6] ^ src_text_7;
        __m512i tweaked_src_text_8 = tweakx8[7] ^ src_text_8;

        AesEncrypt(&tweaked_src_text_5,
                   &tweaked_src_text_6,
                   &tweaked_src_text_7,
                   &tweaked_src_text_8,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_5 = tweakx8[4] ^ tweaked_src_text_5;
        tweaked_src_text_6 = tweakx8[5] ^ tweaked_src_text_6;
        tweaked_src_text_7 = tweakx8[6] ^ tweaked_src_text_7;
        tweaked_src_text_8 = tweakx8[7] ^ tweaked_src_text_8;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512 + 4, tweaked_src_text_5);
        _mm512_storeu_si512(p_dest512 + 5, tweaked_src_text_6);
        _mm512_storeu_si512(p_dest512 + 6, tweaked_src_text_7);
        _mm512_storeu_si512(p_dest512 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = aes::nextTweaks(tweakx8[2]);
        tweakx8[5] = aes::nextTweaks(tweakx8[3]);
        tweakx8[6] = aes::nextTweaks(tweakx8[4]);
        tweakx8[7] = aes::nextTweaks(tweakx8[5]);

        p_dest512 += 8;
        p_src512 += 8;
        blocks -= chunk;
    }

    chunk                = 4 * 4;
    int tweak_to_be_used = 0;

    // Encrypting 4*4 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m512i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m512i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m512i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweakx8[0] ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweakx8[1] ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweakx8[2] ^ tweaked_src_text_3;
        tweaked_src_text_4 = tweakx8[3] ^ tweaked_src_text_4;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        p_dest512 += 4;
        p_src512 += 4;
        tweak_to_be_used += 4;
        blocks -= chunk;
    }
    chunk = 4 * 3;

    // Encrypting 4*3 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);

        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);
        __m512i tweak_2 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 1);
        __m512i tweak_3 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 2);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m512i tweaked_src_text_3 = tweak_3 ^ src_text_3;

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweak_3 ^ tweaked_src_text_3;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);

        p_dest512 += 3;
        p_src512 += 3;
        tweak_to_be_used += 3;
        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);
        __m512i tweak_2 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;

        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;
        tweak_to_be_used += 2;
        blocks -= chunk;
    }

    chunk = 4;

    // Encrypting 4*1 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        p_dest512 += 1;
        p_src512 += 1;
        tweak_to_be_used += 1;
        blocks -= chunk;
    }
    __m512i lastTweak = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);
    if (blocks) {
        uint8_t k          = (uint8_t)((1 << (blocks + blocks)) - 1);
        __m512i src_text_1 = _mm512_maskz_loadu_epi64(k, p_src512);

        src_text_1 = (lastTweak ^ src_text_1);

        AesEncrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = (lastTweak ^ src_text_1);

        memcpy((uint8_t*)p_dest512,
               (uint8_t*)&src_text_1,
               (unsigned long)(blocks * 16));
        memcpy((uint8_t*)p_dest512 + (16 * blocks),
               (uint8_t*)&src_text_1 + (16 * (blocks - 1)),
               extra_bytes_in_message_block);
    } else {
        memcpy((uint8_t*)p_dest512,
               (uint8_t*)p_dest512 - 16,
               extra_bytes_in_message_block);
    }
    if (extra_bytes_in_message_block) {
        __m512i stealed_text, temp_tweak;

        memcpy((uint8_t*)&temp_tweak,
               (uint8_t*)&lastTweak + ((16 * (blocks))),
               (16));

        memcpy((uint8_t*)&stealed_text + extra_bytes_in_message_block,
               (uint8_t*)p_dest512
                   + (extra_bytes_in_message_block + (16 * (blocks - 1))),
               (16 - extra_bytes_in_message_block));
        memcpy((uint8_t*)&stealed_text,
               (uint8_t*)p_src512 + ((16 * (blocks))),
               (extra_bytes_in_message_block));

        stealed_text = _mm512_xor_epi64(temp_tweak, stealed_text);

        AesEncrypt(&stealed_text, p_key128, nRounds);

        stealed_text = _mm512_xor_epi64(temp_tweak, stealed_text);
        memcpy((uint8_t*)p_dest512 + (16 * (blocks - 1)),
               (uint8_t*)&stealed_text,
               16);
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

    uint64_t blocks                       = len / Rijndael::cBlockSize;
    uint64_t extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    uint64_t chunk                        = 8 * 4;

    // iv encryption using tweak key to get alpha
    __m512i extendedIV = _mm512_setr_epi64(
        ((const uint64_t*)pIv)[0], ((const uint64_t*)pIv)[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);

    __m128i temp_iv = (((__m128i*)&extendedIV)[0]);
    __m512i tweakx8[8]; // 8*4 Tweak values stored inside this

    aes::init_alphax8(temp_iv, (__m128i*)tweakx8);

    __m128i* tweaks = (__m128i*)tweakx8;

    tweakx8[2] = aes::nextTweaks(tweakx8[0]);
    tweakx8[3] = aes::nextTweaks(tweakx8[1]);
    tweakx8[4] = aes::nextTweaks(tweakx8[2]);
    tweakx8[5] = aes::nextTweaks(tweakx8[3]);
    tweakx8[6] = aes::nextTweaks(tweakx8[4]);
    tweakx8[7] = aes::nextTweaks(tweakx8[5]);

    while (blocks >= chunk) {
        // Loading next 4*8 blocks of message
        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);
        __m512i src_text_5 = _mm512_loadu_si512(p_src512 + 4);
        __m512i src_text_6 = _mm512_loadu_si512(p_src512 + 5);
        __m512i src_text_7 = _mm512_loadu_si512(p_src512 + 6);
        __m512i src_text_8 = _mm512_loadu_si512(p_src512 + 7);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m512i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m512i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m512i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweakx8[0] ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweakx8[1] ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweakx8[2] ^ tweaked_src_text_3;
        tweaked_src_text_4 = tweakx8[3] ^ tweaked_src_text_4;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = aes::nextTweaks(tweakx8[6]);
        tweakx8[1] = aes::nextTweaks(tweakx8[7]);
        tweakx8[2] = aes::nextTweaks(tweakx8[0]);
        tweakx8[3] = aes::nextTweaks(tweakx8[1]);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp = tweaks[31];
            tweaks[31]   = tweaks[30];
            tweaks[30]   = temp;
        }

        __m512i tweaked_src_text_5 = tweakx8[4] ^ src_text_5;
        __m512i tweaked_src_text_6 = tweakx8[5] ^ src_text_6;
        __m512i tweaked_src_text_7 = tweakx8[6] ^ src_text_7;
        __m512i tweaked_src_text_8 = tweakx8[7] ^ src_text_8;

        AesDecrypt(&tweaked_src_text_5,
                   &tweaked_src_text_6,
                   &tweaked_src_text_7,
                   &tweaked_src_text_8,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_5 = tweakx8[4] ^ tweaked_src_text_5;
        tweaked_src_text_6 = tweakx8[5] ^ tweaked_src_text_6;
        tweaked_src_text_7 = tweakx8[6] ^ tweaked_src_text_7;
        tweaked_src_text_8 = tweakx8[7] ^ tweaked_src_text_8;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512 + 4, tweaked_src_text_5);
        _mm512_storeu_si512(p_dest512 + 5, tweaked_src_text_6);
        _mm512_storeu_si512(p_dest512 + 6, tweaked_src_text_7);
        _mm512_storeu_si512(p_dest512 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = aes::nextTweaks(tweakx8[2]);
        tweakx8[5] = aes::nextTweaks(tweakx8[3]);
        tweakx8[6] = aes::nextTweaks(tweakx8[4]);
        tweakx8[7] = aes::nextTweaks(tweakx8[5]);

        p_dest512 += 8;
        p_src512 += 8;
        blocks -= chunk;
    }

    chunk = 4 * 4;

    int tweak_to_be_used = 0;

    // Encrypting 4*4 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp = tweaks[15];
            tweaks[15]   = tweaks[14];
            tweaks[14]   = temp;
        }

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m512i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m512i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m512i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweakx8[0] ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweakx8[1] ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweakx8[2] ^ tweaked_src_text_3;
        tweaked_src_text_4 = tweakx8[3] ^ tweaked_src_text_4;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        p_dest512 += 4;
        p_src512 += 4;
        tweak_to_be_used += 4;
        blocks -= chunk;
    }
    chunk = 4 * 3;

    // Encrypting 4*3 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp = tweaks[tweak_to_be_used * 4 + 11];
            tweaks[tweak_to_be_used * 4 + 11] =
                tweaks[tweak_to_be_used * 4 + 10];
            tweaks[tweak_to_be_used * 4 + 10] = temp;
        }

        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);
        __m512i tweak_2 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 1);
        __m512i tweak_3 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 2);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m512i tweaked_src_text_3 = tweak_3 ^ src_text_3;

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweak_3 ^ tweaked_src_text_3;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        p_dest512 += 3;
        p_src512 += 3;
        tweak_to_be_used += 3;
        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                     = tweaks[tweak_to_be_used * 4 + 7];
            tweaks[tweak_to_be_used * 4 + 7] = tweaks[tweak_to_be_used * 4 + 6];
            tweaks[tweak_to_be_used * 4 + 6] = temp;
        }
        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);
        __m512i tweak_2 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used + 1);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;

        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;
        tweak_to_be_used += 2;
        blocks -= chunk;
    }

    chunk = 4;

    // Encrypting 4*1 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                     = tweaks[tweak_to_be_used * 4 + 3];
            tweaks[tweak_to_be_used * 4 + 3] = tweaks[tweak_to_be_used * 4 + 2];
            tweaks[tweak_to_be_used * 4 + 2] = temp;
        }
        __m512i tweak_1 = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        tweak_to_be_used += 1;
        blocks -= chunk;
        p_dest512 += 1;
        p_src512 += 1;
    }

    __m512i lastTweak = _mm512_loadu_si512(tweakx8 + tweak_to_be_used);

    if (blocks) {
        uint8_t k          = (uint8_t)((1 << (blocks + blocks)) - 1);
        __m512i src_text_1 = _mm512_maskz_loadu_epi64(k, p_src512);

        if (extra_bytes_in_message_block) {
            __m128i* tweak_p    = (__m128i*)&lastTweak;
            __m128i  temp_tweak = tweak_p[blocks - 1];
            tweak_p[blocks - 1] = tweak_p[blocks];
            tweak_p[blocks]     = temp_tweak;
        }
        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

        AesDecrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

        memcpy((uint8_t*)p_dest512,
               (uint8_t*)&src_text_1,
               (unsigned long)(blocks * 16));
        memcpy((uint8_t*)p_dest512 + (16 * blocks),
               (uint8_t*)&src_text_1 + (16 * (blocks - 1)),
               extra_bytes_in_message_block);
    }
    if (extra_bytes_in_message_block) {
        __m512i stealed_text, tweak_1;

        memcpy(
            (uint8_t*)&tweak_1, (uint8_t*)&lastTweak + ((16 * (blocks))), (16));

        memcpy((uint8_t*)&stealed_text + extra_bytes_in_message_block,
               (uint8_t*)p_dest512
                   + (extra_bytes_in_message_block + (16 * (blocks - 1))),
               (16 - extra_bytes_in_message_block));
        memcpy((uint8_t*)&stealed_text,
               (uint8_t*)p_src512 + ((16 * (blocks))),
               (extra_bytes_in_message_block));
        stealed_text = _mm512_xor_epi64(tweak_1, stealed_text);

        AesDecrypt(&stealed_text, p_key128, nRounds);

        stealed_text = _mm512_xor_epi64(tweak_1, stealed_text);
        memcpy((uint8_t*)p_dest512 + (16 * (blocks - 1)),
               (uint8_t*)&stealed_text,
               16);
    }

    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes
