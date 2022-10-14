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
#include "cipher/avx256.hh"
#include "cipher/vaes.hh"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "error.hh"
#include "key.hh"
#include "types.hh"
#include "utils/copy.hh"

namespace alcp::cipher::vaes {

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
    auto p_iv64         = reinterpret_cast<const uint64_t*>(pIv);

    uint64_t blocks                       = len / Rijndael::cBlockSize;
    uint64_t extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    uint64_t chunk                        = 2 * 8;

    // iv encryption using tweak key to get alpha
    __m256i extendedIV = _mm256_setr_epi64x(p_iv64[0], p_iv64[1], 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);

    __m256i tweakx8[8]; // 8*2 Tweak values stored inside this

    auto p_iv128    = reinterpret_cast<__m128i*>(&extendedIV);
    auto p_tweak128 = reinterpret_cast<__m128i*>(tweakx8);

    aes::init_alphax8(p_iv128[0], p_tweak128);

    tweakx8[4] = aes::nextTweaks(tweakx8[0]);
    tweakx8[5] = aes::nextTweaks(tweakx8[1]);
    tweakx8[6] = aes::nextTweaks(tweakx8[2]);
    tweakx8[7] = aes::nextTweaks(tweakx8[3]);

    while (blocks >= chunk) {

        // Loading next 4*8 blocks of message
        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);
        __m256i src_text_5 = _mm256_loadu_si256(p_src256 + 4);
        __m256i src_text_6 = _mm256_loadu_si256(p_src256 + 5);
        __m256i src_text_7 = _mm256_loadu_si256(p_src256 + 6);
        __m256i src_text_8 = _mm256_loadu_si256(p_src256 + 7);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m256i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m256i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m256i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;
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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = aes::nextTweaks(tweakx8[4]);
        tweakx8[1] = aes::nextTweaks(tweakx8[5]);
        tweakx8[2] = aes::nextTweaks(tweakx8[6]);
        tweakx8[3] = aes::nextTweaks(tweakx8[7]);

        __m256i tweaked_src_text_5 = tweakx8[4] ^ src_text_5;
        __m256i tweaked_src_text_6 = tweakx8[5] ^ src_text_6;
        __m256i tweaked_src_text_7 = tweakx8[6] ^ src_text_7;
        __m256i tweaked_src_text_8 = tweakx8[7] ^ src_text_8;

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
        _mm256_storeu_si256(p_dest256 + 4, tweaked_src_text_5);
        _mm256_storeu_si256(p_dest256 + 5, tweaked_src_text_6);
        _mm256_storeu_si256(p_dest256 + 6, tweaked_src_text_7);
        _mm256_storeu_si256(p_dest256 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = aes::nextTweaks(tweakx8[0]);
        tweakx8[5] = aes::nextTweaks(tweakx8[1]);
        tweakx8[6] = aes::nextTweaks(tweakx8[2]);
        tweakx8[7] = aes::nextTweaks(tweakx8[3]);

        p_dest256 += 8;
        p_src256 += 8;
        blocks -= chunk;
    }

    chunk         = 2 * 4;
    int tweak_idx = 0;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m256i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m256i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m256i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        p_dest256 += 4;
        p_src256 += 4;
        tweak_idx += 4;
        blocks -= chunk;
    }

    chunk = 2 * 3;

    // Encrypting 2*3 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);

        __m256i tweak_1 = tweakx8[tweak_idx];
        __m256i tweak_2 = tweakx8[tweak_idx + 1];
        __m256i tweak_3 = tweakx8[tweak_idx + 2];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m256i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m256i tweaked_src_text_3 = tweak_3 ^ src_text_3;
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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);

        p_dest256 += 3;
        p_src256 += 3;
        tweak_idx += 3;
        blocks -= chunk;
    }

    chunk = 2 * 2;

    // Encrypting 2*2 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);

        __m256i tweak_1 = tweakx8[tweak_idx];
        __m256i tweak_2 = tweakx8[tweak_idx + 1];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m256i tweaked_src_text_2 = tweak_2 ^ src_text_2;

        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);

        p_dest256 += 2;
        p_src256 += 2;
        tweak_idx += 2;
        blocks -= chunk;
    }

    chunk = 2;

    // Encrypting 2*1 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);

        __m256i tweak_1 = tweakx8[tweak_idx];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;
        tweak_idx += 1;
        blocks -= chunk;
    }

    __m256i lastTweak    = tweakx8[tweak_idx];
    auto    p_lastTweak8 = reinterpret_cast<uint8_t*>(&lastTweak);
    auto    p_dest8      = reinterpret_cast<uint8_t*>(p_dest256);
    auto    p_src8       = reinterpret_cast<const uint8_t*>(p_src256);

    if (blocks) {

        __m256i src_text_1   = alcp_loadu_128(p_src256);
        auto    p_src_text_1 = reinterpret_cast<uint8_t*>(&src_text_1);

        src_text_1 = lastTweak ^ src_text_1;

        AesEncrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = lastTweak ^ src_text_1;

        utils::CopyBytes(p_dest8, p_src_text_1, (16));
    }

    if (extra_bytes_in_message_block) {
        utils::CopyBytes(p_dest8 + (16 * blocks),
                         p_dest8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);
        __m256i stealed_text, tweak_1;
        auto    p_stealed_text8 = reinterpret_cast<uint8_t*>(&stealed_text);
        auto    p_tweak_8       = reinterpret_cast<uint8_t*>(&tweak_1);

        utils::CopyBytes(p_tweak_8, p_lastTweak8 + (16 * blocks), 16);

        utils::CopyBytes(p_stealed_text8 + extra_bytes_in_message_block,
                         p_dest8 + (16 * (blocks - 1))
                             + (extra_bytes_in_message_block),
                         (16 - extra_bytes_in_message_block));

        utils::CopyBytes(p_stealed_text8,
                         p_src8 + (16 * blocks),
                         extra_bytes_in_message_block);

        stealed_text = (tweak_1 ^ stealed_text);
        AesEncrypt(&stealed_text, p_key128, nRounds);
        stealed_text = (tweak_1 ^ stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text8, 16);
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
    auto p_iv64         = reinterpret_cast<const uint64_t*>(pIv);

    uint64_t blocks                       = len / Rijndael::cBlockSize;
    uint64_t extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    uint64_t chunk                        = 8 * 2;

    // iv encryption using tweak key to get alpha
    __m256i extendedIV = _mm256_setr_epi64x(p_iv64[0], p_iv64[1], 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);

    __m256i tweakx8[8]; // 8*2 Tweak values stored inside this

    __m128i* p_iv128     = reinterpret_cast<__m128i*>(&extendedIV);
    __m128i* p_tweaks128 = reinterpret_cast<__m128i*>(tweakx8);

    aes::init_alphax8(p_iv128[0], p_tweaks128);

    tweakx8[4] = aes::nextTweaks(tweakx8[0]);
    tweakx8[5] = aes::nextTweaks(tweakx8[1]);
    tweakx8[6] = aes::nextTweaks(tweakx8[2]);
    tweakx8[7] = aes::nextTweaks(tweakx8[3]);

    while (blocks >= chunk) {

        // Loading next 2*8 blocks of message
        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);
        __m256i src_text_5 = _mm256_loadu_si256(p_src256 + 4);
        __m256i src_text_6 = _mm256_loadu_si256(p_src256 + 5);
        __m256i src_text_7 = _mm256_loadu_si256(p_src256 + 6);
        __m256i src_text_8 = _mm256_loadu_si256(p_src256 + 7);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m256i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m256i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m256i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = aes::nextTweaks(tweakx8[4]);
        tweakx8[1] = aes::nextTweaks(tweakx8[5]);
        tweakx8[2] = aes::nextTweaks(tweakx8[6]);
        tweakx8[3] = aes::nextTweaks(tweakx8[7]);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp    = p_tweaks128[15];
            p_tweaks128[15] = p_tweaks128[0];
            p_tweaks128[0]  = temp;
        }

        __m256i tweaked_src_text_5 = tweakx8[4] ^ src_text_5;
        __m256i tweaked_src_text_6 = tweakx8[5] ^ src_text_6;
        __m256i tweaked_src_text_7 = tweakx8[6] ^ src_text_7;
        __m256i tweaked_src_text_8 = tweakx8[7] ^ src_text_8;

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
        _mm256_storeu_si256(p_dest256 + 4, tweaked_src_text_5);
        _mm256_storeu_si256(p_dest256 + 5, tweaked_src_text_6);
        _mm256_storeu_si256(p_dest256 + 6, tweaked_src_text_7);
        _mm256_storeu_si256(p_dest256 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = aes::nextTweaks(tweakx8[0]);
        tweakx8[5] = aes::nextTweaks(tweakx8[1]);
        tweakx8[6] = aes::nextTweaks(tweakx8[2]);
        tweakx8[7] = aes::nextTweaks(tweakx8[3]);

        p_dest256 += 8;
        p_src256 += 8;
        blocks -= chunk;
    }

    chunk = 4 * 2;

    int tweak_idx = 0;

    // Encrypting 2*2 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);
        __m256i src_text_4 = _mm256_loadu_si256(p_src256 + 3);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp   = p_tweaks128[7];
            p_tweaks128[7] = p_tweaks128[8];
            p_tweaks128[8] = temp;
        }

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m256i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m256i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m256i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        _mm256_storeu_si256(p_dest256 + 3, tweaked_src_text_4);

        p_dest256 += 4;
        p_src256 += 4;
        tweak_idx += 4;
        blocks -= chunk;
    }
    chunk = 3 * 2;

    // Encrypting 2*3 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);
        __m256i src_text_3 = _mm256_loadu_si256(p_src256 + 2);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                   = p_tweaks128[tweak_idx * 2 + 5];
            p_tweaks128[tweak_idx * 2 + 5] = p_tweaks128[tweak_idx * 2 + 6];
            p_tweaks128[tweak_idx * 2 + 6] = temp;
        }

        __m256i tweak_1 = tweakx8[tweak_idx];
        __m256i tweak_2 = tweakx8[tweak_idx + 1];
        __m256i tweak_3 = tweakx8[tweak_idx + 2];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m256i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m256i tweaked_src_text_3 = tweak_3 ^ src_text_3;

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
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);
        _mm256_storeu_si256(p_dest256 + 2, tweaked_src_text_3);
        p_dest256 += 3;
        p_src256 += 3;
        tweak_idx += 3;
        blocks -= chunk;
    }

    chunk = 2 * 2;

    // Encrypting 2*2 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                   = p_tweaks128[tweak_idx * 2 + 3];
            p_tweaks128[tweak_idx * 2 + 3] = p_tweaks128[tweak_idx * 2 + 4];
            p_tweaks128[tweak_idx * 2 + 4] = temp;
        }

        __m256i tweak_1 = tweakx8[tweak_idx];
        __m256i tweak_2 = tweakx8[tweak_idx + 1];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m256i tweaked_src_text_2 = tweak_2 ^ src_text_2;

        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);
        _mm256_storeu_si256(p_dest256 + 1, tweaked_src_text_2);

        p_dest256 += 2;
        p_src256 += 2;
        tweak_idx += 2;
        blocks -= chunk;
    }

    chunk = 2;

    // Encrypting 2*1 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                   = p_tweaks128[tweak_idx * 2 + 1];
            p_tweaks128[tweak_idx * 2 + 1] = p_tweaks128[tweak_idx * 2 + 2];
            p_tweaks128[tweak_idx * 2 + 2] = temp;
        }

        __m256i tweak_1 = tweakx8[tweak_idx];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;
        tweak_idx += 1;
        blocks -= chunk;
    }

    __m256i  lastTweak    = tweakx8[tweak_idx];
    __m128i* p_lastTweak  = reinterpret_cast<__m128i*>(&lastTweak);
    uint8_t* p_lastTweak8 = reinterpret_cast<uint8_t*>(&lastTweak);
    uint8_t* p_dest8      = reinterpret_cast<uint8_t*>(p_dest256);
    auto     p_src8       = reinterpret_cast<const uint8_t*>(p_src256);

    if (blocks) {

        __m256i  src_text_1  = alcp_loadu_128(p_src256);
        uint8_t* p_src_text8 = reinterpret_cast<uint8_t*>(&src_text_1);

        if (extra_bytes_in_message_block) {

            __m128i temp_tweak      = p_lastTweak[blocks - 1];
            p_lastTweak[blocks - 1] = p_lastTweak[blocks];
            p_lastTweak[blocks]     = temp_tweak;
        }
        src_text_1 = lastTweak ^ src_text_1;

        AesDecrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = lastTweak ^ src_text_1;

        utils::CopyBytes(p_dest8, p_src_text8, (unsigned long)(blocks * 16));
    }

    if (extra_bytes_in_message_block) {

        utils::CopyBytes(p_dest8 + (16 * blocks),
                         p_dest8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);
        __m256i  stealed_text, tweak_1;
        uint8_t* p_stealed_text = reinterpret_cast<uint8_t*>(&stealed_text);
        uint8_t* p_tweak_1      = reinterpret_cast<uint8_t*>(&tweak_1);

        utils::CopyBytes(p_tweak_1, p_lastTweak8 + ((16 * (blocks))), (16));

        utils::CopyBytes(
            p_stealed_text + extra_bytes_in_message_block,
            p_dest8 + (extra_bytes_in_message_block + (16 * (blocks - 1))),
            (16 - extra_bytes_in_message_block));

        utils::CopyBytes(p_stealed_text,
                         p_src8 + ((16 * (blocks))),
                         (extra_bytes_in_message_block));

        stealed_text = (tweak_1 ^ stealed_text);
        AesDecrypt(&stealed_text, p_key128, nRounds);
        stealed_text = (tweak_1 ^ stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text, 16);
    }

    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes
