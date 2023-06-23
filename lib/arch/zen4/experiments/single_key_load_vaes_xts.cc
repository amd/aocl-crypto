/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include "cipher/vaes_avx512_core.hh"
#include "cipher/zen4/aes_xts_zen4.hh"

#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "alcp/types.hh"
#include "alcp/utils/copy.hh"
#include "key.hh"

#define ENABLE_SINGLE_KEY_LOAD 1

namespace alcp::cipher::experimental {

alc_error_t
EncryptXtsAvx512(const Uint8* pSrc,
                 Uint8*       pDest,
                 Uint64       len,
                 const Uint8* pKey,
                 const Uint8* pTweakKey,
                 int          nRounds,
                 const Uint8* pIv)
{

    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src512       = reinterpret_cast<const __m512i*>(pSrc);
    auto p_dest512      = reinterpret_cast<__m512i*>(pDest);
    auto p_iv64         = reinterpret_cast<const Uint64*>(pIv);

    Uint64 blocks                       = len / Rijndael::cBlockSize;
    Uint64 extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    Uint64 chunk                        = 8 * 4;

    __m512i key_512_0, key_512_1, key_512_2, key_512_3, key_512_4, key_512_5,
        key_512_6, key_512_7, key_512_8, key_512_9, key_512_10, key_512_11,
        key_512_12, key_512_13, key_512_14;
    alcp_load_key_zmm(p_key128,
                      key_512_0,
                      key_512_1,
                      key_512_2,
                      key_512_3,
                      key_512_4,
                      key_512_5,
                      key_512_6,
                      key_512_7,
                      key_512_8,
                      key_512_9,
                      key_512_10,
                      key_512_11,
                      key_512_12,
                      key_512_13,
                      key_512_14);

    // iv encryption using tweak key to get alpha
    __m512i extendedIV =
        _mm512_setr_epi64(p_iv64[0], p_iv64[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);

    __m512i tweakx8[8]; // 8*4 Tweak values stored inside this

    __m128i* p_iv128     = reinterpret_cast<__m128i*>(&extendedIV);
    __m128i* p_tweaks128 = reinterpret_cast<__m128i*>(tweakx8);

    aes::init_alphax8(p_iv128[0], p_tweaks128);

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

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_4x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        tweaked_src_text_4,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
#endif
        // getting Cipher Text after xor of
        // message and Alpha ^ j
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

        // getting Cipher Text after xor of
        // message and Alpha ^ j
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

    chunk         = 4 * 4;
    int tweak_idx = 0;

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

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_4x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        tweaked_src_text_4,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
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
        tweak_idx += 4;
        blocks -= chunk;
    }
    chunk = 4 * 3;

    // Encrypting 4*3 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);

        __m512i tweak_1 = tweakx8[tweak_idx];
        __m512i tweak_2 = tweakx8[tweak_idx + 1];
        __m512i tweak_3 = tweakx8[tweak_idx + 2];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m512i tweaked_src_text_3 = tweak_3 ^ src_text_3;
#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_3x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweak_3 ^ tweaked_src_text_3;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);

        p_dest512 += 3;
        p_src512 += 3;
        tweak_idx += 3;
        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        __m512i tweak_1 = tweakx8[tweak_idx];
        __m512i tweak_2 = tweakx8[tweak_idx + 1];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_2x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;
        tweak_idx += 2;
        blocks -= chunk;
    }

    chunk = 4;

    // Encrypting 4*1 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        __m512i tweak_1 = tweakx8[tweak_idx];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_1x512(tweaked_src_text_1,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        p_dest512 += 1;
        p_src512 += 1;
        tweak_idx += 1;
        blocks -= chunk;
    }

    __m512i lastTweak    = tweakx8[tweak_idx];
    Uint8*  p_lastTweak8 = reinterpret_cast<Uint8*>(&lastTweak);
    Uint8*  p_dest8      = reinterpret_cast<Uint8*>(p_dest512);
    auto    p_src8       = reinterpret_cast<const Uint8*>(p_src512);

    if (blocks) {
        Uint8   k           = ((1 << (blocks + blocks)) - 1);
        __m512i src_text_1  = _mm512_maskz_loadu_epi64(k, p_src512);
        Uint8*  p_src_text8 = reinterpret_cast<Uint8*>(&src_text_1);

        src_text_1 = (lastTweak ^ src_text_1);

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_1x512(src_text_1,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&src_text_1, p_key128, nRounds);
#endif
        src_text_1 = (lastTweak ^ src_text_1);

        utils::CopyBytes(p_dest8, p_src_text8, (unsigned long)(blocks * 16));

        utils::CopyBytes((p_dest8 + (16 * blocks)),
                         p_src_text8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);

    } else {
        utils::CopyBytes(p_dest8, p_dest8 - 16, extra_bytes_in_message_block);
    }

    if (extra_bytes_in_message_block) {
        __m512i stealed_text, temp_tweak;
        Uint8*  p_stealed_text = reinterpret_cast<Uint8*>(&stealed_text);
        Uint8*  p_temp_tweak   = reinterpret_cast<Uint8*>(&temp_tweak);

        utils::CopyBytes(p_temp_tweak, p_lastTweak8 + ((16 * (blocks))), (16));

        utils::CopyBytes(
            p_stealed_text + extra_bytes_in_message_block,
            p_dest8 + (extra_bytes_in_message_block + (16 * (blocks - 1))),
            (16 - extra_bytes_in_message_block));

        utils::CopyBytes(p_stealed_text,
                         p_src8 + ((16 * (blocks))),
                         (extra_bytes_in_message_block));

        stealed_text = _mm512_xor_epi64(temp_tweak, stealed_text);

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesEncryptNoLoad_1x512(stealed_text,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesEncrypt(&stealed_text, p_key128, nRounds);
#endif
        stealed_text = _mm512_xor_epi64(temp_tweak, stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text, 16);
    }
    return ALC_ERROR_NONE;
}

alc_error_t
DecryptXtsAvx512(const Uint8* pSrc,
                 Uint8*       pDest,
                 Uint64       len,
                 const Uint8* pKey,
                 const Uint8* pTweakKey,
                 int          nRounds,
                 const Uint8* pIv)
{
    auto p_key128       = reinterpret_cast<const __m128i*>(pKey);
    auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src512       = reinterpret_cast<const __m512i*>(pSrc);
    auto p_dest512      = reinterpret_cast<__m512i*>(pDest);
    auto p_iv64         = reinterpret_cast<const Uint64*>(pIv);

    Uint64 blocks                       = len / Rijndael::cBlockSize;
    Uint64 extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    Uint64 chunk                        = 8 * 4;

    __m512i key_512_0, key_512_1, key_512_2, key_512_3, key_512_4, key_512_5,
        key_512_6, key_512_7, key_512_8, key_512_9, key_512_10, key_512_11,
        key_512_12, key_512_13, key_512_14;
    alcp_load_key_zmm(p_key128,
                      key_512_0,
                      key_512_1,
                      key_512_2,
                      key_512_3,
                      key_512_4,
                      key_512_5,
                      key_512_6,
                      key_512_7,
                      key_512_8,
                      key_512_9,
                      key_512_10,
                      key_512_11,
                      key_512_12,
                      key_512_13,
                      key_512_14);

    // iv encryption using tweak key to get alpha
    __m512i extendedIV =
        _mm512_setr_epi64(p_iv64[0], p_iv64[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);

    __m512i tweakx8[8]; // 8*4 Tweak values stored inside this

    __m128i* p_iv128     = reinterpret_cast<__m128i*>(&extendedIV);
    __m128i* p_tweaks128 = reinterpret_cast<__m128i*>(tweakx8);

    aes::init_alphax8(p_iv128[0], p_tweaks128);

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

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_4x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        tweaked_src_text_4,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
#endif
        // getting Cipher Text after xor of
        // message and Alpha ^ j
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
            __m128i temp    = p_tweaks128[31];
            p_tweaks128[31] = p_tweaks128[30];
            p_tweaks128[30] = temp;
        }

        __m512i tweaked_src_text_5 = tweakx8[4] ^ src_text_5;
        __m512i tweaked_src_text_6 = tweakx8[5] ^ src_text_6;
        __m512i tweaked_src_text_7 = tweakx8[6] ^ src_text_7;
        __m512i tweaked_src_text_8 = tweakx8[7] ^ src_text_8;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_4x512(tweaked_src_text_5,
                                        tweaked_src_text_6,
                                        tweaked_src_text_7,
                                        tweaked_src_text_8,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_5,
                   &tweaked_src_text_6,
                   &tweaked_src_text_7,
                   &tweaked_src_text_8,
                   p_key128,
                   nRounds);
#endif
        // getting Cipher Text after xor of
        // message and Alpha ^ j
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

    chunk         = 4 * 4;
    int tweak_idx = 0;

    // Encrypting 4*4 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp    = p_tweaks128[15];
            p_tweaks128[15] = p_tweaks128[14];
            p_tweaks128[14] = temp;
        }

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweakx8[0] ^ src_text_1;
        __m512i tweaked_src_text_2 = tweakx8[1] ^ src_text_2;
        __m512i tweaked_src_text_3 = tweakx8[2] ^ src_text_3;
        __m512i tweaked_src_text_4 = tweakx8[3] ^ src_text_4;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_4x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        tweaked_src_text_4,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
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
        tweak_idx += 4;
        blocks -= chunk;
    }
    chunk = 4 * 3;

    // Encrypting 4*3 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                    = p_tweaks128[tweak_idx * 4 + 11];
            p_tweaks128[tweak_idx * 4 + 11] = p_tweaks128[tweak_idx * 4 + 10];
            p_tweaks128[tweak_idx * 4 + 10] = temp;
        }

        __m512i tweak_1 = tweakx8[tweak_idx];
        __m512i tweak_2 = tweakx8[tweak_idx + 1];
        __m512i tweak_3 = tweakx8[tweak_idx + 2];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;
        __m512i tweaked_src_text_3 = tweak_3 ^ src_text_3;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_3x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        tweaked_src_text_3,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweak_3 ^ tweaked_src_text_3;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        p_dest512 += 3;
        p_src512 += 3;
        tweak_idx += 3;
        blocks -= chunk;
    }

    chunk = 4 * 2;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                   = p_tweaks128[tweak_idx * 4 + 7];
            p_tweaks128[tweak_idx * 4 + 7] = p_tweaks128[tweak_idx * 4 + 6];
            p_tweaks128[tweak_idx * 4 + 6] = temp;
        }
        __m512i tweak_1 = tweakx8[tweak_idx];
        __m512i tweak_2 = tweakx8[tweak_idx + 1];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m512i tweaked_src_text_2 = tweak_2 ^ src_text_2;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_2x512(tweaked_src_text_1,
                                        tweaked_src_text_2,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweak_2 ^ tweaked_src_text_2;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);

        p_dest512 += 2;
        p_src512 += 2;
        tweak_idx += 2;
        blocks -= chunk;
    }

    chunk = 4;

    // Encrypting 4*1 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);

        if (blocks == chunk && extra_bytes_in_message_block) {
            __m128i temp                   = p_tweaks128[tweak_idx * 4 + 3];
            p_tweaks128[tweak_idx * 4 + 3] = p_tweaks128[tweak_idx * 4 + 2];
            p_tweaks128[tweak_idx * 4 + 2] = temp;
        }
        __m512i tweak_1 = tweakx8[tweak_idx];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = tweak_1 ^ src_text_1;

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_1x512(tweaked_src_text_1,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);
#endif
        // getting Chiper Text after xor of
        // message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);

        tweak_idx += 1;
        blocks -= chunk;
        p_dest512 += 1;
        p_src512 += 1;
    }

    __m512i  lastTweak    = tweakx8[tweak_idx];
    __m128i* p_lastTweak  = reinterpret_cast<__m128i*>(&lastTweak);
    Uint8*   p_lastTweak8 = reinterpret_cast<Uint8*>(&lastTweak);
    Uint8*   p_dest8      = reinterpret_cast<Uint8*>(p_dest512);
    auto     p_src8       = reinterpret_cast<const Uint8*>(p_src512);

    if (blocks) {
        Uint8   k           = (Uint8)((1 << (blocks + blocks)) - 1);
        __m512i src_text_1  = _mm512_maskz_loadu_epi64(k, p_src512);
        Uint8*  p_src_text8 = reinterpret_cast<Uint8*>(&src_text_1);

        if (extra_bytes_in_message_block) {

            __m128i temp_tweak      = p_lastTweak[blocks - 1];
            p_lastTweak[blocks - 1] = p_lastTweak[blocks];
            p_lastTweak[blocks]     = temp_tweak;
        }
        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_1x512(src_text_1,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&src_text_1, p_key128, nRounds);
#endif
        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

        utils::CopyBytes(p_dest8, p_src_text8, (unsigned long)(blocks * 16));

        utils::CopyBytes(p_dest8 + (16 * blocks),
                         p_src_text8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);
    }

    if (extra_bytes_in_message_block) {
        __m512i stealed_text, tweak_1;
        Uint8*  p_stealed_text = reinterpret_cast<Uint8*>(&stealed_text);
        Uint8*  p_tweak_1      = reinterpret_cast<Uint8*>(&tweak_1);

        utils::CopyBytes(p_tweak_1, p_lastTweak8 + ((16 * (blocks))), (16));

        utils::CopyBytes(
            p_stealed_text + extra_bytes_in_message_block,
            p_dest8 + (extra_bytes_in_message_block + (16 * (blocks - 1))),
            (16 - extra_bytes_in_message_block));

        utils::CopyBytes(p_stealed_text,
                         p_src8 + ((16 * (blocks))),
                         (extra_bytes_in_message_block));

        stealed_text = _mm512_xor_epi64(tweak_1, stealed_text);

#if ENABLE_SINGLE_KEY_LOAD
        vaes512::AesDecryptNoLoad_1x512(stealed_text,
                                        key_512_0,
                                        key_512_1,
                                        key_512_2,
                                        key_512_3,
                                        key_512_4,
                                        key_512_5,
                                        key_512_6,
                                        key_512_7,
                                        key_512_8,
                                        key_512_9,
                                        key_512_10,
                                        key_512_11,
                                        key_512_12,
                                        key_512_13,
                                        key_512_14,
                                        nRounds);
#else
        AesDecrypt(&stealed_text, p_key128, nRounds);
#endif
        stealed_text = _mm512_xor_epi64(tweak_1, stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text, 16);
    }

    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::experimental
