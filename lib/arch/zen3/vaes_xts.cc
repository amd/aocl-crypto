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
#include "avx256.hh"
#include "vaes.hh"

#include "alcp/cipher/aes.hh"
#include "alcp/types.hh"
#include "alcp/utils/copy.hh"
#include "cipher/avx2/aes_xts_avx2.hh"

#include <immintrin.h>

namespace alcp::cipher::vaes {

template<
    void AesEnc_1x256(__m256i* a, const __m128i* pKey, int nRounds),
    void AesEnc_2x256(__m256i* a, __m256i* b, const __m128i* pKey, int nRounds),
    void AesEnc_3x256(
        __m256i* a, __m256i* b, __m256i* c, const __m128i* pKey, int nRounds),
    void AesEnc_4x256(__m256i*       a,
                      __m256i*       b,
                      __m256i*       c,
                      __m256i*       d,
                      const __m128i* pKey,
                      int            nRounds)>
inline alc_error_t
EncryptXts(const Uint8* pSrc,
           Uint8*       pDest,
           Uint64       len,
           const Uint8* pKey,
           const Uint8* pTweakKey,
           int          nRounds,
           Uint8*       pIv)
{

    auto p_key128 = reinterpret_cast<const __m128i*>(pKey);
    // auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src256   = reinterpret_cast<const __m256i*>(pSrc);
    auto p_dest256  = reinterpret_cast<__m256i*>(pDest);
    auto p_iv128_in = reinterpret_cast<__m128i*>(pIv);
    auto p_iv64     = reinterpret_cast<Uint64*>(pIv);

    Uint64 blocks                       = len / Rijndael::cBlockSize;
    Uint64 extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    Uint64 chunk                        = 2 * 8;

    // iv encryption using tweak key to get alpha
    // __m128i tweakBlk   = _mm_load_si128(p_iv128_in);
    __m256i extendedIV = _mm256_setr_epi64x(p_iv64[0], p_iv64[1], 0, 0);
    // __m256i extendedIV = _mm256_set_m128i(tweakBlk, tweakBlk);

    // AesEnc_1x256(&extendedIV, p_tweak_key128, nRounds);

    __m256i tweakx8[8]; // 8*2 Tweak values stored inside this
    __m256i nextTweakBlock;

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
        AesEnc_4x256(&tweaked_src_text_1,
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

        AesEnc_4x256(&tweaked_src_text_5,
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
        __m256i tweaked_src_text_1 = tweakx8[tweak_idx + 0] ^ src_text_1;
        __m256i tweaked_src_text_2 = tweakx8[tweak_idx + 1] ^ src_text_2;
        __m256i tweaked_src_text_3 = tweakx8[tweak_idx + 2] ^ src_text_3;
        __m256i tweaked_src_text_4 = tweakx8[tweak_idx + 3] ^ src_text_4;

        AesEnc_4x256(&tweaked_src_text_1,
                     &tweaked_src_text_2,
                     &tweaked_src_text_3,
                     &tweaked_src_text_4,
                     p_key128,
                     nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweakx8[tweak_idx + 0] ^ tweaked_src_text_1;
        tweaked_src_text_2 = tweakx8[tweak_idx + 1] ^ tweaked_src_text_2;
        tweaked_src_text_3 = tweakx8[tweak_idx + 2] ^ tweaked_src_text_3;
        tweaked_src_text_4 = tweakx8[tweak_idx + 3] ^ tweaked_src_text_4;

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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 2 * 3;

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
        AesEnc_3x256(&tweaked_src_text_1,
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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 2 * 2;

    // Encrypting 2*2 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);
        __m256i src_text_2 = _mm256_loadu_si256(p_src256 + 1);

        __m256i tweak_1 = tweakx8[tweak_idx];
        __m256i tweak_2 = tweakx8[tweak_idx + 1];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;
        __m256i tweaked_src_text_2 = tweak_2 ^ src_text_2;

        AesEnc_2x256(
            &tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 2;

    // Encrypting 2*1 source text blocks at a time
    if (blocks >= chunk) {

        __m256i src_text_1 = _mm256_loadu_si256(p_src256);

        __m256i tweak_1 = tweakx8[tweak_idx];

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m256i tweaked_src_text_1 = tweak_1 ^ src_text_1;

        AesEnc_1x256(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;
        tweak_idx += 1;
        blocks -= chunk;
    }

    nextTweakBlock       = tweakx8[tweak_idx];
    __m256i lastTweak    = tweakx8[tweak_idx];
    auto    p_lastTweak8 = reinterpret_cast<Uint8*>(&lastTweak);
    auto    p_dest8      = reinterpret_cast<Uint8*>(p_dest256);
    auto    p_src8       = reinterpret_cast<const Uint8*>(p_src256);

    if (blocks) {

        __m256i src_text_1   = alcp_loadu_128(p_src256);
        auto    p_src_text_1 = reinterpret_cast<Uint8*>(&src_text_1);

        src_text_1 = lastTweak ^ src_text_1;

        AesEnc_1x256(&src_text_1, p_key128, nRounds);

        src_text_1 = lastTweak ^ src_text_1;

        utils::CopyBytes(p_dest8, p_src_text_1, (16));

        // Swap low and high
        nextTweakBlock = _mm256_permute2x128_si256(lastTweak, lastTweak, 0x01);
        lastTweak      = nextTweakBlock;
    }

    if (extra_bytes_in_message_block) {
        utils::CopyBytes(p_dest8 + (16 * blocks),
                         p_dest8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);
        __m256i stealed_text, tweak_1;
        auto    p_stealed_text8 = reinterpret_cast<Uint8*>(&stealed_text);
        auto    p_tweak_8       = reinterpret_cast<Uint8*>(&tweak_1);

        utils::CopyBytes(p_tweak_8, p_lastTweak8, 16);

        utils::CopyBytes(p_stealed_text8 + extra_bytes_in_message_block,
                         p_dest8 + (16 * (blocks - 1))
                             + (extra_bytes_in_message_block),
                         (16 - extra_bytes_in_message_block));

        utils::CopyBytes(p_stealed_text8,
                         p_src8 + (16 * blocks),
                         extra_bytes_in_message_block);

        stealed_text = (tweak_1 ^ stealed_text);
        AesEnc_1x256(&stealed_text, p_key128, nRounds);
        stealed_text = (tweak_1 ^ stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text8, 16);

        // Swap low and high
        nextTweakBlock = _mm256_permute2x128_si256(lastTweak, lastTweak, 0x01);
    }

    _mm_store_si128(p_iv128_in, *(__m128i*)(&nextTweakBlock));
    return ALC_ERROR_NONE;
}

template<
    void AesEnc_1x256(__m256i* a, const __m128i* pKey, int nRounds),
    void AesDec_1x256(__m256i* a, const __m128i* pKey, int nRounds),
    void AesDec_2x256(__m256i* a, __m256i* b, const __m128i* pKey, int nRounds),
    void AesDec_3x256(
        __m256i* a, __m256i* b, __m256i* c, const __m128i* pKey, int nRounds),
    void AesDec_4x256(__m256i*       a,
                      __m256i*       b,
                      __m256i*       c,
                      __m256i*       d,
                      const __m128i* pKey,
                      int            nRounds)>
inline alc_error_t
DecryptXts(const Uint8* pSrc,
           Uint8*       pDest,
           Uint64       len,
           const Uint8* pKey,
           const Uint8* pTweakKey,
           int          nRounds,
           Uint8*       pIv)
{
    auto p_key128 = reinterpret_cast<const __m128i*>(pKey);
    // auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
    auto p_src256   = reinterpret_cast<const __m256i*>(pSrc);
    auto p_dest256  = reinterpret_cast<__m256i*>(pDest);
    auto p_iv128_in = reinterpret_cast<__m128i*>(pIv);
    auto p_iv64     = reinterpret_cast<Uint64*>(pIv);

    Uint64 blocks                       = len / Rijndael::cBlockSize;
    Uint64 extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    Uint64 chunk                        = 8 * 2;

    // iv encryption using tweak key to get alpha
    __m256i extendedIV = _mm256_setr_epi64x(p_iv64[0], p_iv64[1], 0, 0);

    // AesEnc_1x256(&extendedIV, p_tweak_key128, nRounds);

    __m256i tweakx8[8]; // 8*2 Tweak values stored inside this
    __m256i nextTweakBlock;

    auto p_iv128     = reinterpret_cast<__m128i*>(&extendedIV);
    auto p_tweaks128 = reinterpret_cast<__m128i*>(tweakx8);

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

        AesDec_4x256(&tweaked_src_text_1,
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

        AesDec_4x256(&tweaked_src_text_5,
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

    chunk         = 4 * 2;
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

        AesDec_4x256(&tweaked_src_text_1,
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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 3 * 2;

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

        AesDec_3x256(&tweaked_src_text_1,
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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 2 * 2;

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

        AesDec_2x256(
            &tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

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

    nextTweakBlock = tweakx8[tweak_idx];
    chunk          = 2;

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

        AesDec_1x256(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = tweak_1 ^ tweaked_src_text_1;

        // storing the results in destination
        _mm256_storeu_si256(p_dest256, tweaked_src_text_1);

        p_dest256 += 1;
        p_src256 += 1;
        tweak_idx += 1;
        blocks -= chunk;
    }

    nextTweakBlock        = tweakx8[tweak_idx];
    __m256i  lastTweak    = tweakx8[tweak_idx];
    __m128i* p_lastTweak  = reinterpret_cast<__m128i*>(&lastTweak);
    Uint8*   p_lastTweak8 = reinterpret_cast<Uint8*>(&lastTweak);
    Uint8*   p_dest8      = reinterpret_cast<Uint8*>(p_dest256);
    auto     p_src8       = reinterpret_cast<const Uint8*>(p_src256);

    if (blocks) {

        __m256i src_text_1  = alcp_loadu_128(p_src256);
        Uint8*  p_src_text8 = reinterpret_cast<Uint8*>(&src_text_1);

        if (extra_bytes_in_message_block) {

            __m128i temp_tweak      = p_lastTweak[blocks - 1];
            p_lastTweak[blocks - 1] = p_lastTweak[blocks];
            p_lastTweak[blocks]     = temp_tweak;
        }
        src_text_1 = lastTweak ^ src_text_1;

        AesDec_1x256(&src_text_1, p_key128, nRounds);

        src_text_1 = lastTweak ^ src_text_1;

        utils::CopyBytes(p_dest8, p_src_text8, (unsigned long)(blocks * 16));

        // Swap low and high
        nextTweakBlock = _mm256_permute2x128_si256(lastTweak, lastTweak, 0x01);
    }

    if (extra_bytes_in_message_block) {

        utils::CopyBytes(p_dest8 + (16 * blocks),
                         p_dest8 + (16 * (blocks - 1)),
                         extra_bytes_in_message_block);
        __m256i stealed_text, tweak_1;
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

        stealed_text = (tweak_1 ^ stealed_text);
        AesDec_1x256(&stealed_text, p_key128, nRounds);
        stealed_text = (tweak_1 ^ stealed_text);

        utils::CopyBytes(p_dest8 + (16 * (blocks - 1)), p_stealed_text, 16);
    }

    _mm_store_si128(p_iv128_in, *(__m128i*)(&nextTweakBlock));
    return ALC_ERROR_NONE;
}

alc_error_t
EncryptXts128(const Uint8* pSrc,
              Uint8*       pDest,
              Uint64       len,
              const Uint8* pKey,
              const Uint8* pTweakKey,
              int          nRounds,
              Uint8*       pIv)
{
    // AesEncrypt 1Block, 2Block, 3Block, 4Block
    return EncryptXts<AesEncrypt, AesEncrypt, AesEncrypt, AesEncrypt>(
        pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
}

alc_error_t
EncryptXts256(const Uint8* pSrc,
              Uint8*       pDest,
              Uint64       len,
              const Uint8* pKey,
              const Uint8* pTweakKey,
              int          nRounds,
              Uint8*       pIv)
{
    // AesEncrypt 1Block, 2Block, 3Block, 4Block
    return EncryptXts<AesEncrypt, AesEncrypt, AesEncrypt, AesEncrypt>(
        pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
}

alc_error_t
DecryptXts128(const Uint8* pSrc,
              Uint8*       pDest,
              Uint64       len,
              const Uint8* pKey,
              const Uint8* pTweakKey,
              int          nRounds,
              Uint8*       pIv)
{
    return DecryptXts<AesEncrypt,
                      AesDecrypt,
                      AesDecrypt,
                      AesDecrypt,
                      AesDecrypt>(
        pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
}

alc_error_t
DecryptXts256(const Uint8* pSrc,
              Uint8*       pDest,
              Uint64       len,
              const Uint8* pKey,
              const Uint8* pTweakKey,
              int          nRounds,
              Uint8*       pIv)
{
    return DecryptXts<AesEncrypt,
                      AesDecrypt,
                      AesDecrypt,
                      AesDecrypt,
                      AesDecrypt>(
        pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
}

} // namespace alcp::cipher::vaes
