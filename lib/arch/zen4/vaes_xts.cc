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
MultiplyAlphaByTwo(__m128i& alpha)
{
    Uint64 res, carry;

    Uint64* tmp_tweak = (Uint64*)&alpha;

    res   = (((long long)tmp_tweak[1]) >> 63) & GF_POLYNOMIAL;
    carry = (((long long)tmp_tweak[0]) >> 63) & 1;

    tmp_tweak[0] = ((tmp_tweak[0]) << 1) ^ res;
    tmp_tweak[1] = ((tmp_tweak[1]) << 1) | carry;
}

static inline void
init_alphax8(__m128i& alpha, __m128i* dst)
{

    dst[0] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[1] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[2] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[3] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[4] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[5] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[6] = alpha;
    MultiplyAplhaByTwo(alpha);
    dst[7] = alpha;
}

/* Generate next 4 tweaks with 2^8 multiplier */
static inline __m512i
nextTweaks(__m512i tweak128x4)
{

    const __m512i poly = _mm512_set_epi64(0, 0x87, 0, 0x87, 0, 0x87, 0, 0x87);
    __m512i       nexttweak;

    // Shifting individual 128 bit to right by 15*8 bits
    __m512i highBytes = _mm512_bsrli_epi128(tweak128x4, 15);

    // Multiplying each 128 bit individually to 64 bit at even index of poly
    __m512i tmp = _mm512_clmulepi64_epi128(highBytes, poly, 0);

    // Shifting individual 128 bit to left by 1*8 bits
    nexttweak = _mm512_bslli_epi128(tweak128x4, 1);
    nexttweak = _mm512_xor_si512(nexttweak, tmp);

    return nexttweak;
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

    uint64_t blocks                       = len / Rijndael::cBlockSize;
    uint64_t extra_bytes_in_message_block = len % Rijndael::cBlockSize;
    uint64_t chunk                        = 8 * 4;

    // iv encryption using tweak key to get alpha
    __m512i extendedIV = _mm512_setr_epi64(
        ((const uint64_t*)pIv)[0], ((const uint64_t*)pIv)[1], 0, 0, 0, 0, 0, 0);

    AesEncrypt(&extendedIV, p_tweak_key128, nRounds);
    __m128i tweaks[8 * 4]; // 8*4 Tweak values stored inside this

    init_alphax8(*((__m128i*)&extendedIV), tweaks);

    __m512i* tweakx8 = (__m512i*)tweaks;

    tweakx8[2] = nextTweaks(_mm512_loadu_si512(tweakx8));

    tweakx8[3] = nextTweaks(tweakx8[1]);
    tweakx8[4] = nextTweaks(tweakx8[2]);
    tweakx8[5] = nextTweaks(tweakx8[3]);
    tweakx8[6] = nextTweaks(tweakx8[4]);
    tweakx8[7] = nextTweaks(tweakx8[5]);

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
        __m512i tweaked_src_text_1 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8), src_text_1);
        __m512i tweaked_src_text_2 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 1), src_text_2);
        __m512i tweaked_src_text_3 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 2), src_text_3);
        __m512i tweaked_src_text_4 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 3), src_text_4);
        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8), tweaked_src_text_1);
        tweaked_src_text_2 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 1),
                                              tweaked_src_text_2);
        tweaked_src_text_3 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 2),
                                              tweaked_src_text_3);
        tweaked_src_text_4 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 3),
                                              tweaked_src_text_4);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = nextTweaks(_mm512_loadu_si512(tweakx8 + 6));
        tweakx8[1] = nextTweaks(_mm512_loadu_si512(tweakx8 + 7));
        tweakx8[2] = nextTweaks(_mm512_loadu_si512(tweakx8));
        tweakx8[3] = nextTweaks(_mm512_loadu_si512(tweakx8 + 1));

        __m512i src_text_5 = _mm512_loadu_si512(p_src512 + 4);
        __m512i src_text_6 = _mm512_loadu_si512(p_src512 + 5);
        __m512i src_text_7 = _mm512_loadu_si512(p_src512 + 6);
        __m512i src_text_8 = _mm512_loadu_si512(p_src512 + 7);

        __m512i tweaked_src_text_5 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 4), src_text_5);
        __m512i tweaked_src_text_6 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 5), src_text_6);
        __m512i tweaked_src_text_7 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 6), src_text_7);
        __m512i tweaked_src_text_8 =
            _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 7), src_text_8);

        AesEncrypt(&tweaked_src_text_5,
                   &tweaked_src_text_6,
                   &tweaked_src_text_7,
                   &tweaked_src_text_8,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_5 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 4),
                                              tweaked_src_text_5);
        tweaked_src_text_6 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 5),
                                              tweaked_src_text_6);
        tweaked_src_text_7 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 6),
                                              tweaked_src_text_7);
        tweaked_src_text_8 = _mm512_xor_si512(_mm512_loadu_si512(tweakx8 + 7),
                                              tweaked_src_text_8);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512 + 4, tweaked_src_text_5);
        _mm512_storeu_si512(p_dest512 + 5, tweaked_src_text_6);
        _mm512_storeu_si512(p_dest512 + 6, tweaked_src_text_7);
        _mm512_storeu_si512(p_dest512 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = nextTweaks(_mm512_loadu_si512(tweakx8 + 2));
        tweakx8[5] = nextTweaks(_mm512_loadu_si512(tweakx8 + 3));
        tweakx8[6] = nextTweaks(_mm512_loadu_si512(tweakx8 + 4));
        tweakx8[7] = nextTweaks(_mm512_loadu_si512(tweakx8 + 5));

        p_dest512 += 8;
        p_src512 += 8;
        blocks -= chunk;
    }

    chunk                = 4 * 4;
    int tweak_to_be_used = 0;

    int tweak_to_be_used = 0;
    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = _mm512_xor_si512(*(tweakx8), src_text_1);
        __m512i tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), src_text_2);
        __m512i tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), src_text_3);
        __m512i tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), src_text_4);

        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(*(tweakx8), tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), tweaked_src_text_2);
        tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), tweaked_src_text_3);
        tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), tweaked_src_text_4);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);
        __m512i tweaked_src_text_2 = _mm512_xor_si512(tweak_2, src_text_2);
        __m512i tweaked_src_text_3 = _mm512_xor_si512(tweak_3, src_text_3);
        AesEncrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);
        tweaked_src_text_2 = _mm512_xor_si512(tweak_2, tweaked_src_text_2);
        tweaked_src_text_3 = _mm512_xor_si512(tweak_3, tweaked_src_text_3);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);
        __m512i tweaked_src_text_2 = _mm512_xor_si512(tweak_2, src_text_2);

        AesEncrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);
        tweaked_src_text_2 = _mm512_xor_si512(tweak_2, tweaked_src_text_2);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);

        AesEncrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);

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

        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

        AesEncrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);

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

        AesEncrypt(&stealed_text, p_key128, nRounds);

        stealed_text = _mm512_xor_epi64(tweak_1, stealed_text);
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
    __m128i tweaks[8 * 4]; // 8*4 Tweak values stored inside this

    init_alphax8(temp_iv, tweaks);

    __m512i* tweakx8 = (__m512i*)tweaks;
    tweakx8[2]       = nextTweaks(tweakx8[0]);
    tweakx8[3]       = nextTweaks(tweakx8[1]);
    tweakx8[4]       = nextTweaks(tweakx8[2]);
    tweakx8[5]       = nextTweaks(tweakx8[3]);
    tweakx8[6]       = nextTweaks(tweakx8[4]);
    tweakx8[7]       = nextTweaks(tweakx8[5]);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(*tweakx8, src_text_1);
        __m512i tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), src_text_2);
        __m512i tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), src_text_3);
        __m512i tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), src_text_4);

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(*(tweakx8), tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), tweaked_src_text_2);
        tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), tweaked_src_text_3);
        tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), tweaked_src_text_4);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512, tweaked_src_text_1);
        _mm512_storeu_si512(p_dest512 + 1, tweaked_src_text_2);
        _mm512_storeu_si512(p_dest512 + 2, tweaked_src_text_3);
        _mm512_storeu_si512(p_dest512 + 3, tweaked_src_text_4);

        // 2^8 multiplied to all previous tweaks
        tweakx8[0] = nextTweaks(tweakx8[6]);
        tweakx8[1] = nextTweaks(tweakx8[7]);
        tweakx8[2] = nextTweaks(tweakx8[0]);
        tweakx8[3] = nextTweaks(tweakx8[1]);

        __m512i tweaked_src_text_5 =
            _mm512_xor_si512(*(tweakx8 + 4), src_text_5);
        __m512i tweaked_src_text_6 =
            _mm512_xor_si512(*(tweakx8 + 5), src_text_6);
        __m512i tweaked_src_text_7 =
            _mm512_xor_si512(*(tweakx8 + 6), src_text_7);
        __m512i tweaked_src_text_8 =
            _mm512_xor_si512(*(tweakx8 + 7), src_text_8);

        AesDecrypt(&tweaked_src_text_5,
                   &tweaked_src_text_6,
                   &tweaked_src_text_7,
                   &tweaked_src_text_8,
                   p_key128,
                   nRounds);

        // getting Cipher Text after xor of message and Alpha ^ j
        tweaked_src_text_5 =
            _mm512_xor_si512(*(tweakx8 + 4), tweaked_src_text_5);
        tweaked_src_text_6 =
            _mm512_xor_si512(*(tweakx8 + 5), tweaked_src_text_6);
        tweaked_src_text_7 =
            _mm512_xor_si512(*(tweakx8 + 6), tweaked_src_text_7);
        tweaked_src_text_8 =
            _mm512_xor_si512(*(tweakx8 + 7), tweaked_src_text_8);

        // storing the results in destination
        _mm512_storeu_si512(p_dest512 + 4, tweaked_src_text_5);
        _mm512_storeu_si512(p_dest512 + 5, tweaked_src_text_6);
        _mm512_storeu_si512(p_dest512 + 6, tweaked_src_text_7);
        _mm512_storeu_si512(p_dest512 + 7, tweaked_src_text_8);

        // 2^8 multiplied to all previous tweaks
        tweakx8[4] = nextTweaks(tweakx8[2]);
        tweakx8[5] = nextTweaks(tweakx8[3]);
        tweakx8[6] = nextTweaks(tweakx8[4]);
        tweakx8[7] = nextTweaks(tweakx8[5]);

        p_dest512 += 8;
        p_src512 += 8;
        blocks -= chunk;
    }

    chunk = 4 * 4;

    int tweak_to_be_used = 0;

    // Encrypting 4*2 source text blocks at a time
    if (blocks >= chunk) {

        __m512i src_text_1 = _mm512_loadu_si512(p_src512);
        __m512i src_text_2 = _mm512_loadu_si512(p_src512 + 1);
        __m512i src_text_3 = _mm512_loadu_si512(p_src512 + 2);
        __m512i src_text_4 = _mm512_loadu_si512(p_src512 + 3);

        // getting Tweaked Text after xor of message and Alpha ^ j
        __m512i tweaked_src_text_1 = _mm512_xor_si512(*(tweakx8), src_text_1);
        __m512i tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), src_text_2);
        __m512i tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), src_text_3);
        __m512i tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), src_text_4);

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   &tweaked_src_text_4,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(*(tweakx8), tweaked_src_text_1);
        tweaked_src_text_2 =
            _mm512_xor_si512(*(tweakx8 + 1), tweaked_src_text_2);
        tweaked_src_text_3 =
            _mm512_xor_si512(*(tweakx8 + 2), tweaked_src_text_3);
        tweaked_src_text_4 =
            _mm512_xor_si512(*(tweakx8 + 3), tweaked_src_text_4);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);
        __m512i tweaked_src_text_2 = _mm512_xor_si512(tweak_2, src_text_2);
        __m512i tweaked_src_text_3 = _mm512_xor_si512(tweak_3, src_text_3);

        AesDecrypt(&tweaked_src_text_1,
                   &tweaked_src_text_2,
                   &tweaked_src_text_3,
                   p_key128,
                   nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);
        tweaked_src_text_2 = _mm512_xor_si512(tweak_2, tweaked_src_text_2);
        tweaked_src_text_3 = _mm512_xor_si512(tweak_3, tweaked_src_text_3);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);
        __m512i tweaked_src_text_2 = _mm512_xor_si512(tweak_2, src_text_2);

        AesDecrypt(&tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);
        tweaked_src_text_2 = _mm512_xor_si512(tweak_2, tweaked_src_text_2);

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
        __m512i tweaked_src_text_1 = _mm512_xor_si512(tweak_1, src_text_1);

        AesDecrypt(&tweaked_src_text_1, p_key128, nRounds);

        // getting Chiper Text after xor of message and Alpha ^ j
        tweaked_src_text_1 = _mm512_xor_si512(tweak_1, tweaked_src_text_1);

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
    } else {
        __m512i secondlastTweak, last_src_text;
        if (tweak_to_be_used > 0) {
            secondlastTweak =
                _mm512_loadu_si512(tweakx8 + tweak_to_be_used - 1);
        } else {
            secondlastTweak = _mm512_setr_epi64(0LL,
                                                0LL,
                                                0LL,
                                                0LL,
                                                0LL,
                                                0LL,
                                                ((long long*)&temp_iv)[0],
                                                ((long long*)&temp_iv)[1]);
            for (uint64_t i = 1; i < (len / (128)); i++) {
                secondlastTweak = nextTweaks(secondlastTweak);
            }
        }
        __m512i src_text_1 = _mm512_setr_epi64(((long long*)p_src512 - 2)[0],
                                               ((long long*)p_src512 - 2)[1],
                                               0LL,
                                               0LL,
                                               0LL,
                                               0LL,
                                               0LL,
                                               0LL);
        src_text_1         = _mm512_xor_epi64(lastTweak, src_text_1);

        AesDecrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = _mm512_xor_epi64(lastTweak, src_text_1);
        memcpy((uint8_t*)p_dest512,
               (uint8_t*)&src_text_1,
               extra_bytes_in_message_block);
        memcpy((uint8_t*)&last_src_text,
               (uint8_t*)p_src512,
               extra_bytes_in_message_block);
        memcpy((uint8_t*)&last_src_text + extra_bytes_in_message_block,
               (uint8_t*)&src_text_1 + extra_bytes_in_message_block,
               16 - extra_bytes_in_message_block);
        src_text_1 = _mm512_setr_epi64(0LL,
                                       0LL,
                                       0LL,
                                       0LL,
                                       0LL,
                                       0LL,
                                       ((long long*)&last_src_text)[0],
                                       ((long long*)&last_src_text)[1]);
        src_text_1 = _mm512_xor_epi64(secondlastTweak, src_text_1);

        AesDecrypt(&src_text_1, p_key128, nRounds);

        src_text_1 = _mm512_xor_epi64(secondlastTweak, src_text_1);

        memcpy((uint8_t*)p_dest512 - 16, (uint8_t*)&src_text_1 + 48, 16);
        return ALC_ERROR_NONE;
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
