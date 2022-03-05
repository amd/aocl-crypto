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

#include "digest/shani.hh"
#include "error.hh"
#include <x86intrin.h>
#define SHA256_CHUNK_NUM_VECT                                                  \
    4 // number of vectors needed to accomodate an input chunk
namespace alcp::digest { namespace shani {

    inline static void load_data(__m128i        x[SHA256_CHUNK_NUM_VECT],
                                 const uint8_t* data)
    {
        const __m128i shuf_mask =
            _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

        _Pragma("GCC unroll 4") for (size_t i = 0; i < SHA256_CHUNK_NUM_VECT;
                                     i++)
        {
            x[i] =
                _mm_loadu_si128((const __m128i*)(&data[sizeof(__m128i) * i]));
            x[i] = _mm_shuffle_epi8(x[i], shuf_mask);
        }
    }

    inline static void load_state(uint32_t* pHash,
                                  __m128i*  pState0,
                                  __m128i*  pState1)
    {
        /* Load initial values */
        __m128i tmp = _mm_loadu_si128((const __m128i*)&pHash[0]);
        *pState1    = _mm_loadu_si128((const __m128i*)&pHash[4]);

        tmp      = _mm_shuffle_epi32(tmp, 0xB1);
        *pState1 = _mm_shuffle_epi32(*pState1, 0x1B);
        *pState0 = _mm_alignr_epi8(tmp, *pState1, 8);
        *pState1 = _mm_blend_epi16(*pState1, tmp, 0xF0);
    }

    alc_error_t ShaUpdate256(uint32_t*       pHash,
                             const uint8_t*  pSrc,
                             uint64_t        src_len,
                             const uint32_t* pHashConstants)
    {
        __m128i chunk_vect[SHA256_CHUNK_NUM_VECT
                           * 4]; // Array of vectors big enough to accomdate the
                                 // extended msg(64 words)
        __m128i state0, state1;
        __m128i msg, msg0, tmp;
        __m128i prev_state_abef, prev_state_cdgh;

        load_state(pHash, &state0, &state1);

        while (src_len >= 64) {
            load_data(chunk_vect, pSrc);
            /* Save current state */
            prev_state_abef = state0;
            prev_state_cdgh = state1;
            // Calculate the rounds for the first 16 words
            _Pragma("GCC unroll 4") for (uint32_t i = 0; i < 4; i++)
            {
                msg    = _mm_add_epi32(chunk_vect[i],
                                    _mm_set_epi32(pHashConstants[4 * i + 3],
                                                  pHashConstants[4 * i + 2],
                                                  pHashConstants[4 * i + 1],
                                                  pHashConstants[4 * i]));
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                msg    = _mm_shuffle_epi32(msg, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            }
            // Extend the message to 64 words and calcute the rounds on the
            // extended message.
            _Pragma("GCC unroll 12") for (uint32_t i = 4; i < 16; i++)
            {
                msg0 =
                    _mm_sha256msg1_epu32(chunk_vect[i - 4], chunk_vect[i - 3]);
                tmp  = _mm_alignr_epi8(chunk_vect[i - 1], chunk_vect[i - 2], 4);
                msg0 = _mm_add_epi32(msg0, tmp);
                msg0 = _mm_sha256msg2_epu32(msg0, chunk_vect[i - 1]);
                chunk_vect[i] = msg0;
                msg           = _mm_add_epi32(msg0,
                                    _mm_set_epi32(pHashConstants[4 * i + 3],
                                                  pHashConstants[4 * i + 2],
                                                  pHashConstants[4 * i + 1],
                                                  pHashConstants[4 * i]));
                state1        = _mm_sha256rnds2_epu32(state1, state0, msg);
                msg           = _mm_shuffle_epi32(msg, 0x0E);
                state0        = _mm_sha256rnds2_epu32(state0, state1, msg);
            }
            // Accumulate the current state to the prev chunk's state
            state0 = _mm_add_epi32(state0, prev_state_abef);
            state1 = _mm_add_epi32(state1, prev_state_cdgh);

            pSrc += 64;
            src_len -= 64;
        }

        // Rearrange the state variables from ABEF and CDGH
        // to ABCD and EFGH
        tmp    = _mm_shuffle_epi32(state0, 0x1B);
        state1 = _mm_shuffle_epi32(state1, 0xB1);
        state0 = _mm_blend_epi16(tmp, state1, 0xF0);
        state1 = _mm_alignr_epi8(state1, tmp, 8);

        // Save state
        _mm_storeu_si128((__m128i*)&pHash[0], state0);
        _mm_storeu_si128((__m128i*)&pHash[4], state1);
        return ALC_ERROR_NONE;
    }

}} // namespace alcp::digest::shani
