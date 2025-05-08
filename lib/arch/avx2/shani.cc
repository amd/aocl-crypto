/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest/shani.hh"
#include "config.h"
#include <x86intrin.h>

// number of vectors needed to accomodate an input chunk
#define SHA256_CHUNK_NUM_VECT 4

#ifdef COMPILER_IS_GCC
#define UNROLL_2  _Pragma("GCC unroll 2")
#define UNROLL_4  _Pragma("GCC unroll 4")
#define UNROLL_10 _Pragma("GCC unroll 10")
#else
#define UNROLL_2
#define UNROLL_4
#define UNROLL_10
#endif
namespace alcp::digest { namespace shani {

    inline static void load_data(__m128i      x[SHA256_CHUNK_NUM_VECT],
                                 const Uint8* data)
    {
        const __m128i shuf_mask =
            _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

        UNROLL_4 for (size_t i = 0; i < SHA256_CHUNK_NUM_VECT; i++)
        {
            x[i] =
                _mm_lddqu_si128((const __m128i*)(&data[sizeof(__m128i) * i]));
            x[i] = _mm_shuffle_epi8(x[i], shuf_mask);
        }
    }

    inline static void load_state(Uint32*  pHash,
                                  __m128i* pState0,
                                  __m128i* pState1)
    {
        /* Load initial values */
        __m128i tmp = _mm_load_si128((const __m128i*)&pHash[0]);
        *pState1    = _mm_load_si128((const __m128i*)&pHash[4]);

        tmp      = _mm_shuffle_epi32(tmp, 0xB1);
        *pState1 = _mm_shuffle_epi32(*pState1, 0x1B);
        *pState0 = _mm_alignr_epi8(tmp, *pState1, 8);
        *pState1 = _mm_blend_epi16(*pState1, tmp, 0xF0);
    }

    alc_error_t ShaUpdate256(Uint32* pHash, const Uint8* pSrc, Uint64 src_len)
    {
        alignas(64) static const __m128i c_K[16] = {
            _mm_setr_epi32(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5),
            _mm_setr_epi32(0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5),
            _mm_setr_epi32(0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3),
            _mm_setr_epi32(0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174),
            _mm_setr_epi32(0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc),
            _mm_setr_epi32(0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da),
            _mm_setr_epi32(0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7),
            _mm_setr_epi32(0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967),
            _mm_setr_epi32(0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13),
            _mm_setr_epi32(0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85),
            _mm_setr_epi32(0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3),
            _mm_setr_epi32(0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070),
            _mm_setr_epi32(0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5),
            _mm_setr_epi32(0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3),
            _mm_setr_epi32(0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208),
            _mm_setr_epi32(0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2),
        };
        __m128i chunk_vect[SHA256_CHUNK_NUM_VECT
                           * 4]; // Array of vectors big enough to accomdate the
                                 // extended msg(64 words)
        __m128i state0, state1;
        __m128i msg, tmp;
        __m128i prev_state_abef, prev_state_cdgh;

        load_state(pHash, &state0, &state1);

        while (src_len >= 64) {
            load_data(chunk_vect, pSrc);
            /* Save current state */
            prev_state_abef = state0;
            prev_state_cdgh = state1;

            // Calculate 64 rounds
            msg    = _mm_add_epi32(chunk_vect[0], c_K[0]);
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg    = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            UNROLL_2 for (size_t i = 1; i < 3; i++)
            {
                msg    = _mm_add_epi32(chunk_vect[i], c_K[i]);
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                chunk_vect[i + 3] =
                    _mm_sha256msg1_epu32(chunk_vect[i - 1], chunk_vect[i]);
                msg    = _mm_shuffle_epi32(msg, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            }

            UNROLL_10 for (size_t i = 3; i < 13; i++)
            {
                msg    = _mm_add_epi32(chunk_vect[i], c_K[i]);
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                tmp    = _mm_alignr_epi8(chunk_vect[i], chunk_vect[i - 1], 4);
                chunk_vect[i + 1] = _mm_add_epi32(chunk_vect[i + 1], tmp);
                chunk_vect[i + 1] =
                    _mm_sha256msg2_epu32(chunk_vect[i + 1], chunk_vect[i]);
                chunk_vect[i + 3] =
                    _mm_sha256msg1_epu32(chunk_vect[i - 1], chunk_vect[i]);
                msg    = _mm_shuffle_epi32(msg, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            }

            UNROLL_2 for (size_t i = 13; i < 15; i++)
            {
                msg    = _mm_add_epi32(chunk_vect[i], c_K[i]);
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                tmp    = _mm_alignr_epi8(chunk_vect[i], chunk_vect[i - 1], 4);
                chunk_vect[i + 1] = _mm_add_epi32(chunk_vect[i + 1], tmp);
                chunk_vect[i + 1] =
                    _mm_sha256msg2_epu32(chunk_vect[i + 1], chunk_vect[i]);
                msg    = _mm_shuffle_epi32(msg, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            }

            msg    = _mm_add_epi32(chunk_vect[15], c_K[15]);
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg    = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

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
        _mm_store_si128((__m128i*)&pHash[0], state0);
        _mm_store_si128((__m128i*)&pHash[4], state1);
        return ALC_ERROR_NONE;
    }

}} // namespace alcp::digest::shani
