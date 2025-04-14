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
#include "alcp/digest/sha2.hh"
#include "config.h"
#include <x86intrin.h>

#include "alcp/utils/copy.hh"
namespace utils = alcp::utils;

/* Number of vectors needed to accomodate an input chunk */
#define SHA256_CHUNK_NUM_XMM Sha256::cChunkSize / sizeof(__m128i)
#define SHA256_MSG_SCHEDULE_NUM_XMM                                            \
    (Sha256::cNumRounds * sizeof(Uint32)) / sizeof(__m128i)

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

    inline static void load_data(__m128i      chunk[SHA256_CHUNK_NUM_XMM],
                                 const Uint8* data)
    {
        const __m128i c_shuf_mask =
            _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
        const __m128i* p_data_128 = reinterpret_cast<const __m128i*>(data);

        UNROLL_4
        for (Uint64 i = 0; i < SHA256_CHUNK_NUM_XMM; i++) {
            chunk[i] = _mm_lddqu_si128(p_data_128 + i);
            chunk[i] = _mm_shuffle_epi8(chunk[i], c_shuf_mask);
        }
    }

    inline static void load_state(Uint32*  pHash,
                                  __m128i& state0,
                                  __m128i& state1)
    {
        /* Load initial values */
        const __m128i* p_hash_128 = reinterpret_cast<const __m128i*>(pHash);
        __m128i        tmp        = _mm_load_si128(p_hash_128);
        state1                    = _mm_load_si128(p_hash_128 + 1);

        tmp    = _mm_shuffle_epi32(tmp, 0xB1);
        state1 = _mm_shuffle_epi32(state1, 0x1B);
        state0 = _mm_alignr_epi8(tmp, state1, 8);
        state1 = _mm_blend_epi16(state1, tmp, 0xF0);
    }

    inline static void __attribute__((always_inline)) compute_rounds(
        __m128i&      state0,
        __m128i&      state1,
        __m128i*      msg_schedule,
        const Uint32* pRoundConstants)
    {
        __m128i        msg, tmp;
        __m128i        prev_state_abef, prev_state_cdgh;
        const __m128i* p_k_128 =
            reinterpret_cast<const __m128i*>(pRoundConstants);

        /* Save current state */
        prev_state_abef = state0;
        prev_state_cdgh = state1;

        /* Calculate 64 rounds */
        msg    = _mm_add_epi32(msg_schedule[0], _mm_load_si128(p_k_128));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg    = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        UNROLL_2
        for (Uint64 i = 1; i < 3; i++) {
            msg = _mm_add_epi32(msg_schedule[i], _mm_load_si128(p_k_128 + i));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg_schedule[i + 3] =
                _mm_sha256msg1_epu32(msg_schedule[i - 1], msg_schedule[i]);
            msg    = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        }

        UNROLL_10
        for (Uint64 i = 3; i < 13; i++) {
            msg = _mm_add_epi32(msg_schedule[i], _mm_load_si128(p_k_128 + i));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp    = _mm_alignr_epi8(msg_schedule[i], msg_schedule[i - 1], 4);
            msg_schedule[i + 1] = _mm_add_epi32(msg_schedule[i + 1], tmp);
            msg_schedule[i + 1] =
                _mm_sha256msg2_epu32(msg_schedule[i + 1], msg_schedule[i]);
            msg_schedule[i + 3] =
                _mm_sha256msg1_epu32(msg_schedule[i - 1], msg_schedule[i]);
            msg    = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        }

        UNROLL_2
        for (Uint64 i = 13; i < 15; i++) {
            msg = _mm_add_epi32(msg_schedule[i], _mm_load_si128(p_k_128 + i));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            tmp    = _mm_alignr_epi8(msg_schedule[i], msg_schedule[i - 1], 4);
            msg_schedule[i + 1] = _mm_add_epi32(msg_schedule[i + 1], tmp);
            msg_schedule[i + 1] =
                _mm_sha256msg2_epu32(msg_schedule[i + 1], msg_schedule[i]);
            msg    = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        }

        msg = _mm_add_epi32(
            msg_schedule[SHA256_MSG_SCHEDULE_NUM_XMM - 1],
            _mm_load_si128(p_k_128 + SHA256_MSG_SCHEDULE_NUM_XMM - 1));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg    = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        /* Accumulate the current state to the prev hash state */
        state0 = _mm_add_epi32(state0, prev_state_abef);
        state1 = _mm_add_epi32(state1, prev_state_cdgh);
    }

    alc_error_t ShaUpdate256(Uint32*       pHash,
                             const Uint8*  pSrc,
                             Uint64        src_len,
                             const Uint32* pRoundConstants)
    {
        __m128i msg_schedule[SHA256_MSG_SCHEDULE_NUM_XMM];
        __m128i state0, state1;

        load_state(pHash, state0, state1);
        while (src_len >= Sha256::cChunkSize) {
            load_data(msg_schedule, pSrc);
            compute_rounds(state0, state1, msg_schedule, pRoundConstants);
            pSrc += Sha256::cChunkSize;
            src_len -= Sha256::cChunkSize;
        }

        /* Rearrange the state variables from ABEF and CDGH to ABCD and EFGH */
        __m128i tmp = _mm_shuffle_epi32(state0, 0x1B);
        state1      = _mm_shuffle_epi32(state1, 0xB1);
        state0      = _mm_blend_epi16(tmp, state1, 0xF0);
        state1      = _mm_alignr_epi8(state1, tmp, 8);

        // Save state
        _mm_store_si128((__m128i*)&pHash[0], state0);
        _mm_store_si128((__m128i*)&pHash[4], state1);

        return ALC_ERROR_NONE;
    }

    alc_error_t ShaFinalize256(Uint8*        pSrc,
                               Uint8*        pDest,
                               Uint32*       pHash,
                               const Uint32* pRoundConstants,
                               const Uint32  c_byte_offset,
                               const Uint64  c_msg_len,
                               const Uint64  c_digest_len)
    {
        const __m128i c_shuf_mask =
            _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

        __m128i state0, state1;
        __m128i msg_schedule[SHA256_MSG_SCHEDULE_NUM_XMM]{};
        Uint32  vectors_to_load = c_byte_offset / 16;

        load_state(pHash, state0, state1);

        /* Setting zeros to residue bytes in the last __m128i vector that
         * contains data. The formula `16 - c_byte_offset % 16` calculates the
         * number of unused bytes in the 16-byte vector. */
        utils::PadBlock<Uint8>(&pSrc[c_byte_offset + 1],
                               0x0,
                               sizeof(__m128i)
                                   - (c_byte_offset & (sizeof(__m128i) - 1)));
        pSrc[c_byte_offset] = 0x80;

        const __m128i* p_src_128 = reinterpret_cast<const __m128i*>(pSrc);
        switch (vectors_to_load) {
            case 3:
                msg_schedule[3] = _mm_lddqu_si128(p_src_128 + 3);
                msg_schedule[3] =
                    _mm_shuffle_epi8(msg_schedule[3], c_shuf_mask);
                [[fallthrough]];

            case 2:
                msg_schedule[2] = _mm_lddqu_si128(p_src_128 + 2);
                msg_schedule[2] =
                    _mm_shuffle_epi8(msg_schedule[2], c_shuf_mask);
                [[fallthrough]];

            case 1:
                msg_schedule[1] = _mm_lddqu_si128(p_src_128 + 1);
                msg_schedule[1] =
                    _mm_shuffle_epi8(msg_schedule[1], c_shuf_mask);
                [[fallthrough]];

            case 0:
                if (c_byte_offset) {
                    msg_schedule[0] = _mm_lddqu_si128(p_src_128);
                    msg_schedule[0] =
                        _mm_shuffle_epi8(msg_schedule[0], c_shuf_mask);
                } else {
                    msg_schedule[0] = _mm_setr_epi32(0x80000000, 0x0, 0x0, 0x0);
                }
        }

        /* Setting to zero is required even though msg_schedule is
         * zero-initialized. This is because setzero calls XOR and is faster
         * than zero-initialization. */
        switch (vectors_to_load) {
            case 0:
                msg_schedule[1] = _mm_setzero_si128();
                [[fallthrough]];

            case 1:
                msg_schedule[2] = _mm_setzero_si128();
                [[fallthrough]];

            case 2:
                msg_schedule[3] = _mm_setzero_si128();
        }

        if (c_byte_offset >= Sha256::cChunkSize - sizeof(Uint64)) {
            /* Current chunk doesn't have space for padding, then calculate
             * current round & make new chunk for padding */
            compute_rounds(state0, state1, msg_schedule, pRoundConstants);
            UNROLL_4
            for (Uint64 i = 0; i < SHA256_CHUNK_NUM_XMM; i++) {
                msg_schedule[i] = _mm_setzero_si128();
            }
        }

        /* Adding padding */
#ifdef ALCP_CONFIG_LITTLE_ENDIAN
        /* For little-endian systems, the mask is adjusted to reverse the bytes
         * of message lenght in bits present in the padding
         */
        const __m128i c_mask =
            _mm_set_epi64x(0x0b0a09080f0e0d0cULL, 0x0405060700010203ULL);
#else
        /* For big-endian systems, the default shuffle mask is used */
        const __m128i c_mask = c_shuf_mask;
#endif
        const __m128i c_padding =
            _mm_shuffle_epi8(_mm_set_epi64x(c_msg_len * 8, 0), c_mask);
        msg_schedule[SHA256_CHUNK_NUM_XMM - 1] =
            _mm_or_si128(msg_schedule[SHA256_CHUNK_NUM_XMM - 1], c_padding);

        compute_rounds(state0, state1, msg_schedule, pRoundConstants);

        /* Rearrange the state variables from ABEF and CDGH to ABCD and EFGH */
        __m128i tmp = _mm_shuffle_epi32(state0, 0x1B);
        state1      = _mm_shuffle_epi32(state1, 0xB1);
        state0      = _mm_blend_epi16(tmp, state1, 0xF0);
        state1      = _mm_alignr_epi8(state1, tmp, 8);

        state0 = _mm_shuffle_epi8(state0, c_shuf_mask);
        state1 = _mm_shuffle_epi8(state1, c_shuf_mask);

        /* Copy the final digest */
        memcpy(pDest, &state0, 16);
        memcpy(pDest + 16, &state1, c_digest_len - 16);

        return ALC_ERROR_NONE;
    }
}} // namespace alcp::digest::shani
