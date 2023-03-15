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

#include "digest.hh"
#include "digest/sha2_512.hh"

#include <string.h>
#include <x86intrin.h>

#define SHA512_WORDS_IN_128_BIT_VEC                                            \
    2 // Number of sha512 words that can be accomodated in 128 bit vector
#define SHA512_WORDS_IN_256_BIT_VEC                                            \
    4 // Number of sha512 words that can be accomodated in 256 bit vector
#define SHA512_CHUNK_NUM_VECT_AVX                                              \
    8 // Number of avx registers needed to accomodate a sha512 block
#define SHA512_CHUNK_NUM_VECT_AVX2                                             \
    4 // Number of avx2 registers needed to accomodate a sha512 block

#ifdef COMPILER_IS_GCC
#define UNROLL_8  _Pragma("GCC unroll 8")
#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_80 _Pragma("GCC unroll 80")
#else
#define UNROLL_8
#define UNROLL_16
#define UNROLL_80
#endif

namespace alcp::digest { namespace avx2 {

    static inline void rotate_x(__m128i x[8])
    {
        const __m128i tmp = x[0];
        x[0]              = x[1];
        x[1]              = x[2];
        x[2]              = x[3];
        x[3]              = x[4];
        x[4]              = x[5];
        x[5]              = x[6];
        x[6]              = x[7];

        x[7] = tmp;
    }

    static inline void process_buffer_avx(Uint64       state[8],
                                          const Uint8* data,
                                          Uint32       length)
    {

        __attribute__((aligned(64))) Uint64 message_sch[Sha512::cNumRounds];
        __m128i                             msg_vect[SHA512_CHUNK_NUM_VECT_AVX];

        Uint64 a, b, c, d, e, f, g, h, t;
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        // load_data
        static const __m128i shuf_mask =
            _mm_setr_epi32(0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b);

        UNROLL_8
        for (Uint32 j = 0; j < SHA512_CHUNK_NUM_VECT_AVX; j++) {
            const Uint32 pos = 2 * j;
            msg_vect[j] =
                _mm_loadu_si128((const __m128i*)(&data[sizeof(__m128i) * j]));
            msg_vect[j] = _mm_shuffle_epi8(msg_vect[j], shuf_mask);
            __m128i tmp = _mm_add_epi64(
                msg_vect[j],
                _mm_loadu_si128((const __m128i*)(&cRoundConstants[pos])));
            _mm_store_si128((__m128i*)(&message_sch[pos]), tmp);
        }

        // execute rounds 0 to 63
        Uint32 k512_idx = 16;
        for (Uint32 j = 0; j < 4; j++) {
            UNROLL_8
            for (Uint32 k = 0; k < SHA512_CHUNK_NUM_VECT_AVX; k++) {
                const Uint32 pos = 2 * k;

                __m128i temp[4];
                temp[0] = _mm_alignr_epi8(msg_vect[1], msg_vect[0], 8);

                temp[1] = _mm_srli_epi64(temp[0], 1);
                temp[2] = _mm_slli_epi64(temp[0], 64 - 1);
                temp[1] |= temp[2];

                temp[2] = _mm_srli_epi64(temp[0], 8);
                temp[3] = _mm_slli_epi64(temp[0], 64 - 8);
                temp[2] |= temp[3];

                temp[3] = _mm_srli_epi64(temp[0], 7);

                temp[0] = temp[1] ^ temp[2] ^ temp[3];

                temp[3] = _mm_alignr_epi8(msg_vect[5], msg_vect[4], 8);
                temp[3] = _mm_add_epi64(msg_vect[0], temp[3]);

                temp[0] = _mm_add_epi64(temp[0], temp[3]);

                // Calculation of s1
                temp[1] = _mm_srli_epi64(msg_vect[7], 19);
                temp[2] = _mm_slli_epi64(msg_vect[7], 64 - 19);
                temp[1] |= temp[2];

                temp[2] = _mm_srli_epi64(msg_vect[7], 61);
                temp[3] = _mm_slli_epi64(msg_vect[7], 64 - 61);
                temp[2] |= temp[3];

                temp[3] = _mm_srli_epi64(msg_vect[7], 6);
                temp[3] = temp[1] ^ temp[2] ^ temp[3];

                msg_vect[0] = _mm_add_epi64(temp[0], temp[3]);
                rotate_x(msg_vect);
                const __m128i y = _mm_add_epi64(
                    msg_vect[7],
                    _mm_loadu_si128(
                        (const __m128i*)(&cRoundConstants[k512_idx])));

                ShaRound(a, b, c, d, e, f, g, h, message_sch[pos]);
                ShaRound(h, a, b, c, d, e, f, g, message_sch[pos + 1]);

                t = h;
                h = f;
                f = d;
                d = b;
                b = t;
                t = g;
                g = e;
                e = c;
                c = a;
                a = t;
                _mm_store_si128((__m128i*)&message_sch[pos], y);
                k512_idx += 2;
            }
        }
        // do 16 of them
        ShaRound(a, b, c, d, e, f, g, h, message_sch[0]);
        ShaRound(h, a, b, c, d, e, f, g, message_sch[1]);
        ShaRound(g, h, a, b, c, d, e, f, message_sch[2]);
        ShaRound(f, g, h, a, b, c, d, e, message_sch[3]);
        ShaRound(e, f, g, h, a, b, c, d, message_sch[4]);
        ShaRound(d, e, f, g, h, a, b, c, message_sch[5]);
        ShaRound(c, d, e, f, g, h, a, b, message_sch[6]);
        ShaRound(b, c, d, e, f, g, h, a, message_sch[7]);
        ShaRound(a, b, c, d, e, f, g, h, message_sch[8]);
        ShaRound(h, a, b, c, d, e, f, g, message_sch[9]);
        ShaRound(g, h, a, b, c, d, e, f, message_sch[10]);
        ShaRound(f, g, h, a, b, c, d, e, message_sch[11]);
        ShaRound(e, f, g, h, a, b, c, d, message_sch[12]);
        ShaRound(d, e, f, g, h, a, b, c, message_sch[13]);
        ShaRound(c, d, e, f, g, h, a, b, message_sch[14]);
        ShaRound(b, c, d, e, f, g, h, a, message_sch[15]);
        // accumulate the state
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    alc_error_t ShaUpdate512(Uint64* pHash, const Uint8* pSrc, Uint64 src_len)
    {
        Uint32 num_chunks = src_len / Sha512::cChunkSize;

        for (Uint32 i = 0; i < num_chunks; i++) {
            process_buffer_avx(pHash, pSrc, Sha512::cChunkSize);
            pSrc += Sha512::cChunkSize;
        }
        return ALC_ERROR_NONE;
    }
}} // namespace alcp::digest::avx2
