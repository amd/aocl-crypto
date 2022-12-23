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

#include "avx512.hh"
#include "avx512_gmul.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

#include "alcp/types.hh"
#include "cipher/aes.hh"
#include "cipher/aes_gcm.hh"
#include "cipher/aesni.hh"
#include "cipher/gmul.hh"

#include <cstdint>
#include <immintrin.h>

#define MAX_NUM_512_BLKS 24

namespace alcp::cipher::vaes512 {
// tbd: code currently duplicated, to be replaced with template code in
// aes_gcm.hh

void
gcmCryptInit(__m512i* c1,
             __m128i  iv_128,
             __m512i* one_lo,
             __m512i* one_x,
             __m512i* two_x,
             __m512i* three_x,
             __m512i* four_x,
             __m512i* eight_x,
             __m512i* swap_ctr)
{

    *one_lo = alcp_set_epi32(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
    *one_x  = alcp_set_epi32(4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0);
    *two_x  = alcp_set_epi32(8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0);
    *three_x =
        alcp_set_epi32(12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0);
    *four_x =
        alcp_set_epi32(16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0);
    *eight_x =
        alcp_set_epi32(32, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0);

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    *swap_ctr = _mm512_set_epi32(0x0c0d0e0f,
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100,
                                 0x0c0d0e0f, // Repeats here
                                 0x0b0a0908,
                                 0x07060504,
                                 0x03020100);
    // nonce counter
    *c1 = _mm512_broadcast_i64x2(iv_128);
    //*c1 = alcp_shuffle_epi8(*c1, *swap_ctr);

    __m512i onehi =
        _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3);
    *c1 = alcp_add_epi32(*c1, onehi);
}

static inline void
computeHashSubKeys(int num_512_blks, __m128i Hsubkey_128, __m512i* Hsubkey_512)
{
    __m128i*      pH_512_128[MAX_NUM_512_BLKS];
    const Uint64* H1_64 = (const Uint64*)&Hsubkey_128;
    pH_512_128[0]       = (__m128i*)&Hsubkey_512[0];

    Hsubkey_512[0] = _mm512_set_epi64(H1_64[1], // 3
                                      H1_64[0], // 3
                                      0,        // 2
                                      0,        // 2
                                      0,        // 1
                                      0,        // 1
                                      0,        // 0
                                      0);       // 0

    gMul(Hsubkey_128, Hsubkey_128, &pH_512_128[0][2]);
    gMul(pH_512_128[0][2], Hsubkey_128, &pH_512_128[0][1]);
    gMul(pH_512_128[0][1], Hsubkey_128, &pH_512_128[0][0]);

    for (int i = 1; i < num_512_blks; i++) {
        pH_512_128[i] = (__m128i*)&Hsubkey_512[i];
        // compute 4 hash to be used in a 4 block parallel Ghash
        // computation.
        gMul(pH_512_128[i - 1][0], Hsubkey_128, &pH_512_128[i][3]);
        gMul(pH_512_128[i][3], Hsubkey_128, &pH_512_128[i][2]);
        gMul(pH_512_128[i][2], Hsubkey_128, &pH_512_128[i][1]);
        gMul(pH_512_128[i][1], Hsubkey_128, &pH_512_128[i][0]);
    }
}

#define ONE_TIME_KEY_LOAD   1
#define PARALLEL_512_BLKS_4 4

Uint64
gcmBlk_512_dec(const __m512i* p_in_x,
               __m512i*       p_out_x,
               Uint64         blocks,
               const __m128i* pkey128,
               const Uint8*   pIv,
               int            nRounds,
               Uint8          factor,
               // gcm specific params
               __m128i* pgHash_128,
               __m128i  Hsubkey_128,
               __m128i  iv_128,
               __m128i  reverse_mask_128,
               int      remBytes)
{
    __m512i swap_ctr, c1;
    __m512i one_lo, one_x, two_x, three_x, four_x, eight_x;

    /* gcm init + Hash subkey init */
    gcmCryptInit(&c1,
                 iv_128,
                 &one_lo,
                 &one_x,
                 &two_x,
                 &three_x,
                 &four_x,
                 &eight_x,
                 &swap_ctr);

#if ONE_TIME_KEY_LOAD

    __m512i key_512_0, key_512_1, key_512_2, key_512_3, key_512_4, key_512_5,
        key_512_6, key_512_7, key_512_8, key_512_9, key_512_10, key_512_11,
        key_512_12, key_512_13, key_512_14;
    alcp_load_key_zmm(pkey128,
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
#endif
    __attribute__((aligned(64))) Uint64 Hsubkey_64[MAX_NUM_512_BLKS * 8];
    __m512i*                            Hsubkey_512 = (__m512i*)Hsubkey_64;

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int num_512_blks = 0;

    /* 64 (16*4) blocks per loop. Minimum 20 loops required to get
     * benefit of precomputing hash^x table.
     * 32 (16*2) blocks per loop needs minimum 4 loops to get benefit from
     * precomputing hash^x table.
     */

    // 16*num_unroll*MinloopCount
    Uint64 threshold_4x512_4unroll = 16 * 4 * 20;
    Uint64 threshold_4x512_2unroll = 16 * 2 * 4;
    bool   do_4_unroll             = false;
    bool   do_2_unroll             = false;

    if (blocks >= threshold_4x512_4unroll) {
        num_512_blks = 4 * 4;
        do_4_unroll  = true;
    } else if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 4 * 2;
        do_2_unroll  = true;
    } else if (blocks >= 16) {
        num_512_blks = 4;
    } else if (blocks >= 4) {
        num_512_blks = 1;
    }

    if (num_512_blks > MAX_NUM_512_BLKS) {
        num_512_blks = MAX_NUM_512_BLKS;
    }

    if (num_512_blks) {
        computeHashSubKeys(num_512_blks, Hsubkey_128, Hsubkey_512);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;
    Uint64 blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    if (do_4_unroll) {
        Uint64 blockCount_4x512_4_unroll = 16 * 4;

        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i  z0_512, z1_512, z2_512;
            __m512i  z0_512_t, z1_512_t, z2_512_t;
            int      n            = 12;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128);
        }

    } else if (do_2_unroll) {
        Uint64 blockCount_4x512_2_unroll = 16 * 2;

        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {
            __m512i z0_512, z1_512, z2_512;
            __m512i z0_512_t, z1_512_t, z2_512_t;

            int      n            = 4; // numParallel_512blks * k;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            // first iteration gmul
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             b1, // outputs B = A xor B
                             b2,
                             b3,
                             b4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, b1, b2, b3, b4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128);
        }
    }

    Hsubkey_512_0 = Hsubkey_512[0];

    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {

        Hsubkey_512_1 = Hsubkey_512[1];
        Hsubkey_512_2 = Hsubkey_512[2];
        Hsubkey_512_3 = Hsubkey_512[3];

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              pgHash_128);

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_4x512(b1,
                                        b2,
                                        b3,
                                        b4,
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
#endif

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        c2 = alcp_add_epi32(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, pgHash_128);
        gMulR(Hsubkey_512_0, a2, reverse_mask_512, pgHash_128);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, &b2, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_2x512(b1,
                                        b2,
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
#endif

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        a1 = alcp_loadu(p_in_x);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, pgHash_128);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_1x512(b1,
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
#endif
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);
    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }
    }

    // clear all keys in registers.
    key_512_0  = _mm512_setzero_si512();
    key_512_1  = _mm512_setzero_si512();
    key_512_2  = _mm512_setzero_si512();
    key_512_3  = _mm512_setzero_si512();
    key_512_4  = _mm512_setzero_si512();
    key_512_5  = _mm512_setzero_si512();
    key_512_6  = _mm512_setzero_si512();
    key_512_7  = _mm512_setzero_si512();
    key_512_8  = _mm512_setzero_si512();
    key_512_9  = _mm512_setzero_si512();
    key_512_10 = _mm512_setzero_si512();
    key_512_11 = _mm512_setzero_si512();
    key_512_12 = _mm512_setzero_si512();
    key_512_13 = _mm512_setzero_si512();
    key_512_14 = _mm512_setzero_si512();

    return blocks;
}

Uint64
gcmBlk_512_enc(const __m512i* p_in_x,
               __m512i*       p_out_x,
               Uint64         blocks,
               const __m128i* pkey128,
               const Uint8*   pIv,
               int            nRounds,
               Uint8          factor,
               // gcm specific params
               __m128i* pgHash_128,
               __m128i  Hsubkey_128,
               __m128i  iv_128,
               __m128i  reverse_mask_128,
               int      remBytes)
{
    __m512i swap_ctr, c1;
    __m512i one_lo, one_x, two_x, three_x, four_x, eight_x;

    /* gcm init + Hash subkey init */
    gcmCryptInit(&c1,
                 iv_128,
                 &one_lo,
                 &one_x,
                 &two_x,
                 &three_x,
                 &four_x,
                 &eight_x,
                 &swap_ctr);

#if ONE_TIME_KEY_LOAD
    __m512i key_512_0, key_512_1, key_512_2, key_512_3, key_512_4, key_512_5,
        key_512_6, key_512_7, key_512_8, key_512_9, key_512_10, key_512_11,
        key_512_12, key_512_13, key_512_14;
    alcp_load_key_zmm(pkey128,
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
#endif
    __attribute__((aligned(64))) Uint64 Hsubkey_64[MAX_NUM_512_BLKS * 8];
    __m512i*                            Hsubkey_512 = (__m512i*)Hsubkey_64;

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int num_512_blks = 0;

    /* 64 (16*4) blocks per loop. Minimum 20 loops required to get
     * benefit of precomputing hash^x table.
     * 32 (16*2) blocks per loop needs minimum 4 loops to get benefit from
     * precomputing hash^x table.
     */

    // 16*num_unroll*MinloopCount
    Uint64 threshold_4x512_4unroll = 16 * 4 * 20;
    Uint64 threshold_4x512_2unroll = 16 * 2 * 4;
    bool   do_4_unroll             = false;
    bool   do_2_unroll             = false;

    if (blocks >= threshold_4x512_4unroll) {
        num_512_blks = 4 * 4;
        do_4_unroll  = true;
    } else if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 4 * 2;
        do_2_unroll  = true;
    } else if (blocks >= 16) {
        num_512_blks = 4;
    } else if (blocks >= 4) {
        num_512_blks = 1;
    }

    if (num_512_blks > MAX_NUM_512_BLKS) {
        num_512_blks = MAX_NUM_512_BLKS;
    }

    if (num_512_blks) {
        computeHashSubKeys(num_512_blks, Hsubkey_128, Hsubkey_512);
    }

    Uint64  blockCount_1x512 = factor;
    __m512i a1, b1;

    Uint64 blockCount_4x512 = 4 * factor;
    Uint64 blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    __m512i Hsubkey_512_0, Hsubkey_512_1, Hsubkey_512_2, Hsubkey_512_3;

    if (do_4_unroll) {
        Uint64 blockCount_4x512_4_unroll = 16 * 4;

        for (; blocks >= blockCount_4x512_4_unroll;
             blocks -= blockCount_4x512_4_unroll) {

            __m512i  z0_512, z1_512, z2_512;
            __m512i  z0_512_t, z1_512_t, z2_512_t;
            int      n            = 12;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, // inputs A
                             a2,
                             a3,
                             a4,
                             b1, // inputs B
                             b2,
                             b3,
                             b4,
                             a1, // outputs B = A xor B
                             a2,
                             a3,
                             a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd iteration
            n            = PARALLEL_512_BLKS_4 * 2;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);
#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 3rd
            n            = PARALLEL_512_BLKS_4 * 1;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 4th
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128);
        }

    } else if (do_2_unroll) {
        Uint64 blockCount_4x512_2_unroll = 16 * 2;

        for (; blocks >= blockCount_4x512_2_unroll;
             blocks -= blockCount_4x512_2_unroll) {

            __m512i z0_512, z1_512, z2_512;
            __m512i z0_512_t, z1_512_t, z2_512_t;

            int      n            = 4; // numParallel_512blks * k;
            __m512i* pHsubkey_512 = Hsubkey_512 + n;

            alcp_loadu_4values(pHsubkey_512, // address
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1,
                             a2,
                             a3,
                             a4, // inputs A
                             b1,
                             b2,
                             b3,
                             b4, // inputs B
                             a1,
                             a2,
                             a3,
                             a4); // outputs A = A xor B
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // 2nd
            n            = 0;
            pHsubkey_512 = Hsubkey_512 + n;

            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            // re-arrange as per spec
            alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
            vaes512::AesEncryptNoLoad_4x512(b1,
                                            b2,
                                            b3,
                                            b4,
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
#endif
            // first iteration gmul
            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
            alcp_loadu_4values(pHsubkey_512,
                               Hsubkey_512_0,
                               Hsubkey_512_1,
                               Hsubkey_512_2,
                               Hsubkey_512_3);

            alcp_loadu_4values(p_in_x, a1, a2, a3, a4);
            alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);
            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            get_aggregated_karatsuba_components(Hsubkey_512_0,
                                                Hsubkey_512_1,
                                                Hsubkey_512_2,
                                                Hsubkey_512_3,
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                reverse_mask_512,
                                                &z0_512_t,
                                                &z1_512_t,
                                                &z2_512_t,
                                                *pgHash_128,
                                                0);
            z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
            z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
            z2_512 = _mm512_xor_si512(z2_512_t, z2_512);

            alcp_storeu_4values(p_out_x, a1, a2, a3, a4);
            p_in_x += PARALLEL_512_BLKS_4;
            p_out_x += PARALLEL_512_BLKS_4;

            // compute Ghash
            getGhash(z0_512, z1_512, z2_512, pgHash_128);
        }
    }

    Hsubkey_512_0 = Hsubkey_512[0];

    bool isFirst   = true;
    bool isLoopHit = false;
    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        Hsubkey_512_1 = Hsubkey_512[1];
        Hsubkey_512_2 = Hsubkey_512[2];
        Hsubkey_512_3 = Hsubkey_512[3];

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        if (!isFirst) {
            gMulR(Hsubkey_512_0,
                  Hsubkey_512_1,
                  Hsubkey_512_2,
                  Hsubkey_512_3,
                  a1,
                  a2,
                  a3,
                  a4,
                  reverse_mask_512,
                  pgHash_128);
        }
        isFirst   = false;
        isLoopHit = true;

        alcp_loadu_4values(p_in_x, a1, a2, a3, a4);

        // re-arrange as per spec
        alcp_shuffle_epi8(c1, c2, c3, c4, swap_ctr, b1, b2, b3, b4);

#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_4x512(b1,
                                        b2,
                                        b3,
                                        b4,
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
#endif

        alcp_xor_4values(a1, a2, a3, a4, b1, b2, b3, b4, a1, a2, a3, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);
        alcp_storeu_4values(p_out_x, a1, a2, a3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    if (isLoopHit) {
        gMulR(Hsubkey_512_0,
              Hsubkey_512_1,
              Hsubkey_512_2,
              Hsubkey_512_3,
              a1,
              a2,
              a3,
              a4,
              reverse_mask_512,
              pgHash_128);
    }

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        c2 = alcp_add_epi32(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, &b2, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_2x512(b1,
                                        b2,
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
#endif

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, pgHash_128);
        gMulR(Hsubkey_512_0, a2, reverse_mask_512, pgHash_128);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        a1 = alcp_loadu(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
#if (!ONE_TIME_KEY_LOAD)
        AesEncrypt(&b1, pkey128, nRounds);
#else
        vaes512::AesEncryptNoLoad_1x512(b1,
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
#endif
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        gMulR(Hsubkey_512_0, a1, reverse_mask_512, pgHash_128);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    __m128i c1_128     = _mm512_castsi512_si128(c1);
    __m128i one_lo_128 = _mm_set_epi32(1, 0, 0, 0);
    for (; blocks != 0; blocks--) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        a1 = _mm_loadu_si128((__m128i*)p_in_x);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);

        _mm_storeu_si128((__m128i*)p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // remaining bytes
    if (remBytes) {
        __m128i a1; // remaining bytes handled with 128bit
        __m128i swap_ctr_128 = _mm512_castsi512_si128(swap_ctr);

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);

        const Uint8* p_in  = reinterpret_cast<const Uint8*>(p_in_x);
        Uint8*       p_out = reinterpret_cast<Uint8*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        Uint8* p_store = reinterpret_cast<Uint8*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }

        __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
        *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
        gMul(*pgHash_128, Hsubkey_128, pgHash_128);
    }

    // clear all keys in registers.
    key_512_0  = _mm512_setzero_si512();
    key_512_1  = _mm512_setzero_si512();
    key_512_2  = _mm512_setzero_si512();
    key_512_3  = _mm512_setzero_si512();
    key_512_4  = _mm512_setzero_si512();
    key_512_5  = _mm512_setzero_si512();
    key_512_6  = _mm512_setzero_si512();
    key_512_7  = _mm512_setzero_si512();
    key_512_8  = _mm512_setzero_si512();
    key_512_9  = _mm512_setzero_si512();
    key_512_10 = _mm512_setzero_si512();
    key_512_11 = _mm512_setzero_si512();
    key_512_12 = _mm512_setzero_si512();
    key_512_13 = _mm512_setzero_si512();
    key_512_14 = _mm512_setzero_si512();

    return blocks;
}

alc_error_t
CryptGcm(const Uint8* pInputText,  // ptr to inputText
         Uint8*       pOutputText, // ptr to outputtext
         Uint64       len,         // message length in bytes
         const Uint8* pKey,        // ptr to Key
         int          nRounds,     // No. of rounds
         const Uint8* pIv,         // ptr to Initialization Vector
         __m128i*     pgHash_128,
         __m128i      Hsubkey_128,
         __m128i      iv_128,
         __m128i      reverse_mask_128,
         bool         isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64 blocks   = len / Rijndael::cBlockSize;
    int    remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    if (isEncrypt) {
        gcmBlk_512_enc(p_in_512,
                       p_out_512,
                       blocks,
                       pkey128,
                       pIv,
                       nRounds,
                       4, // factor*128
                       // gcm specific params
                       pgHash_128,
                       Hsubkey_128,
                       iv_128,
                       reverse_mask_128,
                       remBytes);
    } else {
        gcmBlk_512_dec(p_in_512,
                       p_out_512,
                       blocks,
                       pkey128,
                       pIv,
                       nRounds,
                       4, // factor*128
                       // gcm specific params
                       pgHash_128,
                       Hsubkey_128,
                       iv_128,
                       reverse_mask_128,
                       remBytes);
    }

    return err;
}

} // namespace alcp::cipher::vaes512
