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
#include <cstdint>
#include <immintrin.h>

#include "cipher/aes.hh"
#include "cipher/aes_gcm.hh"
#include "cipher/aesni.hh"
#include "cipher/avx128.hh"
#include "cipher/avx128_gmul.hh"
#include "cipher/avx512_gmul.hh"
#include "cipher/vaes.hh"
#include "cipher/vaes_avx512.hh"

#include "error.hh"
#include "key.hh"
#include "types.hh"

namespace alcp::cipher::vaes {
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

#define MAX_NUM_512_BLKS       24 // 96 HashSubkeys
#define ENABLE_96_BLK_AGG_GMUL 0  // disable would use 64 block GMUL

uint64_t
gcmBlk_512(const __m512i* p_in_x,
           __m512i*       p_out_x,
           uint64_t       blocks,
           const __m128i* pkey128,
           const uint8_t* pIv,
           int            nRounds,
           uint8_t        factor,
           // gcm specific params
           __m128i* pgHash_128,
           __m128i  Hsubkey_128,
           __m128i  iv_128,
           __m128i  reverse_mask_128,
           bool     isEncrypt,
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

    __m512i  Hsubkey_512[MAX_NUM_512_BLKS];
    __m128i* pH_512_128[MAX_NUM_512_BLKS];

    // clang-format off
    __m512i reverse_mask_512 =
            _mm512_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    // clang-format on

    int num_512_blks = 0;

    /* 96 (24*4) blocks per loop. Minimum 20 loops required to get benefit of
     *     precomputing hash^x table.
     */

    // 16*num_unroll*MinloopCount
    uint64_t threshold_4x512_4unroll = 16 * 4 * 20;
    uint64_t threshold_4x512_2unroll = 16 * 2 * 4;

#if ENABLE_96_BLK_AGG_GMUL
    uint64_t threshold_6x512_4unroll = 24 * 4 * 20;
    if (blocks >= threshold_6x512_4unroll) {
        num_512_blks = 6 * 4;
    } else if (blocks >= threshold_4x512_4unroll) {
#else
    if (blocks >= threshold_4x512_4unroll) {
#endif
        num_512_blks = 4 * 4;
        // printf(" 4x4 ");
    } else if (blocks >= threshold_4x512_2unroll) {
        num_512_blks = 4 * 2;
        // printf(" 4x2 ");
    } else if (blocks >= 16) {
        num_512_blks = 4;
        // printf(" 4x1 ");
    } else if (blocks >= 4) {
        num_512_blks = 1;
        // printf(" 1x1 ");
    } else {
        // printf(" 0x0 ");
    }

    if (num_512_blks > MAX_NUM_512_BLKS) {
        num_512_blks = MAX_NUM_512_BLKS;
    }

    if (num_512_blks) {
        const uint64_t* H1_64 = (const uint64_t*)&Hsubkey_128;
        pH_512_128[0]         = (__m128i*)&Hsubkey_512[0];

        Hsubkey_512[0] = _mm512_set_epi64(H1_64[1], // 3
                                          H1_64[0], // 3
                                          0,        // 2
                                          0,        // 2
                                          0,        // 1
                                          0,        // 1
                                          0,        // 0
                                          0);       // 0

        alcp::cipher::aesni::gMul(Hsubkey_128, Hsubkey_128, &pH_512_128[0][2]);
        alcp::cipher::aesni::gMul(
            pH_512_128[0][2], Hsubkey_128, &pH_512_128[0][1]);
        alcp::cipher::aesni::gMul(
            pH_512_128[0][1], Hsubkey_128, &pH_512_128[0][0]);

        for (int i = 1; i < num_512_blks; i++) {
            pH_512_128[i] = (__m128i*)&Hsubkey_512[i];
            // compute 4 hash to be used in a 4 block parallel Ghash
            // computation.
            alcp::cipher::aesni::gMul(
                pH_512_128[i - 1][0], Hsubkey_128, &pH_512_128[i][3]);
            alcp::cipher::aesni::gMul(
                pH_512_128[i][3], Hsubkey_128, &pH_512_128[i][2]);
            alcp::cipher::aesni::gMul(
                pH_512_128[i][2], Hsubkey_128, &pH_512_128[i][1]);
            alcp::cipher::aesni::gMul(
                pH_512_128[i][1], Hsubkey_128, &pH_512_128[i][0]);
        }
    }

    uint64_t blockCount_1x512 = factor;
    __m512i  a1, b1;

    uint64_t blockCount_4x512 = 4 * factor;
    uint64_t blockCount_2x512 = 2 * factor;

    __m512i a2, a3, a4;
    __m512i b2, b3, b4;
    __m512i c2, c3, c4;

    int numParallel_512blks = 1;
#if ENABLE_96_BLK_AGG_GMUL
    numParallel_512blks = 6;

    uint64_t blockCount_6x512 = numParallel_512blks * factor;
    if (blocks < 48) {
        blockCount_6x512 =
            blocks + 1; // stop condition, not to use blockCount_6x512 loop.
    }

    __m512i six_x = alcp_add_epi32(four_x, two_x);
    __m512i a5, a6;
    __m512i b5, b6;
    __m512i c5, c6;

    uint64_t blockCount_6x512_4unroll = blockCount_6x512 * 4;
    if (blocks < threshold_6x512_4unroll) {
        blockCount_6x512_4unroll =
            blocks
            + 1; // stop condition, not to use blockCount_6x512_4unroll loop.
    }

    for (; blocks >= blockCount_6x512_4unroll;
         blocks -= blockCount_6x512_4unroll) {
        __m512i z0_512, z1_512, z2_512;

        __m512i z0_512_t, z1_512_t, z2_512_t;
        int     k = (num_512_blks / numParallel_512blks - 1);
        int     n = numParallel_512blks * k;

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);
        c5 = alcp_add_epi32(c4, one_x);
        c6 = alcp_add_epi32(c5, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);
        a5 = alcp_loadu(p_in_x + 4);
        a6 = alcp_loadu(p_in_x + 5);

        if (isEncrypt == false) {

            get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                Hsubkey_512[1 + n],
                                                Hsubkey_512[2 + n],
                                                Hsubkey_512[3 + n],
                                                Hsubkey_512[4 + n],
                                                Hsubkey_512[5 + n],
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                a5,
                                                a6,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);
        b5 = alcp_shuffle_epi8(c5, swap_ctr);
        b6 = alcp_shuffle_epi8(c6, swap_ctr);

        AesEncrypt(&b1, &b2, &b3, &b4, &b5, &b6, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);
        a5 = alcp_xor(b5, a5);
        a6 = alcp_xor(b6, a6);

        // increment counter
        c1 = alcp_add_epi32(c1, six_x);

        if (isEncrypt == true) {
            get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                Hsubkey_512[1 + n],
                                                Hsubkey_512[2 + n],
                                                Hsubkey_512[3 + n],
                                                Hsubkey_512[4 + n],
                                                Hsubkey_512[5 + n],
                                                a1,
                                                a2,
                                                a3,
                                                a4,
                                                a5,
                                                a6,
                                                reverse_mask_512,
                                                &z0_512,
                                                &z1_512,
                                                &z2_512,
                                                *pgHash_128,
                                                1);
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);
        alcp_storeu(p_out_x + 4, a5);
        alcp_storeu(p_out_x + 5, a6);

        p_in_x += numParallel_512blks;
        p_out_x += numParallel_512blks;

        for (k = (num_512_blks / numParallel_512blks - 2); k >= 0; k--) {

            n  = numParallel_512blks * k;
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);
            c5 = alcp_add_epi32(c4, one_x);
            c6 = alcp_add_epi32(c5, one_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);
            a3 = alcp_loadu(p_in_x + 2);
            a4 = alcp_loadu(p_in_x + 3);
            a5 = alcp_loadu(p_in_x + 4);
            a6 = alcp_loadu(p_in_x + 5);

            if (isEncrypt == false) {
                get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                    Hsubkey_512[1 + n],
                                                    Hsubkey_512[2 + n],
                                                    Hsubkey_512[3 + n],
                                                    Hsubkey_512[4 + n],
                                                    Hsubkey_512[5 + n],
                                                    a1,
                                                    a2,
                                                    a3,
                                                    a4,
                                                    a5,
                                                    a6,
                                                    reverse_mask_512,
                                                    &z0_512_t,
                                                    &z1_512_t,
                                                    &z2_512_t,
                                                    *pgHash_128,
                                                    0);

                z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
                z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
                z2_512 = _mm512_xor_si512(z2_512_t, z2_512);
            }

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);
            b3 = alcp_shuffle_epi8(c3, swap_ctr);
            b4 = alcp_shuffle_epi8(c4, swap_ctr);
            b5 = alcp_shuffle_epi8(c5, swap_ctr);
            b6 = alcp_shuffle_epi8(c6, swap_ctr);

            AesEncrypt(&b1, &b2, &b3, &b4, &b5, &b6, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);
            a3 = alcp_xor(b3, a3);
            a4 = alcp_xor(b4, a4);
            a5 = alcp_xor(b5, a5);
            a6 = alcp_xor(b6, a6);

            // increment counter
            c1 = alcp_add_epi32(c1, six_x);

            if (isEncrypt == true) {
                get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                    Hsubkey_512[1 + n],
                                                    Hsubkey_512[2 + n],
                                                    Hsubkey_512[3 + n],
                                                    Hsubkey_512[4 + n],
                                                    Hsubkey_512[5 + n],
                                                    a1,
                                                    a2,
                                                    a3,
                                                    a4,
                                                    a5,
                                                    a6,
                                                    reverse_mask_512,
                                                    &z0_512_t,
                                                    &z1_512_t,
                                                    &z2_512_t,
                                                    *pgHash_128,
                                                    0);

                z0_512 = _mm512_xor_si512(z0_512_t, z0_512);
                z1_512 = _mm512_xor_si512(z1_512_t, z1_512);
                z2_512 = _mm512_xor_si512(z2_512_t, z2_512);
            }

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);
            alcp_storeu(p_out_x + 2, a3);
            alcp_storeu(p_out_x + 3, a4);
            alcp_storeu(p_out_x + 4, a5);
            alcp_storeu(p_out_x + 5, a6);

            p_in_x += numParallel_512blks;
            p_out_x += numParallel_512blks;
        }

        getGhash(z0_512, z1_512, z2_512, pgHash_128);
    }
#else // ENABLE_96_BLK_AGG_GMUL

    /* 64 blocks Aggregrated Reductions */

#if 1 // variable LOOP count
    numParallel_512blks = 4;
    uint64_t blockCount_4x512_N_unroll =
        blockCount_4x512 * (num_512_blks / numParallel_512blks);

    if (blocks < threshold_4x512_2unroll) {
        blockCount_4x512_N_unroll =
            blocks + 1; // stop condition, not to skip this loop.
    }

    for (; blocks >= blockCount_4x512_N_unroll;
         blocks -= blockCount_4x512_N_unroll) {

        __m512i z0_512, z1_512, z2_512;

        __m512i z0_512_t, z1_512_t, z2_512_t;
        int     k = (num_512_blks / numParallel_512blks - 1);
        int     n = numParallel_512blks * k;

        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        if (isEncrypt == false) {
            get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                Hsubkey_512[1 + n],
                                                Hsubkey_512[2 + n],
                                                Hsubkey_512[3 + n],
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
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        if (isEncrypt == true) {
            get_aggregated_karatsuba_components(Hsubkey_512[0 + n],
                                                Hsubkey_512[1 + n],
                                                Hsubkey_512[2 + n],
                                                Hsubkey_512[3 + n],
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
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += numParallel_512blks;
        p_out_x += numParallel_512blks;

        for (k = (num_512_blks / numParallel_512blks - 2); k >= 0; k--) {

            n  = numParallel_512blks * k;
            c2 = alcp_add_epi32(c1, one_x);
            c3 = alcp_add_epi32(c1, two_x);
            c4 = alcp_add_epi32(c1, three_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);
            a3 = alcp_loadu(p_in_x + 2);
            a4 = alcp_loadu(p_in_x + 3);

            if (isEncrypt == false) {
                __m512i Hsubkey_512_0 = Hsubkey_512[0 + n];
                __m512i Hsubkey_512_1 = Hsubkey_512[1 + n];
                __m512i Hsubkey_512_2 = Hsubkey_512[2 + n];
                __m512i Hsubkey_512_3 = Hsubkey_512[3 + n];

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
            }

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);
            b3 = alcp_shuffle_epi8(c3, swap_ctr);
            b4 = alcp_shuffle_epi8(c4, swap_ctr);

            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);
            a3 = alcp_xor(b3, a3);
            a4 = alcp_xor(b4, a4);

            // increment counter
            c1 = alcp_add_epi32(c1, four_x);

            if (isEncrypt == true) {
                __m512i Hsubkey_512_0 = Hsubkey_512[0 + n];
                __m512i Hsubkey_512_1 = Hsubkey_512[1 + n];
                __m512i Hsubkey_512_2 = Hsubkey_512[2 + n];
                __m512i Hsubkey_512_3 = Hsubkey_512[3 + n];

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
            }

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);
            alcp_storeu(p_out_x + 2, a3);
            alcp_storeu(p_out_x + 3, a4);

            p_in_x += numParallel_512blks;
            p_out_x += numParallel_512blks;
        }

        getGhash(z0_512, z1_512, z2_512, pgHash_128);
    }
#else // LOOP Fixed = 4

#endif // LOOP
#endif // ENABLE_96_BLK_AGG_GMUL

    for (; blocks >= blockCount_4x512; blocks -= blockCount_4x512) {
        c2 = alcp_add_epi32(c1, one_x);
        c3 = alcp_add_epi32(c1, two_x);
        c4 = alcp_add_epi32(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        if (isEncrypt == false) {
            gMulR(Hsubkey_512[0],
                  Hsubkey_512[1],
                  Hsubkey_512[2],
                  Hsubkey_512[3],
                  a1,
                  a2,
                  a3,
                  a4,
                  reverse_mask_512,
                  pgHash_128);
        }
        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi32(c1, four_x);

        if (isEncrypt == true) {
            gMulR(Hsubkey_512[0],
                  Hsubkey_512[1],
                  Hsubkey_512[2],
                  Hsubkey_512[3],
                  a1,
                  a2,
                  a3,
                  a4,
                  reverse_mask_512,
                  pgHash_128);
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount_2x512; blocks -= blockCount_2x512) {
        c2 = alcp_add_epi32(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        if (isEncrypt == false) {
            gMulR(Hsubkey_512[0], a1, reverse_mask_512, pgHash_128);
            gMulR(Hsubkey_512[0], a2, reverse_mask_512, pgHash_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        AesEncrypt(&b1, &b2, pkey128, nRounds);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi32(c1, two_x);

        if (isEncrypt == true) {
            gMulR(Hsubkey_512[0], a1, reverse_mask_512, pgHash_128);
            gMulR(Hsubkey_512[0], a2, reverse_mask_512, pgHash_128);
        }

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount_1x512; blocks -= blockCount_1x512) {
        a1 = alcp_loadu(p_in_x);

        if (isEncrypt == false) {
            gMulR(Hsubkey_512[0], a1, reverse_mask_512, pgHash_128);
        }

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        AesEncrypt(&b1, pkey128, nRounds);
        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi32(c1, one_x);

        if (isEncrypt == true) {
            gMulR(Hsubkey_512[0], a1, reverse_mask_512, pgHash_128);
        }

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

        if (isEncrypt == false) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            alcp::cipher::aesni::gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        // re-arrange as per spec
        __m128i b1 = _mm_shuffle_epi8(c1_128, swap_ctr_128);
        alcp::cipher::aesni::AesEncrypt(&b1, pkey128, nRounds);
        a1 = _mm_xor_si128(b1, a1);

        // increment counter
        c1_128 = _mm_add_epi32(c1_128, one_lo_128);

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            alcp::cipher::aesni::gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

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

        const uint8_t* p_in  = reinterpret_cast<const uint8_t*>(p_in_x);
        uint8_t*       p_out = reinterpret_cast<uint8_t*>(&a1);

        int i = 0;
        for (; i < remBytes; i++) {
            p_out[i] = p_in[i];
        }
        for (; i < 16; i++) {
            p_out[i] = 0;
        }

        if (isEncrypt == false) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            alcp::cipher::aesni::gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }

        a1 = _mm_xor_si128(b1, a1);
        for (i = remBytes; i < 16; i++) {
            p_out[i] = 0;
        }

        uint8_t* p_store = reinterpret_cast<uint8_t*>(p_out_x);
        for (i = 0; i < remBytes; i++) {
            p_store[i] = p_out[i];
        }

        if (isEncrypt == true) {
            __m128i ra1 = _mm_shuffle_epi8(a1, reverse_mask_128);
            *pgHash_128 = _mm_xor_si128(ra1, *pgHash_128);
            alcp::cipher::aesni::gMul(*pgHash_128, Hsubkey_128, pgHash_128);
        }
    }
    return blocks;
}

alc_error_t
CryptGcm(const uint8_t* pInputText,  // ptr to inputText
         uint8_t*       pOutputText, // ptr to outputtext
         uint64_t       len,         // message length in bytes
         const uint8_t* pKey,        // ptr to Key
         int            nRounds,     // No. of rounds
         const uint8_t* pIv,         // ptr to Initialization Vector
         __m128i*       pgHash_128,
         __m128i        Hsubkey_128,
         __m128i        iv_128,
         __m128i        reverse_mask_128,
         bool           isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;

    uint64_t blocks   = len / Rijndael::cBlockSize;
    int      remBytes = len - (blocks * Rijndael::cBlockSize);

    auto p_in_512  = reinterpret_cast<const __m512i*>(pInputText);
    auto p_out_512 = reinterpret_cast<__m512i*>(pOutputText);
    auto pkey128   = reinterpret_cast<const __m128i*>(pKey);

    gcmBlk_512(p_in_512,
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
               isEncrypt,
               remBytes);

    return err;
}

} // namespace alcp::cipher::vaes
