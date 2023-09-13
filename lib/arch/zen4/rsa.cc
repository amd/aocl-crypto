/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
#include "alcp/rsa.h"
#include "alcp/rsa/rsa_internal.hh"
#include "alcp/utils/copy.hh"
#include <immintrin.h>

namespace alcp::rsa { namespace zen4 {
#include "../../rsa/rsa.cc.inc"

    constexpr Uint64 num_digit = (2048 / 52 + 1);

    static inline void Amm1024LoopInternalStage1(__m512i       res_reg[3],
                                                 __m512i       first_reg[3],
                                                 __m512i       mod_reg[3],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[0] =
                _mm512_madd52lo_epu64(res_reg[0], first_reg[0], second_reg);

            for (Uint64 z = 1; z < 3; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(zero, res_reg[2], 1);

            res_reg[0] =
                _mm512_madd52hi_epu64(res_reg[0], first_reg[0], second_reg);

            for (Uint64 z = 1; z < 3; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage2(__m512i       res_reg[3],
                                                 __m512i       first_reg[3],
                                                 __m512i       mod_reg[3],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[1] =
                _mm512_madd52lo_epu64(res_reg[1], first_reg[1], second_reg);

            for (Uint64 z = 2; z < 3; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(zero, res_reg[2], 1);

            res_reg[1] =
                _mm512_madd52hi_epu64(res_reg[1], first_reg[1], second_reg);

            for (Uint64 z = 2; z < 3; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage3(__m512i       res_reg[3],
                                                 __m512i       first_reg[3],
                                                 __m512i       mod_reg[3],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 4; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[2] =
                _mm512_madd52lo_epu64(res_reg[2], first_reg[2], second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(zero, res_reg[2], 1);

            res_reg[2] =
                _mm512_madd52hi_epu64(res_reg[2], first_reg[2], second_reg);

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
        }
    }

    static inline void AMM1024(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg_0;
        __m512i first_reg_1;
        __m512i first_reg_2;

        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;

        __m512i res_reg_0{};
        __m512i res_reg_1{};
        __m512i res_reg_2{};

        first_reg_0 = _mm512_loadu_si512(first);
        first_reg_1 = _mm512_loadu_si512(first + 8);
        first_reg_2 = _mm512_loadu_si512(first + 16);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);

        const __m512i zero{};
        __m512i       k_reg = _mm512_set1_epi64(k0);

        for (Uint64 i = 0; i < 20; i++) {

            __m512i second_reg = _mm512_set1_epi64(second[i]);

            res_reg_0 =
                _mm512_madd52lo_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52lo_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52lo_epu64(res_reg_2, first_reg_2, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg_0);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(zero, res_reg_2, 1);

            res_reg_0 =
                _mm512_madd52hi_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52hi_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52hi_epu64(res_reg_2, first_reg_2, second_reg);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024Parallel(Uint64* res[2],
                                       Uint64* first[2],
                                       Uint64* second[2],
                                       Uint64* mod[2],
                                       Uint64  k0[2])
    {
        __m512i first_reg_0;
        __m512i first_reg_1;
        __m512i first_reg_2;
        __m512i first_reg_3;
        __m512i first_reg_4;
        __m512i first_reg_5;

        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;
        __m512i mod_reg_5;

        __m512i res_reg_0{};
        __m512i res_reg_1{};
        __m512i res_reg_2{};
        __m512i res_reg_3{};
        __m512i res_reg_4{};
        __m512i res_reg_5{};

        first_reg_0 = _mm512_loadu_si512(first[0]);
        first_reg_1 = _mm512_loadu_si512(first[0] + 8);
        first_reg_2 = _mm512_loadu_si512(first[0] + 16);
        first_reg_3 = _mm512_loadu_si512(first[1]);
        first_reg_4 = _mm512_loadu_si512(first[1] + 8);
        first_reg_5 = _mm512_loadu_si512(first[1] + 16);

        mod_reg_0 = _mm512_loadu_si512(mod[0]);
        mod_reg_1 = _mm512_loadu_si512(mod[0] + 8);
        mod_reg_2 = _mm512_loadu_si512(mod[0] + 16);
        mod_reg_3 = _mm512_loadu_si512(mod[1]);
        mod_reg_4 = _mm512_loadu_si512(mod[1] + 8);
        mod_reg_5 = _mm512_loadu_si512(mod[1] + 16);

        const __m512i zero{};
        __m512i       k_reg_0 = _mm512_set1_epi64(k0[0]);
        __m512i       k_reg_1 = _mm512_set1_epi64(k0[1]);

        for (Uint64 i = 0; i < 20; i++) {

            __m512i second_reg = _mm512_set1_epi64(second[0][i]);

            res_reg_0 =
                _mm512_madd52lo_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52lo_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52lo_epu64(res_reg_2, first_reg_2, second_reg);

            // Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            // Uint64 y0 = (k0[0] * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            // __m512i y_reg = _mm512_set1_epi64(y0);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg_0, res_reg_0);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(zero, res_reg_2, 1);

            res_reg_0 =
                _mm512_madd52hi_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52hi_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52hi_epu64(res_reg_2, first_reg_2, second_reg);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);

            // second multiplier
            second_reg = _mm512_set1_epi64(second[1][i]);

            res_reg_3 =
                _mm512_madd52lo_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52lo_epu64(res_reg_4, first_reg_4, second_reg);
            res_reg_5 =
                _mm512_madd52lo_epu64(res_reg_5, first_reg_5, second_reg);

            // x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_3));

            // y0 = (k0[1] * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            // y_reg = _mm512_set1_epi64(y0);

            y_reg = _mm512_madd52lo_epu64(zero, k_reg_1, res_reg_3);
            y_reg = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);
            res_reg_5 = _mm512_madd52lo_epu64(res_reg_5, mod_reg_5, y_reg);

            carry     = _mm512_maskz_srli_epi64(1, res_reg_3, 52);
            res_reg_3 = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_3 = _mm512_add_epi64(res_reg_3, carry);
            res_reg_4 = _mm512_alignr_epi64(res_reg_5, res_reg_4, 1);
            res_reg_5 = _mm512_alignr_epi64(zero, res_reg_5, 1);

            res_reg_3 =
                _mm512_madd52hi_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52hi_epu64(res_reg_4, first_reg_4, second_reg);
            res_reg_5 =
                _mm512_madd52hi_epu64(res_reg_5, first_reg_5, second_reg);

            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
            res_reg_5 = _mm512_madd52hi_epu64(res_reg_5, mod_reg_5, y_reg);
        }

        _mm512_storeu_si512(res[0], res_reg_0);
        _mm512_storeu_si512(res[0] + 8, res_reg_1);
        _mm512_storeu_si512(res[0] + 16, res_reg_2);
        _mm512_storeu_si512(res[1], res_reg_3);
        _mm512_storeu_si512(res[1] + 8, res_reg_4);
        _mm512_storeu_si512(res[1] + 16, res_reg_5);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[0][i] + carry;
            carry      = sum >> 52;
            res[0][i]  = sum & 0xfffffffffffff;
        }

        carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[1][i] + carry;
            carry      = sum >> 52;
            res[1][i]  = sum & 0xfffffffffffff;
        }
    }

    static inline void AMS1024(Uint64*       res,
                               const Uint64* first,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg[3];
        __m512i mod_reg[3];

        __m512i res_reg[3]{};

        first_reg[0] = _mm512_loadu_si512(first);
        first_reg[1] = _mm512_loadu_si512(first + 8);
        first_reg[2] = _mm512_loadu_si512(first + 16);

        mod_reg[0] = _mm512_loadu_si512(mod);
        mod_reg[1] = _mm512_loadu_si512(mod + 8);
        mod_reg[2] = _mm512_loadu_si512(mod + 16);

        __m512i k_reg = _mm512_set1_epi64(k0);

        Amm1024LoopInternalStage1(res_reg, first_reg, mod_reg, first, k_reg);
        Amm1024LoopInternalStage2(
            res_reg, first_reg, mod_reg, first + 8, k_reg);
        Amm1024LoopInternalStage3(
            res_reg, first_reg, mod_reg, first + 16, k_reg);

        _mm512_storeu_si512(res, res_reg[0]);
        _mm512_storeu_si512(res + 8, res_reg[1]);
        _mm512_storeu_si512(res + 16, res_reg[2]);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMS1024Parallel(Uint64* res[2],
                                       Uint64* first[2],
                                       Uint64* mod[2],
                                       Uint64  k0[2])
    {
        __m512i first_reg[6];
        __m512i mod_reg[6];

        __m512i res_reg[6]{};
        Uint64* first_0 = first[0];
        Uint64* first_1 = first[1];
        Uint64* mod_0   = mod[0];
        Uint64* mod_1   = mod[1];
        Uint64* res_0   = res[0];
        Uint64* res_1   = res[1];

        first_reg[0] = _mm512_loadu_si512(first_0);
        first_reg[1] = _mm512_loadu_si512(first_0 + 8);
        first_reg[2] = _mm512_loadu_si512(first_0 + 16);
        first_reg[3] = _mm512_loadu_si512(first_1);
        first_reg[4] = _mm512_loadu_si512(first_1 + 8);
        first_reg[5] = _mm512_loadu_si512(first_1 + 16);

        mod_reg[0] = _mm512_loadu_si512(mod_0);
        mod_reg[1] = _mm512_loadu_si512(mod_0 + 8);
        mod_reg[2] = _mm512_loadu_si512(mod_0 + 16);
        mod_reg[3] = _mm512_loadu_si512(mod_1);
        mod_reg[4] = _mm512_loadu_si512(mod_1 + 8);
        mod_reg[5] = _mm512_loadu_si512(mod_1 + 16);

        __m512i k_reg = _mm512_set1_epi64(k0[0]);
        Amm1024LoopInternalStage1(res_reg, first_reg, mod_reg, first_0, k_reg);
        Amm1024LoopInternalStage2(
            res_reg, first_reg, mod_reg, first_0 + 8, k_reg);
        Amm1024LoopInternalStage3(
            res_reg, first_reg, mod_reg, first_0 + 16, k_reg);

        k_reg = _mm512_set1_epi64(k0[1]);
        Amm1024LoopInternalStage1(
            res_reg + 3, first_reg + 3, mod_reg + 3, first_1, k_reg);
        Amm1024LoopInternalStage2(
            res_reg + 3, first_reg + 3, mod_reg + 3, first_1 + 8, k_reg);
        Amm1024LoopInternalStage3(
            res_reg + 3, first_reg + 3, mod_reg + 3, first_1 + 16, k_reg);

        _mm512_storeu_si512(res_0, res_reg[0]);
        _mm512_storeu_si512(res_0 + 8, res_reg[1]);
        _mm512_storeu_si512(res_0 + 16, res_reg[2]);
        _mm512_storeu_si512(res_1, res_reg[3]);
        _mm512_storeu_si512(res_1 + 8, res_reg[4]);
        _mm512_storeu_si512(res_1 + 16, res_reg[5]);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[0][i] + carry;
            carry      = sum >> 52;
            res[0][i]  = sum & 0xfffffffffffff;
        }

        carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[1][i] + carry;
            carry      = sum >> 52;
            res[1][i]  = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM2048(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg_0;
        __m512i first_reg_1;
        __m512i first_reg_2;
        __m512i first_reg_3;
        __m512i first_reg_4;

        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;

        __m512i res_reg_0{};
        __m512i res_reg_1{};
        __m512i res_reg_2{};
        __m512i res_reg_3{};
        __m512i res_reg_4{};

        first_reg_0 = _mm512_loadu_si512(first);
        first_reg_1 = _mm512_loadu_si512(first + 8);
        first_reg_2 = _mm512_loadu_si512(first + 16);
        first_reg_3 = _mm512_loadu_si512(first + 24);
        first_reg_4 = _mm512_loadu_si512(first + 32);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);
        mod_reg_3 = _mm512_loadu_si512(mod + 24);
        mod_reg_4 = _mm512_loadu_si512(mod + 32);

        __m512i k_reg = _mm512_set1_epi64(k0);

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {
            __m512i second_reg = _mm512_set1_epi64(second[i]);

            res_reg_0 =
                _mm512_madd52lo_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52lo_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52lo_epu64(res_reg_2, first_reg_2, second_reg);
            res_reg_3 =
                _mm512_madd52lo_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52lo_epu64(res_reg_4, first_reg_4, second_reg);

            // Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            // Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            // __m512i y_reg = _mm512_set1_epi64(y0);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg_0);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(res_reg_3, res_reg_2, 1);
            res_reg_3     = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_4     = _mm512_alignr_epi64(zero, res_reg_4, 1);

            res_reg_0 =
                _mm512_madd52hi_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52hi_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52hi_epu64(res_reg_2, first_reg_2, second_reg);
            res_reg_3 =
                _mm512_madd52hi_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52hi_epu64(res_reg_4, first_reg_4, second_reg);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);
        _mm512_storeu_si512(res + 24, res_reg_3);
        _mm512_storeu_si512(res + 32, res_reg_4);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void Amm2048LoopInternalStage1(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 __m512i       mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[0] =
                _mm512_madd52lo_epu64(res_reg[0], first_reg[0], second_reg);

            for (Uint64 z = 1; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            // Uint64 x0 =
            // _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg[0]));

            // Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            // __m512i y_reg = _mm512_set1_epi64(y0);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52lo_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52lo_epu64(res_reg[4], mod_reg[4], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            res_reg[0] =
                _mm512_madd52hi_epu64(res_reg[0], first_reg[0], second_reg);

            for (Uint64 z = 1; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52hi_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52hi_epu64(res_reg[4], mod_reg[4], y_reg);
        }
    }

    static inline void Amm2048LoopInternalStage2(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 __m512i       mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[1] =
                _mm512_madd52lo_epu64(res_reg[1], first_reg[1], second_reg);

            for (Uint64 z = 2; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52lo_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52lo_epu64(res_reg[4], mod_reg[4], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            res_reg[1] =
                _mm512_madd52hi_epu64(res_reg[1], first_reg[1], second_reg);

            for (Uint64 z = 2; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52hi_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52hi_epu64(res_reg[4], mod_reg[4], y_reg);
        }
    }
    static inline void Amm2048LoopInternalStage3(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 __m512i       mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[2] =
                _mm512_madd52lo_epu64(res_reg[2], first_reg[2], second_reg);

            for (Uint64 z = 3; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52lo_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52lo_epu64(res_reg[4], mod_reg[4], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            res_reg[2] =
                _mm512_madd52hi_epu64(res_reg[2], first_reg[2], second_reg);

            for (Uint64 z = 3; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52hi_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52hi_epu64(res_reg[4], mod_reg[4], y_reg);
        }
    }
    static inline void Amm2048LoopInternalStage4(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 __m512i       mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[3] =
                _mm512_madd52lo_epu64(res_reg[3], first_reg[3], second_reg);

            for (Uint64 z = 4; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52lo_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52lo_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52lo_epu64(res_reg[4], mod_reg[4], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            res_reg[3] =
                _mm512_madd52hi_epu64(res_reg[3], first_reg[3], second_reg);

            for (Uint64 z = 4; z < 5; z++) {
                __m512i temp =
                    _mm512_madd52hi_epu64(zero, first_reg[z], second_reg);

                temp       = _mm512_slli_epi64(temp, 1);
                res_reg[z] = _mm512_add_epi64(temp, res_reg[z]);
            }

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52hi_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52hi_epu64(res_reg[4], mod_reg[4], y_reg);
        }
    }

    static inline void Amm2048LoopInternalStage5(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 __m512i       mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            res_reg[4] =
                _mm512_madd52lo_epu64(res_reg[4], first_reg[4], second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

            res_reg[0] = _mm512_madd52lo_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52lo_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52lo_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52lo_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52lo_epu64(res_reg[4], mod_reg[4], y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            res_reg[4] =
                _mm512_madd52hi_epu64(res_reg[4], first_reg[4], second_reg);

            res_reg[0] = _mm512_madd52hi_epu64(res_reg[0], mod_reg[0], y_reg);
            res_reg[1] = _mm512_madd52hi_epu64(res_reg[1], mod_reg[1], y_reg);
            res_reg[2] = _mm512_madd52hi_epu64(res_reg[2], mod_reg[2], y_reg);
            res_reg[3] = _mm512_madd52hi_epu64(res_reg[3], mod_reg[3], y_reg);
            res_reg[4] = _mm512_madd52hi_epu64(res_reg[4], mod_reg[4], y_reg);
        }
    }

    static inline void AMS2048(Uint64*       res,
                               const Uint64* first,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg[5];
        __m512i mod_reg[5];

        __m512i res_reg[5]{};

        first_reg[0] = _mm512_loadu_si512(first);
        first_reg[1] = _mm512_loadu_si512(first + 8);
        first_reg[2] = _mm512_loadu_si512(first + 16);
        first_reg[3] = _mm512_loadu_si512(first + 24);
        first_reg[4] = _mm512_loadu_si512(first + 32);

        mod_reg[0] = _mm512_loadu_si512(mod);
        mod_reg[1] = _mm512_loadu_si512(mod + 8);
        mod_reg[2] = _mm512_loadu_si512(mod + 16);
        mod_reg[3] = _mm512_loadu_si512(mod + 24);
        mod_reg[4] = _mm512_loadu_si512(mod + 32);

        __m512i k_reg = _mm512_set1_epi64(k0);
        Amm2048LoopInternalStage1(res_reg, first_reg, mod_reg, first, k_reg);
        Amm2048LoopInternalStage2(
            res_reg, first_reg, mod_reg, first + 8, k_reg);
        Amm2048LoopInternalStage3(
            res_reg, first_reg, mod_reg, first + 16, k_reg);
        Amm2048LoopInternalStage4(
            res_reg, first_reg, mod_reg, first + 24, k_reg);
        Amm2048LoopInternalStage5(
            res_reg, first_reg, mod_reg, first + 32, k_reg);

        _mm512_storeu_si512(res, res_reg[0]);
        _mm512_storeu_si512(res + 8, res_reg[1]);
        _mm512_storeu_si512(res + 16, res_reg[2]);
        _mm512_storeu_si512(res + 24, res_reg[3]);
        _mm512_storeu_si512(res + 32, res_reg[4]);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM2048Reduce(Uint64*       res,
                                     const Uint64* first,
                                     const Uint64* mod,
                                     Uint64        k0)
    {
        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;

        __m512i res_reg_0 = _mm512_loadu_si512(first);
        __m512i res_reg_1 = _mm512_loadu_si512(first + 8);
        __m512i res_reg_2 = _mm512_loadu_si512(first + 16);
        __m512i res_reg_3 = _mm512_loadu_si512(first + 24);
        __m512i res_reg_4 = _mm512_loadu_si512(first + 32);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);
        mod_reg_3 = _mm512_loadu_si512(mod + 24);
        mod_reg_4 = _mm512_loadu_si512(mod + 32);

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(res_reg_3, res_reg_2, 1);
            res_reg_3     = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_4     = _mm512_alignr_epi64(zero, res_reg_4, 1);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);
        _mm512_storeu_si512(res + 24, res_reg_3);
        _mm512_storeu_si512(res + 32, res_reg_4);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024Reduce(Uint64*       res,
                                     const Uint64* first,
                                     const Uint64* mod,
                                     Uint64        k0)
    {
        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;

        __m512i res_reg_0 = _mm512_loadu_si512(first);
        __m512i res_reg_1 = _mm512_loadu_si512(first + 8);
        __m512i res_reg_2 = _mm512_loadu_si512(first + 16);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);

        const __m512i zero{};

        for (Uint64 i = 0; i < 20; i++) {

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(zero, res_reg_2, 1);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024ReduceParallel(Uint64* res[2],
                                             Uint64* first[2],
                                             Uint64* mod[2],
                                             Uint64  k0[2])
    {
        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;
        __m512i mod_reg_5;

        __m512i res_reg_0 = _mm512_loadu_si512(first[0]);
        __m512i res_reg_1 = _mm512_loadu_si512(first[0] + 8);
        __m512i res_reg_2 = _mm512_loadu_si512(first[0] + 16);
        __m512i res_reg_3 = _mm512_loadu_si512(first[1]);
        __m512i res_reg_4 = _mm512_loadu_si512(first[1] + 8);
        __m512i res_reg_5 = _mm512_loadu_si512(first[1] + 16);

        mod_reg_0 = _mm512_loadu_si512(mod[0]);
        mod_reg_1 = _mm512_loadu_si512(mod[0] + 8);
        mod_reg_2 = _mm512_loadu_si512(mod[0] + 16);
        mod_reg_3 = _mm512_loadu_si512(mod[1]);
        mod_reg_4 = _mm512_loadu_si512(mod[1] + 8);
        mod_reg_5 = _mm512_loadu_si512(mod[1] + 16);

        const __m512i zero{};

        for (Uint64 i = 0; i < 20; i++) {

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            Uint64 y0 = (k0[0] * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(zero, res_reg_2, 1);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);

            // second multiplier
            x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_3));

            y0 = (k0[1] * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            y_reg = _mm512_set1_epi64(y0);

            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);
            res_reg_5 = _mm512_madd52lo_epu64(res_reg_5, mod_reg_5, y_reg);

            carry     = _mm512_maskz_srli_epi64(1, res_reg_3, 52);
            res_reg_3 = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_3 = _mm512_add_epi64(res_reg_3, carry);
            res_reg_4 = _mm512_alignr_epi64(res_reg_5, res_reg_4, 1);
            res_reg_5 = _mm512_alignr_epi64(zero, res_reg_5, 1);

            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
            res_reg_5 = _mm512_madd52hi_epu64(res_reg_5, mod_reg_5, y_reg);
        }

        _mm512_storeu_si512(res[0], res_reg_0);
        _mm512_storeu_si512(res[0] + 8, res_reg_1);
        _mm512_storeu_si512(res[0] + 16, res_reg_2);
        _mm512_storeu_si512(res[1], res_reg_3);
        _mm512_storeu_si512(res[1] + 8, res_reg_4);
        _mm512_storeu_si512(res[1] + 16, res_reg_5);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[0][i] + carry;
            carry      = sum >> 52;
            res[0][i]  = sum & 0xfffffffffffff;
        }
        carry = 0;
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[1][i] + carry;
            carry      = sum >> 52;
            res[1][i]  = sum & 0xfffffffffffff;
        }
    }

    static inline void AMMAndAMS1024(
        Uint64* res, Uint64* mult, Uint64* mod, Uint64 k0, Uint64 val)
    {
        AMS1024(res, res, mod, k0);
        // AMM1024(res, res, res, mod, k0);
        if (val & mont::one_msb) {
            AMM1024(res, res, mult, mod, k0);
        }
    }

    static inline void AMMAndAMS2048(
        Uint64* res, Uint64* mult, Uint64* mod, Uint64 k0, Uint64 val)
    {
        AMS2048(res, res, mod, k0);
        if (val & mont::one_msb) {
            AMM2048(res, res, mult, mod, k0);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::CreateContext(
        MontContextBignum& context, Uint64* mod, Uint64 size)
    {
        Uint64* r1               = new Uint64[size]{};
        Uint64* r2               = new Uint64[size]{};
        Uint64* r3               = new Uint64[size]{};
        Uint64* r2_radix_52_bit  = new Uint64[40]{};
        Uint64* mod_radix_52_bit = new Uint64[40]{};

        context.m_r1.reset(r1);
        context.m_r2.reset(r2);
        context.m_r3.reset(r3);
        context.m_r2_radix_52_bit.reset(r2_radix_52_bit);
        context.m_mod_radix_52_bit.reset(mod_radix_52_bit);
        context.m_size = size;
        context.m_k0   = computeMontFactor(mod[0]);

        BigNum inp{ mod, size, size - 1 }, res{ r2, size, size - 1 };

        computeMontConverter(res, inp);

        MontMultHalf(r3, r2, r2, mod, context.m_k0);

        auto param     = std::make_unique<Uint64[]>(size * 2);
        auto param_ptr = param.get();
        alcp::utils::CopyChunk(param_ptr, r2, size * 8);

        MontReduce(r1, param_ptr, mod, context.m_k0, size * 2);

        if (size == 32) {
            Rsa2048BytesToRadix52Bit(mod_radix_52_bit, mod);
            Rsa2048BytesToRadix52Bit(r2_radix_52_bit, r2);

            //(congruent to 2^(4n-k×m) mod M)
            AMM2048(r2_radix_52_bit,
                    r2_radix_52_bit,
                    r2_radix_52_bit,
                    mod_radix_52_bit,
                    context.m_k0);
            // 2^(4n-km) in radix 52
            alignas(64) const Uint64 mult[40] = { 0x00, 0x00, 0x1000000 };

            //(congruent to 2^2k×m mod M)
            AMM2048(r2_radix_52_bit,
                    r2_radix_52_bit,
                    mult,
                    mod_radix_52_bit,
                    context.m_k0);
        } else {
            Rsa1024BytesToRadix52Bit(mod_radix_52_bit, mod);
            Rsa1024BytesToRadix52Bit(r2_radix_52_bit, r2);

            //(congruent to 2^(4n-k×m) mod M)
            AMM1024(r2_radix_52_bit,
                    r2_radix_52_bit,
                    r2_radix_52_bit,
                    mod_radix_52_bit,
                    context.m_k0);
            // 2^(4n-km) in radix 52
            alignas(64) const Uint64 mult[20] = { 0x00, 0x1000 };

            //(congruent to 2^2k×m mod M)
            AMM1024(r2_radix_52_bit,
                    r2_radix_52_bit,
                    mult,
                    mod_radix_52_bit,
                    context.m_k0);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::CreateContext(
        MontContextBignum& context, Uint64* mod, Uint64 size)
    {
        Uint64* r1               = new Uint64[size]{};
        Uint64* r2               = new Uint64[size]{};
        Uint64* r3               = new Uint64[size]{};
        Uint64* r2_radix_52_bit  = new Uint64[24]{};
        Uint64* mod_radix_52_bit = new Uint64[24]{};

        context.m_r1.reset(r1);
        context.m_r2.reset(r2);
        context.m_r3.reset(r3);
        context.m_r2_radix_52_bit.reset(r2_radix_52_bit);
        context.m_mod_radix_52_bit.reset(mod_radix_52_bit);
        context.m_size = size;
        context.m_k0   = computeMontFactor(mod[0]);

        BigNum inp{ mod, size, size - 1 }, res{ r2, size, size - 1 };

        computeMontConverter(res, inp);

        MontMultHalf(r3, r2, r2, mod, context.m_k0);

        auto param     = std::make_unique<Uint64[]>(size * 2);
        auto param_ptr = param.get();
        alcp::utils::CopyChunk(param_ptr, r2, size * 8);

        MontReduce(r1, param_ptr, mod, context.m_k0, size * 2);

        Rsa1024BytesToRadix52Bit(mod_radix_52_bit, mod);
        Rsa1024BytesToRadix52Bit(r2_radix_52_bit, r2);

        //(congruent to 2^(4n-k×m) mod M)
        AMM1024(r2_radix_52_bit,
                r2_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                context.m_k0);
        // 2^(4n-km) in radix 52
        alignas(64) const Uint64 mult[20] = { 0x00, 0x1000 };

        //(congruent to 2^2k×m mod M)
        AMM1024(r2_radix_52_bit,
                r2_radix_52_bit,
                mult,
                mod_radix_52_bit,
                context.m_k0);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        Uint64*       exp,
        Uint64        expSize,
        Uint64*       mod_radix_52_bit,
        Uint64*       r2_radix_52_bit,
        Uint64        k0)
    {

        alignas(64) Uint64 input_radix_52_bit[40];
        alignas(64) Uint64 res_radix_52_bit[40];
        Rsa2048BytesToRadix52Bit(input_radix_52_bit, input);

        // conversion to mont domain by multiplying with mont converter
        AMM2048(input_radix_52_bit,
                input_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                k0);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        alcp::utils::CopyChunk(res_radix_52_bit, input_radix_52_bit, 40 * 8);

        while (index++ < 64) {
            AMMAndAMS2048(res_radix_52_bit,
                          input_radix_52_bit,
                          mod_radix_52_bit,
                          k0,
                          val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                AMMAndAMS2048(res_radix_52_bit,
                              input_radix_52_bit,
                              mod_radix_52_bit,
                              k0,
                              val);
                val <<= 1;
            }
        }

        AMM2048Reduce(
            input_radix_52_bit, res_radix_52_bit, mod_radix_52_bit, k0);

        Rsa2048Radix52BitToBytes(res, input_radix_52_bit);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        Uint64*       exp,
        Uint64        expSize,
        Uint64*       mod_radix_52_bit,
        Uint64*       r2_radix_52_bit,
        Uint64        k0)
    {

        alignas(64) Uint64 input_radix_52_bit[24]{};
        alignas(64) Uint64 res_radix_52_bit[24]{};
        Rsa1024BytesToRadix52Bit(input_radix_52_bit, input);

        // conversion to mont domain by multiplying with mont converter
        AMM1024(input_radix_52_bit,
                input_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                k0);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        alcp::utils::CopyChunk(res_radix_52_bit, input_radix_52_bit, 20 * 8);

        while (index++ < 64) {
            AMMAndAMS1024(res_radix_52_bit,
                          input_radix_52_bit,
                          mod_radix_52_bit,
                          k0,
                          val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                AMMAndAMS1024(res_radix_52_bit,
                              input_radix_52_bit,
                              mod_radix_52_bit,
                              k0,
                              val);
                val <<= 1;
            }
        }

        AMM1024Reduce(
            input_radix_52_bit, res_radix_52_bit, mod_radix_52_bit, k0);

        Rsa1024Radix52BitToBytes(res, input_radix_52_bit);
    }

    template<>
    void archEncryptPublic<KEY_SIZE_1024>(Uint8*              pEncText,
                                          const Uint64*       pTextBignum,
                                          RsaPublicKeyBignum& pubKey,
                                          MontContextBignum&  context)
    {
        auto mod = context.m_mod_radix_52_bit.get(); //.m_mod.get();
        auto r2  = context.m_r2_radix_52_bit.get();  // context.m_r2.get();
        auto k0  = context.m_k0;
        auto exp = &pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[1024 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = 1024 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    template<>
    void archEncryptPublic<KEY_SIZE_2048>(Uint8*              pEncText,
                                          const Uint64*       pTextBignum,
                                          RsaPublicKeyBignum& pubKey,
                                          MontContextBignum&  context)
    {
        auto mod = context.m_mod_radix_52_bit.get(); //.m_mod.get();
        auto r2  = context.m_r2_radix_52_bit.get();  // context.m_r2.get();
        auto k0  = context.m_k0;
        auto exp = &pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[2048 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = 2048 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    // static inline void RSA2048MontgomeryExpConstantTime(
    //     Uint64* res,
    //     Uint64* input,
    //     Uint64* exp,
    //     Uint64* mod_radix_52_bit,
    //     Uint64* r2_radix_52_bit,
    //     Uint64  k0)
    // {
    //     alignas(64) Uint64 t[16 * 20] = {};
    //     Uint64             r1_radix_52_bit_p[24]{};
    //     Uint64             input_radix_52[24]{};
    //     Uint64             res_radix_52[24]{};
    //     Uint64             mult_radix_52[24]{};
    //     Uint64             sq_radix_52[24]{};

    //     // to do check which window size is correct
    //     Uint64 winSize    = 4;
    //     Uint64 valueLimit = 1 << 4;
    //     // putting one in mont form
    //     AMM1024Reduce(r1_radix_52_bit_p, r2_radix_52_bit, mod_radix_52_bit,
    //     k0); mont::PutInTable(t, 0, r1_radix_52_bit_p, 20, valueLimit);

    //     mont::Rsa1024BytesToRadix52Bit(input_radix_52, input);
    //     AMM1024(res_radix_52,
    //             input_radix_52,
    //             r2_radix_52_bit,
    //             mod_radix_52_bit,
    //             k0);
    //     mont::PutInTable(t, 1, res_radix_52, 20, valueLimit);

    //     alcp::utils::CopyChunk(mult_radix_52, res_radix_52, 20 * 8);
    //     for (Uint64 i = 2; i < valueLimit; i++) {
    //         AMM1024(mult_radix_52,
    //                 mult_radix_52,
    //                 res_radix_52,
    //                 mod_radix_52_bit,
    //                 k0);
    //         mont::PutInTable(t, i, mult_radix_52, 20, valueLimit);
    //     }

    //     const Uint8* exp_byte_ptr = reinterpret_cast<const Uint8*>(exp);
    //     Uint8        index_value  = exp_byte_ptr[127];
    //     mont::GetFromTable(t, index_value >> 4, sq_radix_52, 20, valueLimit);
    //     for (Uint64 i = 0; i < winSize; i++) {
    //         AMS1024(sq_radix_52, sq_radix_52, mod_radix_52_bit, k0);
    //     }

    //     mont::GetFromTable(t, index_value & 0xf, mult_radix_52, 20,
    //     valueLimit); AMM1024(sq_radix_52, sq_radix_52, mult_radix_52,
    //     mod_radix_52_bit, k0);

    //     for (Int64 i = 126; i >= 0; --i) {

    //         // first 4 bits
    //         for (Uint64 i = 0; i < winSize; i++) {
    //             AMS1024(sq_radix_52, sq_radix_52, mod_radix_52_bit, k0);
    //         }
    //         index_value = exp_byte_ptr[i];
    //         mont::GetFromTable(
    //             t, index_value >> 4, mult_radix_52, 20, valueLimit);

    //         AMM1024(
    //             sq_radix_52, mult_radix_52, sq_radix_52, mod_radix_52_bit,
    //             k0);

    //         // next 4 bits
    //         for (Uint64 i = 0; i < winSize; i++) {
    //             AMS1024(sq_radix_52, sq_radix_52, mod_radix_52_bit, k0);
    //         }
    //         mont::GetFromTable(
    //             t, index_value & 0xf, mult_radix_52, 20, valueLimit);
    //         AMM1024(
    //             sq_radix_52, mult_radix_52, sq_radix_52, mod_radix_52_bit,
    //             k0);
    //     }

    //     AMM1024Reduce(sq_radix_52, sq_radix_52, mod_radix_52_bit, k0);

    //     alcp::utils::PadBlock<Uint64>(res, 0LL, 16 * 8);
    //     mont::Rsa1024Radix52BitToBytes(res, sq_radix_52);
    // }

    static inline void RSA2048MontgomeryExpConstantTimeParallel(
        Uint64* res[2],
        Uint64* input[2],
        Uint64* exp[2],
        Uint64* modRadix52Bit[2],
        Uint64* r2Radix52Bit[2],
        Uint64  k0[2])
    {
        alignas(64) Uint64 t[16 * 20 * 2] = {};
        Uint64             r1_radix_52_bit_contig[2 * 24]{};
        Uint64             input_radix_52_contig[2 * 24]{};
        Uint64             res_radix_52_contig[2 * 24]{};
        Uint64             mult_radix_52_contig[2 * 24]{};
        Uint64             sq_radix_52_contig[2 * 24]{};

        Uint64* r1_radix_52_bit_p[2] = { r1_radix_52_bit_contig,
                                         r1_radix_52_bit_contig + 24 };
        Uint64* input_radix_52[2]    = { input_radix_52_contig,
                                      input_radix_52_contig + 24 };
        Uint64* res_radix_52[2]      = { res_radix_52_contig,
                                    res_radix_52_contig + 24 };

        Uint64* mult_radix_52[2] = { mult_radix_52_contig,
                                     mult_radix_52_contig + 24 };
        Uint64* sq_radix_52[2]   = { sq_radix_52_contig,
                                   sq_radix_52_contig + 24 };

        // to do check which window size is correct
        Uint64 winSize    = 4;
        Uint64 valueLimit = 1 << 4;
        // putting one in mont form
        AMM1024ReduceParallel(
            r1_radix_52_bit_p, r2Radix52Bit, modRadix52Bit, k0);
        mont::PutInTable(t, 0, r1_radix_52_bit_p[0], 20, valueLimit);
        mont::PutInTable(t + 16 * 20, 0, r1_radix_52_bit_p[1], 20, valueLimit);

        mont::Rsa1024BytesToRadix52Bit(input_radix_52[0], input[0]);
        mont::Rsa1024BytesToRadix52Bit(input_radix_52[1], input[1]);

        AMM1024Parallel(
            res_radix_52, input_radix_52, r2Radix52Bit, modRadix52Bit, k0);
        mont::PutInTable(t, 1, res_radix_52[0], 20, valueLimit);
        mont::PutInTable(t + 16 * 20, 1, res_radix_52[1], 20, valueLimit);

        alcp::utils::CopyChunk(
            mult_radix_52_contig, res_radix_52_contig, 24 * 8 * 2);

        for (Uint64 i = 2; i < valueLimit; i++) {
            AMM1024Parallel(
                mult_radix_52, mult_radix_52, res_radix_52, modRadix52Bit, k0);
            mont::PutInTable(t, i, mult_radix_52[0], 20, valueLimit);
            mont::PutInTable(t + 16 * 20, i, mult_radix_52[1], 20, valueLimit);
        }

        const Uint8* exp_byte_ptr_1 = reinterpret_cast<const Uint8*>(exp[0]);
        const Uint8* exp_byte_ptr_2 = reinterpret_cast<const Uint8*>(exp[1]);

        Uint8 index_value_1 = exp_byte_ptr_1[127];
        Uint8 index_value_2 = exp_byte_ptr_2[127];
        mont::GetFromTable(
            t, index_value_1 >> 4, sq_radix_52[0], 20, valueLimit);
        mont::GetFromTable(
            t + 16 * 20, index_value_2 >> 4, sq_radix_52[1], 20, valueLimit);

        for (Uint64 i = 0; i < winSize; i++) {
            AMS1024Parallel(sq_radix_52, sq_radix_52, modRadix52Bit, k0);
        }

        mont::GetFromTable(
            t, index_value_1 & 0xf, mult_radix_52[0], 20, valueLimit);
        mont::GetFromTable(
            t + 16 * 20, index_value_2 & 0xf, mult_radix_52[1], 20, valueLimit);

        AMM1024Parallel(
            sq_radix_52, sq_radix_52, mult_radix_52, modRadix52Bit, k0);

        for (Int64 i = 126; i >= 0; --i) {

            // first 4 bits
            for (Uint64 i = 0; i < winSize; i++) {
                AMS1024Parallel(sq_radix_52, sq_radix_52, modRadix52Bit, k0);
            }
            index_value_1 = exp_byte_ptr_1[i];
            index_value_2 = exp_byte_ptr_2[i];

            mont::GetFromTable(
                t, index_value_1 >> 4, mult_radix_52[0], 20, valueLimit);
            mont::GetFromTable(t + 16 * 20,
                               index_value_2 >> 4,
                               mult_radix_52[1],
                               20,
                               valueLimit);

            AMM1024Parallel(
                sq_radix_52, mult_radix_52, sq_radix_52, modRadix52Bit, k0);

            // next 4 bits
            for (Uint64 i = 0; i < winSize; i++) {
                AMS1024Parallel(sq_radix_52, sq_radix_52, modRadix52Bit, k0);
            }
            mont::GetFromTable(
                t, index_value_1 & 0xf, mult_radix_52[0], 20, valueLimit);

            mont::GetFromTable(t + 16 * 20,
                               index_value_2 & 0xf,
                               mult_radix_52[1],
                               20,
                               valueLimit);

            AMM1024Parallel(
                sq_radix_52, mult_radix_52, sq_radix_52, modRadix52Bit, k0);
        }

        AMM1024ReduceParallel(sq_radix_52, sq_radix_52, modRadix52Bit, k0);

        alcp::utils::PadBlock<Uint64>(res[0], 0LL, 16 * 8);
        mont::Rsa1024Radix52BitToBytes(res[0], sq_radix_52[0]);

        alcp::utils::PadBlock<Uint64>(res[1], 0LL, 16 * 8);
        mont::Rsa1024Radix52BitToBytes(res[1], sq_radix_52[1]);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::decryptUsingCRT(
        Uint64*              res,
        const Uint64*        inp,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ)
    {
        auto size = contextP.m_size;

        Uint64 buff_p[32];
        Uint64 buff_0_p[16];
        Uint64 buff_1_p[16];

        auto p_mod_radix_52_bit = contextP.m_mod_radix_52_bit.get();
        auto p_mod              = privKey.m_p.get();
        auto q_mod              = privKey.m_q.get();
        auto p_exp              = privKey.m_dp.get();
        auto q_mod_radix_52_bit = contextQ.m_mod_radix_52_bit.get();
        auto q_exp              = privKey.m_dq.get();
        auto r2_p               = contextP.m_r2.get();
        auto r2_q               = contextQ.m_r2.get();
        auto r2_radix_52_bit_p  = contextP.m_r2_radix_52_bit.get();
        auto r2_radix_52_bit_q  = contextQ.m_r2_radix_52_bit.get();
        auto qinv               = privKey.m_qinv.get();
        auto p_k0               = contextP.m_k0;
        auto q_k0               = contextQ.m_k0;

        // P reduction - ap
        alcp::utils::CopyChunk(buff_p, inp, 2048 / 8);

        MontReduceHalf(buff_0_p, buff_p, p_mod, p_k0);

        MontMultHalf(buff_0_p, buff_0_p, r2_p, p_mod, p_k0);

        // Q reduction - aq
        alcp::utils::CopyChunk(buff_p, inp, 2048 / 8);
        MontReduceHalf(buff_1_p, buff_p, q_mod, q_k0);
        MontMultHalf(buff_1_p, buff_1_p, r2_q, q_mod, q_k0);

        // Rsa1024BytesToRadix52Bit(r1_p_rdix_52_bit, r1_p);
        // ap = ap ^ dp mod p // aq = aq ^dq mod q
        Uint64* buff[2] = { buff_0_p, buff_1_p };
        Uint64* exp[2]  = { p_exp, q_exp };
        Uint64* mod[2]  = { p_mod_radix_52_bit, q_mod_radix_52_bit };
        Uint64* r2[2]   = { r2_radix_52_bit_p, r2_radix_52_bit_q };
        Uint64  k0[2]   = { p_k0, q_k0 };

        RSA2048MontgomeryExpConstantTimeParallel(buff, buff, exp, mod, r2, k0);

        // // aq = aq ^dq mod q
        // RSA2048MontgomeryExpConstantTime(buff_1_p,
        //                                  buff_1_p,
        //                                  q_exp,
        //                                  q_mod_radix_52_bit,
        //                                  r2_radix_52_bit_q,
        //                                  q_k0);

        // convert aq to aq mod p
        MontSub(buff_p, buff_1_p, p_mod, p_mod, size);

        // ap = (ap - aq) mod p
        MontSub(buff_0_p, buff_0_p, buff_p, p_mod, size);

        // convert qInv to qInv * r mod P
        MontMultHalf(res, qinv, r2_p, p_mod, p_k0);

        // qInv * r * ap * r^-1 mod P -> qInv * ap mod P
        // h = qInv * ap mod P
        MontMultHalf(buff_0_p, buff_0_p, res, p_mod, p_k0);

        alcp::utils::PadBlock<Uint64>(buff_p, 0LL, size * 8 * 2);

        // h * Q
        mul(buff_p, buff_0_p, size, q_mod, size);

        // res = aq + h*Q
        AddBigNum(res, size * 2, buff_p, buff_1_p, size);
        return;
    }

    template void archDecryptPrivate<KEY_SIZE_1024>(
        Uint8*               pText,
        const Uint64*        pEncTextBigNum,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ);

    template void archDecryptPrivate<KEY_SIZE_2048>(
        Uint8*               pText,
        const Uint64*        pEncTextBigNum,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ);

    template void archCreateContext<KEY_SIZE_1024>(MontContextBignum& context,
                                                   Uint64*            mod,
                                                   Uint64             size);

    template void archCreateContext<KEY_SIZE_2048>(MontContextBignum& context,
                                                   Uint64*            mod,
                                                   Uint64             size);
}} // namespace alcp::rsa::zen4
