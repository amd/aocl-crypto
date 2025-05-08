/*
 * Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
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
 * Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *       *	Redistributions of source code must retain copyright notices,
 *          this list of conditions and the following disclaimer.
 *
 *       *	Redistributions in binary form must reproduce the above
 *          copyright notice, this list of conditions and the following
 *          disclaimer in the documentation and/or other materials
 *          provided with the distribution.
 *
 *       *	Neither the name of the CRYPTOGAMS nor the names of its
 *          copyright holder and contributors may be used to endorse or
 *          promote products derived from this software without specific
 *          prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL), in which case the provisions of the GPL apply INSTEAD OF
 * those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <immintrin.h>

#include "alcp/digest/sha3_zen4.hh"
#include "alcp/utils/copy.hh"
#include "config.h"

// For SHA-3 standard refer
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

// Additionally this implementation uses __m128i matrix of size 5x3 to store the
// state, which helps eliminate use of permutation operation.

namespace alcp::digest { namespace zen4 {

    using alcp::utils::CopyBlock;

    // Constants
    static constexpr Uint8 cDim      = 5;
    static constexpr Uint8 cRegs     = 3;
    static constexpr Uint8 cRounds   = 24;
    static constexpr Uint8 cRounds12 = 12;
    // Constants

    static inline void load128Absorb128(__m128i&      dest_State,
                                        const Uint64* p_src_state,
                                        const Uint64* p_src)
    {
        dest_State = _mm_loadu_epi64(p_src_state);
        dest_State =
            _mm_xor_epi64(dest_State, _mm_lddqu_si128((const __m128i*)(p_src)));
    }

    static inline void load128Absorb64(__m128i&      dest_State,
                                       Uint64*       p_src_state,
                                       const Uint64* p_src)
    {
        (*p_src_state) ^= (*p_src);
        dest_State = _mm_loadu_epi64(p_src_state);
    }

    static inline void absorbRow(__m128i       state[cDim][cRegs],
                                 Uint64        para_state[cDim][cDim],
                                 const Uint64* pSrc,
                                 const Uint64  row)
    {
        load128Absorb128(state[row][0], &para_state[row][0], &pSrc[0]);
        load128Absorb128(state[row][1], &para_state[row][2], &pSrc[2]);
        state[row][2] = _mm_cvtsi64_si128(para_state[row][4] ^ pSrc[4]);
    }

    static inline void loadRow(__m128i      state[cDim][cRegs],
                               Uint64       para_state[cDim][cDim],
                               const Uint64 row)
    {
        state[row][0] = _mm_loadu_epi64(&para_state[row][0]);
        state[row][1] = _mm_loadu_epi64(&para_state[row][2]);
        state[row][2] = _mm_cvtsi64_si128(para_state[row][4]);
    }

    static inline void fFunction(Uint64        para_state[cDim][cDim],
                                 const Uint64* pSrc,
                                 const Uint64  chunk_size_u64)
    {
        // setting constants
        alignas(64) static const __m128i cRoundConstant[cRounds] = {
            _mm_set_epi64x(0x0, 0x0000000000000001),
            _mm_set_epi64x(0x0, 0x0000000000008082),
            _mm_set_epi64x(0x0, 0x800000000000808A),
            _mm_set_epi64x(0x0, 0x8000000080008000),
            _mm_set_epi64x(0x0, 0x000000000000808B),
            _mm_set_epi64x(0x0, 0x0000000080000001),
            _mm_set_epi64x(0x0, 0x8000000080008081),
            _mm_set_epi64x(0x0, 0x8000000000008009),
            _mm_set_epi64x(0x0, 0x000000000000008A),
            _mm_set_epi64x(0x0, 0x0000000000000088),
            _mm_set_epi64x(0x0, 0x0000000080008009),
            _mm_set_epi64x(0x0, 0x000000008000000A),
            _mm_set_epi64x(0x0, 0x000000008000808B),
            _mm_set_epi64x(0x0, 0x800000000000008B),
            _mm_set_epi64x(0x0, 0x8000000000008089),
            _mm_set_epi64x(0x0, 0x8000000000008003),
            _mm_set_epi64x(0x0, 0x8000000000008002),
            _mm_set_epi64x(0x0, 0x8000000000000080),
            _mm_set_epi64x(0x0, 0x000000000000800A),
            _mm_set_epi64x(0x0, 0x800000008000000A),
            _mm_set_epi64x(0x0, 0x8000000080008081),
            _mm_set_epi64x(0x0, 0x8000000000008080),
            _mm_set_epi64x(0x0, 0x0000000080000001),
            _mm_set_epi64x(0x0, 0x8000000080008008)
        };

        alignas(64) static const __m128i cRotate0[5][3] = {
            { _mm_set_epi64x(1, 0),
              _mm_set_epi64x(28, 62),
              _mm_set_epi64x(0, 27) },
            { _mm_set_epi64x(44, 36),
              _mm_set_epi64x(55, 6),
              _mm_set_epi64x(0, 20) },
            { _mm_set_epi64x(10, 3),
              _mm_set_epi64x(25, 43),
              _mm_set_epi64x(0, 39) },
            { _mm_set_epi64x(45, 41),
              _mm_set_epi64x(21, 15),
              _mm_set_epi64x(0, 8) },
            { _mm_set_epi64x(2, 18),
              _mm_set_epi64x(56, 61),
              _mm_set_epi64x(0, 14) }
        };

        alignas(64) static const __m128i cRotate1[5][3] = {
            { _mm_set_epi64x(44, 0),
              _mm_set_epi64x(21, 43),
              _mm_set_epi64x(0, 14) },
            { _mm_set_epi64x(1, 18),
              _mm_set_epi64x(25, 6),
              _mm_set_epi64x(0, 8) },
            { _mm_set_epi64x(2, 41),
              _mm_set_epi64x(55, 62),
              _mm_set_epi64x(0, 39) },
            { _mm_set_epi64x(45, 3),
              _mm_set_epi64x(28, 61),
              _mm_set_epi64x(0, 20) },
            { _mm_set_epi64x(10, 36),
              _mm_set_epi64x(56, 15),
              _mm_set_epi64x(0, 27) }
        };
        // setting constants

        // Loading data
        __m128i state[cDim][cRegs]{};

        /**
         * The only possible values of digest_len are 128, 224, 256, 384, and
         * 512 bits. Chunk size in bits is calculated as: 1600 - 2 * digest_len.
         * Hence, in terms of 64-bit words:
         * - When digest_len = 128, chunk_size_u64 = (1600 - 2 * 128) / 64 = 21
         * - When digest_len = 224, chunk_size_u64 = (1600 - 2 * 224) / 64 = 18
         * - When digest_len = 256, chunk_size_u64 = (1600 - 2 * 256) / 64 = 17
         * - When digest_len = 384, chunk_size_u64 = (1600 - 2 * 384) / 64 = 13
         * - When digest_len = 512, chunk_size_u64 = (1600 - 2 * 512) / 64 = 9
         * - And =0 in Sha3Finalize calls because we don't absorb any input in
         * the squeezing phase.
         */
        if (chunk_size_u64 == 9) {
            // SHA3-512
            // Row 0
            absorbRow(state, para_state, pSrc, 0);
            // Row 1
            load128Absorb128(state[1][0], &para_state[1][0], &pSrc[5]);
            load128Absorb128(state[1][1], &para_state[1][2], &pSrc[7]);
            state[1][2] = _mm_cvtsi64_si128(para_state[1][4]);
            // Row 2-4
            for (Uint64 i = 2; i < 5; i++) {
                loadRow(state, para_state, i);
            }
        } else if (chunk_size_u64 == 13) {
            // SHA3-384
            // Row 0
            absorbRow(state, para_state, pSrc, 0);
            // Row 1
            absorbRow(state, para_state, &pSrc[5], 1);
            // Row 2
            load128Absorb128(state[2][0], &para_state[2][0], &pSrc[10]);
            load128Absorb64(state[2][1], &para_state[2][2], &pSrc[12]);
            state[2][2] = _mm_cvtsi64_si128(para_state[2][4]);
            // Row 3
            loadRow(state, para_state, 3);
            loadRow(state, para_state, 4);
        } else if (chunk_size_u64 == 17) {
            // SHA3-256, SHAKE-256
            // Row 0
            absorbRow(state, para_state, pSrc, 0);
            // Row 1
            absorbRow(state, para_state, &pSrc[5], 1);
            // Row 2
            absorbRow(state, para_state, &pSrc[10], 2);
            // Row 3
            load128Absorb128(state[3][0], &para_state[3][0], &pSrc[15]);
            state[3][1] = _mm_loadu_epi64(&para_state[3][2]);
            state[3][2] = _mm_cvtsi64_si128(para_state[3][4]);
            // Row 4
            loadRow(state, para_state, 4);
        } else if (chunk_size_u64 == 18) {
            // SHA3-224
            // Row 0
            absorbRow(state, para_state, pSrc, 0);
            // Row 1
            absorbRow(state, para_state, &pSrc[5], 1);
            // Row 2
            absorbRow(state, para_state, &pSrc[10], 2);
            // Row 3
            load128Absorb128(state[3][0], &para_state[3][0], &pSrc[15]);
            load128Absorb64(state[3][1], &para_state[3][2], &pSrc[17]);
            state[3][2] = _mm_cvtsi64_si128(para_state[3][4]);
            // Row 4
            loadRow(state, para_state, 4);
        } else if (chunk_size_u64 == 21) {
            // SHAKE-128
            // Row 0
            absorbRow(state, para_state, pSrc, 0);
            // Row 1
            absorbRow(state, para_state, &pSrc[5], 1);
            // Row 2
            absorbRow(state, para_state, &pSrc[10], 2);
            // Row 3
            absorbRow(state, para_state, &pSrc[15], 3);
            // Row 4
            para_state[4][0] ^= pSrc[20];
            loadRow(state, para_state, 4);
        } else {
            // Calls from Sha3Finalize go here
            for (Uint64 i = 0; i < cDim; i++) {
                loadRow(state, para_state, i);
            }
        }
        // Loading data

        __m128i temp[cDim][cRegs];

        for (Uint64 k = 0; k < cRounds12; k++) {

            // _mm_shuffle_epi32({a,b}, 0x4E)
            // performs : {a,b} to {b,a}

            // _mm_mask_shuffle_epi32({b,a},0xC,{c,d},_MM_PERM_BAAA)
            // performs : {b,a}, {c,d} to {b,c}

            // _mm_mask_shuffle_epi32({a,b}, 0xC, {c,d}, _MM_PERM_DCAA)
            // performs : {a,b}, {c,d} to {a,d}

            // _mm_mask_shuffle_epi32({d,c}, 0x3, {a,b}, _MM_PERM_AADC);
            // performs : {d,c}, {a,b} to {b,c}

            /////////////////////////////// THETA even
            // temp[2][0...2] is C, temp[1][0...2] is D
            for (Uint64 i = 0; i < cRegs; i++) {
                temp[0][i] = _mm_ternarylogic_epi64(
                    state[0][i], state[1][i], state[2][i], 0x96);
                temp[0][i] = _mm_ternarylogic_epi64(
                    temp[0][i], state[3][i], state[4][i], 0x96);
            }

            // ROTATE C,D
            // Permute index for C : 4, 0, 1, 2, 3
            // Permute index for D : 1, 2, 3, 4, 0
            temp[3][0] = _mm_shuffle_epi32(temp[0][1], 0x4E);

            temp[2][0] = _mm_mask_shuffle_epi32(
                temp[0][2], 0xC, temp[0][0], _MM_PERM_BAAA);
            temp[2][1] = _mm_mask_shuffle_epi32(
                temp[3][0], 0x3, temp[0][0], _MM_PERM_AADC);
            temp[2][2] = temp[3][0];

            temp[1][0] = temp[2][1];
            temp[1][1] = _mm_mask_shuffle_epi32(
                temp[3][0], 0xC, temp[0][2], _MM_PERM_BAAA);
            temp[1][2] = temp[0][0];
            // ROTATE C,D

            for (Uint64 i = 0; i < cRegs; i++) {
                temp[1][i] = _mm_rol_epi64(temp[1][i], 1);
            }

            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = _mm_ternarylogic_epi64(
                        state[i][j], temp[2][j], temp[1][j], 0x96);
                }
            }
            /////////////////////////////// THETA even

            /////////////////////////////// RHO even
            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = _mm_rolv_epi64(state[i][j], cRotate0[i][j]);
                }
            }
            /////////////////////////////// RHO even

            /////////////////////////////// PI even
            // Row 0
            // Permute Idx for Row 0 : 0, 3, 1, 4, 2
            temp[0][0] = _mm_mask_shuffle_epi32(
                state[0][0], 0xC, state[0][1], _MM_PERM_DCAA);
            temp[0][1] =
                _mm_mask_shuffle_epi32(_mm_shuffle_epi32(state[0][0], 0x4E),
                                       0xC,
                                       state[0][2],
                                       _MM_PERM_BAAA);
            temp[0][2] = state[0][1];

            // Row 1
            // Permute Idx for Row 1 : 1, 4, 2, 0, 3
            state[1][0] = _mm_shuffle_epi32(state[1][0], 0x4E);
            temp[1][0]  = _mm_mask_shuffle_epi32(
                state[1][0], 0xC, state[1][2], _MM_PERM_BAAA);
            temp[1][1] = _mm_mask_shuffle_epi32(
                state[1][1], 0xC, state[1][0], _MM_PERM_DCAA);
            temp[1][2] = _mm_shuffle_epi32(state[1][1], 0x4E);

            // Row 2
            // Permute Idx for Row 2 : 2, 0, 3, 1, 4
            temp[2][0] = _mm_mask_shuffle_epi32(
                state[2][1], 0xC, state[2][0], _MM_PERM_BAAA);
            temp[2][1] = _mm_mask_shuffle_epi32(
                state[2][0], 0x3, state[2][1], _MM_PERM_AADC);
            temp[2][2] = state[2][2];

            // Row 3
            // Permute Idx for Row 3 : 3, 1, 4, 2, 0
            temp[3][0] = _mm_mask_shuffle_epi32(
                state[3][0], 0x3, state[3][1], _MM_PERM_AADC);
            temp[3][1] = _mm_mask_shuffle_epi32(
                state[3][2], 0xC, state[3][1], _MM_PERM_BAAA);
            temp[3][2] = state[3][0];

            // Row 4
            // Permute Idx for Row 4 : 4, 2, 0, 3, 1
            temp[4][0] = _mm_mask_shuffle_epi32(
                state[4][2], 0xC, state[4][1], _MM_PERM_BAAA);
            temp[4][1] = _mm_mask_shuffle_epi32(
                state[4][0], 0xC, state[4][1], _MM_PERM_DCAA);
            temp[4][2] = _mm_shuffle_epi32(state[4][0], 0x4E);

            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = temp[i][j];
                }
            }
            /////////////////////////////// PI even

            /////////////////////////////// CHI even
            for (Uint64 i = 0; i < cRegs; i++) {
                temp[0][i] = state[0][i];
                temp[1][i] = state[1][i];

                state[0][i] = _mm_ternarylogic_epi64(
                    state[0][i], state[1][i], state[2][i], 0xD2);
                state[1][i] = _mm_ternarylogic_epi64(
                    state[1][i], state[2][i], state[3][i], 0xD2);
                state[2][i] = _mm_ternarylogic_epi64(
                    state[2][i], state[3][i], state[4][i], 0xD2);
                state[3][i] = _mm_ternarylogic_epi64(
                    state[3][i], state[4][i], temp[0][i], 0xD2);
                state[4][i] = _mm_ternarylogic_epi64(
                    state[4][i], temp[0][i], temp[1][i], 0xD2);
            }
            /////////////////////////////// CHI even

            /////////////////////////////// IOTA even
            state[0][0] = _mm_xor_epi64(state[0][0], cRoundConstant[k * 2]);
            /////////////////////////////// IOTA even

            /////////////////////////////// HARMONIZE
            // Harmonize converts state as follows :

            // a b c d e
            // f g h i j
            // k l m n o
            // p q r s t
            // u v w x y

            // to

            // a g m s y
            // e f l r x
            // d j k q w
            // c i o p v
            // b h n t u

            // Row 0
            temp[0][0] = _mm_mask_shuffle_epi32(
                state[0][0], 0xC, state[1][0], _MM_PERM_DCAA);
            temp[0][1] = _mm_mask_shuffle_epi32(
                state[2][1], 0xC, state[3][1], _MM_PERM_DCAA);
            temp[0][2] = state[4][2];

            // Row 1
            temp[1][0] = _mm_mask_shuffle_epi32(
                state[0][2], 0xC, state[1][0], _MM_PERM_BAAA);
            temp[1][1] =
                _mm_mask_shuffle_epi32(_mm_shuffle_epi32(state[2][0], 0x4E),
                                       0xC,
                                       state[3][1],
                                       _MM_PERM_BAAA);
            temp[1][2] = _mm_shuffle_epi32(state[4][1], 0x4E);

            // Row 2
            temp[2][0] =
                _mm_mask_shuffle_epi32(_mm_shuffle_epi32(state[0][1], 0x4E),
                                       0xC,
                                       state[1][2],
                                       _MM_PERM_BAAA);
            temp[2][1] = _mm_mask_shuffle_epi32(
                state[2][0], 0xC, state[3][0], _MM_PERM_DCAA);
            temp[2][2] = state[4][1];

            // Row 3
            temp[3][0] = _mm_mask_shuffle_epi32(
                state[0][1], 0xC, state[1][1], _MM_PERM_DCAA);
            temp[3][1] = _mm_mask_shuffle_epi32(
                state[2][2], 0xC, state[3][0], _MM_PERM_BAAA);
            temp[3][2] = _mm_shuffle_epi32(state[4][0], 0x4E);

            // Row 4
            temp[4][0] =
                _mm_mask_shuffle_epi32(_mm_shuffle_epi32(state[0][0], 0x4E),
                                       0xC,
                                       state[1][1],
                                       _MM_PERM_BAAA);
            temp[4][1] =
                _mm_mask_shuffle_epi32(_mm_shuffle_epi32(state[2][1], 0x4E),
                                       0xC,
                                       state[3][2],
                                       _MM_PERM_BAAA);
            temp[4][2] = state[4][0];

            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = temp[i][j];
                }
            }
            /////////////////////////////// HARMONIZE

            /////////////////////////////// THETA odd round
            // temp[2][0...2] is C, temp[1][0...2] is D
            for (Uint64 i = 0; i < cRegs; i++) {
                temp[0][i] = _mm_ternarylogic_epi64(
                    state[0][i], state[1][i], state[2][i], 0x96);
                temp[0][i] = _mm_ternarylogic_epi64(
                    temp[0][i], state[3][i], state[4][i], 0x96);
            }

            // ROTATE C,D
            // Permute index for C : 4, 0, 1, 2, 3
            // Permute index for D : 1, 2, 3, 4, 0
            temp[3][0] = _mm_shuffle_epi32(temp[0][1], 0x4E);

            temp[2][0] = _mm_mask_shuffle_epi32(
                temp[0][2], 0xC, temp[0][0], _MM_PERM_BAAA);
            temp[2][1] = _mm_mask_shuffle_epi32(
                temp[3][0], 0x3, temp[0][0], _MM_PERM_AADC);
            temp[2][2] = temp[3][0];

            temp[1][0] = temp[2][1];
            temp[1][1] = _mm_mask_shuffle_epi32(
                temp[3][0], 0xC, temp[0][2], _MM_PERM_BAAA);
            temp[1][2] = temp[0][0];
            // ROTATE C,D

            for (Uint64 i = 0; i < cRegs; i++) {
                temp[1][i] = _mm_rol_epi64(temp[1][i], 1);
            }

            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = _mm_ternarylogic_epi64(
                        state[i][j], temp[2][j], temp[1][j], 0x96);
                }
            }
            /////////////////////////////// THETA odd round

            /////////////////////////////// RHO odd round
            for (Uint64 i = 0; i < cDim; i++) {
                for (Uint64 j = 0; j < cRegs; j++) {
                    state[i][j] = _mm_rolv_epi64(state[i][j], cRotate1[i][j]);
                }
            }
            /////////////////////////////// RHO odd round

            /////////////////////////////// PI + CHI + IOTA - odd round
            // Row 0
            temp[0][1] = _mm_shuffle_epi32(state[0][1], 0x4E);
            temp[1][0] = state[0][0];
            // Permute Idx for operand 2 : 1, 2, 3, 4, 0
            // Permute Idx for operand 3 : 2, 3, 4, 0, 1
            state[0][0] = _mm_ternarylogic_epi64(
                _mm_xor_epi64(state[0][0], cRoundConstant[k * 2 + 1]),
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0x3, state[0][0], _MM_PERM_AADC),
                state[0][1],
                0xD2);
            state[0][1] = _mm_ternarylogic_epi64(
                state[0][1],
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0xC, state[0][2], _MM_PERM_BAAA),
                _mm_mask_shuffle_epi32(
                    state[0][2], 0xC, temp[1][0], _MM_PERM_BAAA),
                0xD2);
            state[0][2] =
                _mm_ternarylogic_epi64(state[0][2],
                                       temp[1][0],
                                       _mm_shuffle_epi32(temp[1][0], 0x4E),
                                       0xD2);

            // save state[3] for state[1]
            temp[3][0] = state[3][0];
            temp[3][1] = state[3][1];
            temp[3][2] = state[3][2];
            // save state[3] for state[1]

            // Row 3
            temp[0][1] = _mm_shuffle_epi32(state[4][1], 0x4E);
            temp[1][0] = _mm_mask_shuffle_epi32(
                temp[0][1], 0x3, state[4][0], _MM_PERM_AADC);
            // Permute Idx for operand 1 : 4, 0, 1, 2, 3
            // Permute Idx for operand 3 : 1, 2, 3, 4, 0
            state[3][0] = _mm_ternarylogic_epi64(
                _mm_mask_shuffle_epi32(
                    state[4][2], 0xC, state[4][0], _MM_PERM_BAAA),
                state[4][0],
                temp[1][0],
                0xD2);
            state[3][1] = _mm_ternarylogic_epi64(
                temp[1][0],
                state[4][1],
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0xC, state[4][2], _MM_PERM_BAAA),
                0xD2);
            state[3][2] = _mm_ternarylogic_epi64(
                temp[0][1], state[4][2], state[4][0], 0xD2);

            // Row 4
            temp[0][0] = _mm_shuffle_epi32(state[2][0], 0x4E);
            temp[0][1] = _mm_shuffle_epi32(state[2][1], 0x4E);
            temp[1][0] = _mm_mask_shuffle_epi32(
                state[2][2], 0xC, temp[0][0], _MM_PERM_DCAA);
            // Permute Idx for operand 1 : 2, 3, 4, 0, 1
            // Permute Idx for operand 2 : 3, 4, 0, 1, 2
            // Permute Idx for operand 3 : 4, 0, 1, 2, 3
            state[4][0] = _mm_ternarylogic_epi64(
                state[2][1],
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0xC, state[2][2], _MM_PERM_BAAA),
                temp[1][0],
                0xD2);
            state[4][1] = _mm_ternarylogic_epi64(
                temp[1][0],
                state[2][0],
                _mm_mask_shuffle_epi32(
                    temp[0][0], 0xC, temp[0][1], _MM_PERM_DCAA),
                0xD2);
            state[4][2] = _mm_ternarylogic_epi64(
                temp[0][0], state[2][1], temp[0][1], 0xD2);

            // Row 2
            temp[0][1] = _mm_shuffle_epi32(state[1][1], 0x4E);
            temp[1][0] = _mm_mask_shuffle_epi32(
                temp[0][1], 0xC, state[1][2], _MM_PERM_BAAA);
            // Permute Idx for operand 1 : 1, 2, 3, 4, 0
            // Permute Idx for operand 2 : 2, 3, 4, 0, 1
            // Permute Idx for operand 3 : 3, 4, 0, 1, 2
            state[2][0] = _mm_ternarylogic_epi64(
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0x3, state[1][0], _MM_PERM_AADC),
                state[1][1],
                temp[1][0],
                0xD2);
            state[2][1] = _mm_ternarylogic_epi64(
                temp[1][0],
                _mm_mask_shuffle_epi32(
                    state[1][2], 0xC, state[1][0], _MM_PERM_BAAA),
                state[1][0],
                0xD2);
            state[2][2] =
                _mm_ternarylogic_epi64(state[1][0],
                                       _mm_shuffle_epi32(state[1][0], 0x4E),
                                       state[1][1],
                                       0xD2);

            // Row 1
            temp[0][1] = _mm_shuffle_epi32(temp[3][1], 0x4E);
            // Permute Idx for operand 1 : 3, 4, 0, 1, 2
            // Permute Idx for operand 2 : 4, 0, 1, 2, 3
            state[1][0] = _mm_ternarylogic_epi64(
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0xC, temp[3][2], _MM_PERM_BAAA),
                _mm_mask_shuffle_epi32(
                    temp[3][2], 0xC, temp[3][0], _MM_PERM_BAAA),
                temp[3][0],
                0xD2);
            state[1][1] = _mm_ternarylogic_epi64(
                temp[3][0],
                _mm_mask_shuffle_epi32(
                    temp[0][1], 0x3, temp[3][0], _MM_PERM_AADC),
                temp[3][1],
                0xD2);
            state[1][2] = _mm_ternarylogic_epi64(
                temp[3][1], temp[0][1], temp[3][2], 0xD2);
            /////////////////////////////// PI + CHI + IOTA - odd round
        }

        // Storing data
        for (Uint64 i = 0; i < cDim; i++) {
            _mm_storeu_epi64(&para_state[i][0], state[i][0]);
            _mm_storeu_epi64(&para_state[i][2], state[i][1]);
            _mm_storeu_si64(&para_state[i][4], state[i][2]);
        }
        // Storing data
    }

    alc_error_t Sha3Update(Uint64* state,
                           Uint64* pSrc,
                           Uint64  msg_size,
                           Uint64  chunk_size)
    {

        Uint32 num_chunks     = msg_size / chunk_size;
        Uint64 chunk_size_u64 = chunk_size / 8;

        for (Uint32 i = 0; i < num_chunks; i++) {
            fFunction(
                reinterpret_cast<Uint64(*)[cDim]>(state), pSrc, chunk_size_u64);
            pSrc += chunk_size_u64;
        }

        return ALC_ERROR_NONE;
    }

    void Sha3Finalize(Uint8*  state,
                      Uint8*  hash,
                      Uint64  hash_size,
                      Uint64  chunk_size,
                      Uint64& index)
    {
        Uint64 rem = chunk_size - index;

        if (hash_size <= rem) {
            CopyBlock(hash, state + index, hash_size);
            index = (index + hash_size);
            return;
        }
        CopyBlock(hash, state + index, rem);
        hash_size -= rem;
        hash += rem;
        index = 0;

        while (hash_size) {
            fFunction(reinterpret_cast<Uint64(*)[cDim]>(state), nullptr, 0);
            if (hash_size <= chunk_size) {
                CopyBlock(hash, state + index, hash_size);
                index = (index + hash_size);
                return;
            }
            CopyBlock(hash, state, chunk_size);
            hash_size -= chunk_size;
            hash += chunk_size;
        }
    }
}} // namespace alcp::digest::zen4