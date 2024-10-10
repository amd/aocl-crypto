/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#pragma once

#include <immintrin.h>

#include "alcp/error.h"
#include <avx512fintrin.h>

namespace alcp::cipher { namespace vaes512 {

    alc_error_t ExpandKeys(const Uint8* pUserKey,
                           Uint8*       pEncKey,
                           Uint8*       pDecKey,
                           int          nRounds);

    // ctr APIs for vaes
    void ctrInit(__m512i&     c1,
                 const Uint8* pIv,
                 __m512i&     onelo,
                 __m512i&     one_x,
                 __m512i&     two_x,
                 __m512i&     three_x,
                 __m512i&     four_x,
                 __m512i&     swap_ctr);

    // Encrypt Begins here
    /* 1 x 4 block at a time */
    static inline void AesEncrypt(__m512i*       blk0,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey += 1; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesenc_epi128(b0, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);
            b0    = _mm512_aesenc_epi128(b0, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0    = _mm512_aesenc_epi128(b0, rkey1);
        *blk0 = _mm512_aesenclast_epi128(b0, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 2 x 4 blocks at a time */
    static inline void AesEncrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesenc_epi128(b0, rkey1);
            b1    = _mm512_aesenc_epi128(b1, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesenc_epi128(b0, rkey0);
            b1    = _mm512_aesenc_epi128(b1, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesenc_epi128(b0, rkey1);
        b1 = _mm512_aesenc_epi128(b1, rkey1);

        *blk0 = _mm512_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesenclast_epi128(b1, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 3 x 4 blocks at a time */
    static inline void AesEncrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  __m512i*       blk2,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);
        __m512i b2 = _mm512_xor_si512(*blk2, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesenc_epi128(b0, rkey1);
            b1    = _mm512_aesenc_epi128(b1, rkey1);
            b2    = _mm512_aesenc_epi128(b2, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesenc_epi128(b0, rkey0);
            b1    = _mm512_aesenc_epi128(b1, rkey0);
            b2    = _mm512_aesenc_epi128(b2, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesenc_epi128(b0, rkey1);
        b1 = _mm512_aesenc_epi128(b1, rkey1);
        b2 = _mm512_aesenc_epi128(b2, rkey1);

        *blk0 = _mm512_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesenclast_epi128(b1, rkey0);
        *blk2 = _mm512_aesenclast_epi128(b2, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 4 x 4 blocks at a time */
    static inline void AesEncrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  __m512i*       blk2,
                                  __m512i*       blk3,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int     nr;
        __m512i rkey0, rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);
        __m512i b2 = _mm512_xor_si512(*blk2, rkey0);
        __m512i b3 = _mm512_xor_si512(*blk3, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesenc_epi128(b0, rkey1);
            b1    = _mm512_aesenc_epi128(b1, rkey1);
            b2    = _mm512_aesenc_epi128(b2, rkey1);
            b3    = _mm512_aesenc_epi128(b3, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesenc_epi128(b0, rkey0);
            b1    = _mm512_aesenc_epi128(b1, rkey0);
            b2    = _mm512_aesenc_epi128(b2, rkey0);
            b3    = _mm512_aesenc_epi128(b3, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesenc_epi128(b0, rkey1);
        b1 = _mm512_aesenc_epi128(b1, rkey1);
        b2 = _mm512_aesenc_epi128(b2, rkey1);
        b3 = _mm512_aesenc_epi128(b3, rkey1);

        *blk0 = _mm512_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesenclast_epi128(b1, rkey0);
        *blk2 = _mm512_aesenclast_epi128(b2, rkey0);
        *blk3 = _mm512_aesenclast_epi128(b3, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    // From here decrypt starts

    static inline void AesDecrypt(__m512i*       blk0,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey += 1; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesdec_epi128(b0, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);
            b0    = _mm512_aesdec_epi128(b0, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0    = _mm512_aesdec_epi128(b0, rkey1);
        *blk0 = _mm512_aesdeclast_epi128(b0, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 2 x 4 blocks at a time */
    static inline void AesDecrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  const __m128i* pKey, /* Round key */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesdec_epi128(b0, rkey1);
            b1    = _mm512_aesdec_epi128(b1, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesdec_epi128(b0, rkey0);
            b1    = _mm512_aesdec_epi128(b1, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesdec_epi128(b0, rkey1);
        b1 = _mm512_aesdec_epi128(b1, rkey1);

        *blk0 = _mm512_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesdeclast_epi128(b1, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 3 x 4 blocks at a time */
    static inline void AesDecrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  __m512i*       blk2,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int nr;

        __m512i rkey0;
        __m512i rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);
        __m512i b2 = _mm512_xor_si512(*blk2, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesdec_epi128(b0, rkey1);
            b1    = _mm512_aesdec_epi128(b1, rkey1);
            b2    = _mm512_aesdec_epi128(b2, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesdec_epi128(b0, rkey0);
            b1    = _mm512_aesdec_epi128(b1, rkey0);
            b2    = _mm512_aesdec_epi128(b2, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesdec_epi128(b0, rkey1);
        b1 = _mm512_aesdec_epi128(b1, rkey1);
        b2 = _mm512_aesdec_epi128(b2, rkey1);

        *blk0 = _mm512_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesdeclast_epi128(b1, rkey0);
        *blk2 = _mm512_aesdeclast_epi128(b2, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    /* 4 x 4 blocks at a time */
    static inline void AesDecrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  __m512i*       blk2,
                                  __m512i*       blk3,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int     nr;
        __m512i rkey0, rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);
        __m512i b2 = _mm512_xor_si512(*blk2, rkey0);
        __m512i b3 = _mm512_xor_si512(*blk3, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0    = _mm512_aesdec_epi128(b0, rkey1);
            b1    = _mm512_aesdec_epi128(b1, rkey1);
            b2    = _mm512_aesdec_epi128(b2, rkey1);
            b3    = _mm512_aesdec_epi128(b3, rkey1);
            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0    = _mm512_aesdec_epi128(b0, rkey0);
            b1    = _mm512_aesdec_epi128(b1, rkey0);
            b2    = _mm512_aesdec_epi128(b2, rkey0);
            b3    = _mm512_aesdec_epi128(b3, rkey0);
            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesdec_epi128(b0, rkey1);
        b1 = _mm512_aesdec_epi128(b1, rkey1);
        b2 = _mm512_aesdec_epi128(b2, rkey1);
        b3 = _mm512_aesdec_epi128(b3, rkey1);

        *blk0 = _mm512_aesdeclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesdeclast_epi128(b1, rkey0);
        *blk2 = _mm512_aesdeclast_epi128(b2, rkey0);
        *blk3 = _mm512_aesdeclast_epi128(b3, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

    static inline void AesEncrypt(__m512i*       blk0,
                                  __m512i*       blk1,
                                  __m512i*       blk2,
                                  __m512i*       blk3,
                                  __m512i*       blk4,
                                  __m512i*       blk5,
                                  const __m128i* pKey, /* Round keys */
                                  int            nRounds)
    {
        int     nr;
        __m512i rkey0, rkey1;

        rkey0 = _mm512_broadcast_i64x2(pKey[0]);
        rkey1 = _mm512_broadcast_i64x2(pKey[1]);

        __m512i b0 = _mm512_xor_si512(*blk0, rkey0);
        __m512i b1 = _mm512_xor_si512(*blk1, rkey0);
        __m512i b2 = _mm512_xor_si512(*blk2, rkey0);
        __m512i b3 = _mm512_xor_si512(*blk3, rkey0);

        __m512i b4 = _mm512_xor_si512(*blk4, rkey0);
        __m512i b5 = _mm512_xor_si512(*blk5, rkey0);

        rkey0 = _mm512_broadcast_i64x2(pKey[2]);

        for (nr = 2, pKey++; nr < nRounds; nr += 2, pKey += 2) {
            b0 = _mm512_aesenc_epi128(b0, rkey1);
            b1 = _mm512_aesenc_epi128(b1, rkey1);
            b2 = _mm512_aesenc_epi128(b2, rkey1);
            b3 = _mm512_aesenc_epi128(b3, rkey1);

            b4 = _mm512_aesenc_epi128(b4, rkey1);
            b5 = _mm512_aesenc_epi128(b5, rkey1);

            rkey1 = _mm512_broadcast_i64x2(pKey[2]);

            b0 = _mm512_aesenc_epi128(b0, rkey0);
            b1 = _mm512_aesenc_epi128(b1, rkey0);
            b2 = _mm512_aesenc_epi128(b2, rkey0);
            b3 = _mm512_aesenc_epi128(b3, rkey0);

            b4 = _mm512_aesenc_epi128(b4, rkey0);
            b5 = _mm512_aesenc_epi128(b5, rkey0);

            rkey0 = _mm512_broadcast_i64x2(pKey[3]);
        }

        b0 = _mm512_aesenc_epi128(b0, rkey1);
        b1 = _mm512_aesenc_epi128(b1, rkey1);
        b2 = _mm512_aesenc_epi128(b2, rkey1);
        b3 = _mm512_aesenc_epi128(b3, rkey1);
        b4 = _mm512_aesenc_epi128(b4, rkey1);
        b5 = _mm512_aesenc_epi128(b5, rkey1);

        *blk0 = _mm512_aesenclast_epi128(b0, rkey0);
        *blk1 = _mm512_aesenclast_epi128(b1, rkey0);
        *blk2 = _mm512_aesenclast_epi128(b2, rkey0);
        *blk3 = _mm512_aesenclast_epi128(b3, rkey0);
        *blk4 = _mm512_aesenclast_epi128(b4, rkey0);
        *blk5 = _mm512_aesenclast_epi128(b5, rkey0);

        rkey0 = _mm512_setzero_si512();
        rkey1 = _mm512_setzero_si512();
    }

}} // namespace alcp::cipher::vaes512
