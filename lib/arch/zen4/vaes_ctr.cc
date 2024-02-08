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

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/types.hh"

#include "avx512.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher::vaes512 {

static inline void
ctrInitx(__m512i&     c1,
         const Uint8* pIv,
         __m512i&     one_lo,
         __m512i&     one_x,
         __m512i&     two_x,
         __m512i&     three_x,
         __m512i&     four_x,
         __m512i&     swap_ctr)
{

    one_lo = alcp_set_epi32(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0);
    one_x  = alcp_set_epi32(0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0);
    two_x  = alcp_set_epi32(0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0);
    three_x =
        alcp_set_epi32(0, 12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0);
    four_x = alcp_set_epi32(0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0);

    //
    // counterblock :: counter 4 bytes: IV 8 bytes : Nonce 4 bytes
    // as per spec: http://www.faqs.org/rfcs/rfc3686.html
    //

    // counter 4 bytes are arranged in reverse order
    // for counter increment
    swap_ctr = _mm512_set_epi32(0x08090a0b,
                                0x0c0d0e0f,
                                0x07060504,
                                0x03020100,
                                0x08090a0b, // Repeats here
                                0x0c0d0e0f,
                                0x07060504,
                                0x03020100,
                                0x08090a0b, // Repeats here
                                0x0c0d0e0f,
                                0x07060504,
                                0x03020100,
                                0x08090a0b, // Repeats here
                                0x0c0d0e0f,
                                0x07060504,
                                0x03020100);
    // nonce counter
    c1 = _mm512_broadcast_i64x2(*((__m128i*)pIv));
    c1 = alcp_shuffle_epi8(c1, swap_ctr);

    __m512i onehi =
        _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0);
    c1 = alcp_add_epi32(c1, onehi);
}

static inline Uint64
ctrBlk128(const __m512i* p_in_x,
          __m512i*       p_out_x,
          Uint64         blocks,
          const __m128i* pkey128,
          const Uint8*   pIv,
          int            nRounds,
          Uint8          factor)
{
    __m512i a1, a2, a3, a4;
    __m512i b1, b2, b3, b4;
    __m512i c1, c2, c3, c4, swap_ctr;
    __m512i one_lo, one_x, two_x, three_x, four_x;

    ctrInitx(c1, pIv, one_lo, one_x, two_x, three_x, four_x, swap_ctr);

    Uint64 blockCount4 = factor << 2;
    Uint64 blockCount2 = factor << 1;
    Uint64 blockCount1 = factor;

    sKeys keys{};
    alcp_load_key_zmm_10rounds(pkey128, keys);

    for (; blocks >= blockCount4; blocks -= blockCount4) {

        c2 = alcp_add_epi64(c1, one_x);
        c3 = alcp_add_epi64(c1, two_x);
        c4 = alcp_add_epi64(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncryptNoLoad_4x512Rounds10(b1, b2, b3, b4, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi64(c1, four_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount2; blocks -= blockCount2) {
        c2 = alcp_add_epi64(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        AesEncryptNoLoad_2x512Rounds10(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi64(c1, two_x);
        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount1; blocks -= blockCount1) {
        a1 = alcp_loadu(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds10(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    for (; blocks != 0; blocks--) {
        a1 = alcp_loadu_128(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds10(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_lo);

        alcp_storeu_128(p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // clear all keys in registers.
    alcp_clear_keys_zmm_10rounds(keys);

    return blocks;
}

static inline Uint64
ctrBlk192(const __m512i* p_in_x,
          __m512i*       p_out_x,
          Uint64         blocks,
          const __m128i* pkey128,
          const Uint8*   pIv,
          int            nRounds,
          Uint8          factor)
{
    __m512i a1, a2, a3, a4;
    __m512i b1, b2, b3, b4;
    __m512i c1, c2, c3, c4, swap_ctr;
    __m512i one_lo, one_x, two_x, three_x, four_x;

    ctrInitx(c1, pIv, one_lo, one_x, two_x, three_x, four_x, swap_ctr);

    Uint64 blockCount4 = factor << 2;
    Uint64 blockCount2 = factor << 1;
    Uint64 blockCount1 = factor;

    sKeys keys{};
    alcp_load_key_zmm_12rounds(pkey128, keys);

    for (; blocks >= blockCount4; blocks -= blockCount4) {

        c2 = alcp_add_epi64(c1, one_x);
        c3 = alcp_add_epi64(c1, two_x);
        c4 = alcp_add_epi64(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncryptNoLoad_4x512Rounds12(b1, b2, b3, b4, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi64(c1, four_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount2; blocks -= blockCount2) {
        c2 = alcp_add_epi64(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        AesEncryptNoLoad_2x512Rounds12(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi64(c1, two_x);
        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount1; blocks -= blockCount1) {
        a1 = alcp_loadu(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds12(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    for (; blocks != 0; blocks--) {
        a1 = alcp_loadu_128(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds12(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_lo);

        alcp_storeu_128(p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // clear all keys in registers.
    alcp_clear_keys_zmm_12rounds(keys);

    return blocks;
}

static inline Uint64
ctrBlk256(const __m512i* p_in_x,
          __m512i*       p_out_x,
          Uint64         blocks,
          const __m128i* pkey128,
          const Uint8*   pIv,
          int            nRounds,
          Uint8          factor)
{
    __m512i a1, a2, a3, a4;
    __m512i b1, b2, b3, b4;
    __m512i c1, c2, c3, c4, swap_ctr;
    __m512i one_lo, one_x, two_x, three_x, four_x;

    ctrInitx(c1, pIv, one_lo, one_x, two_x, three_x, four_x, swap_ctr);

    Uint64 blockCount4 = factor << 2;
    Uint64 blockCount2 = factor << 1;
    Uint64 blockCount1 = factor;

    sKeys keys{};
    alcp_load_key_zmm_14rounds(pkey128, keys);

    for (; blocks >= blockCount4; blocks -= blockCount4) {

        c2 = alcp_add_epi64(c1, one_x);
        c3 = alcp_add_epi64(c1, two_x);
        c4 = alcp_add_epi64(c1, three_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);
        a3 = alcp_loadu(p_in_x + 2);
        a4 = alcp_loadu(p_in_x + 3);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);
        b3 = alcp_shuffle_epi8(c3, swap_ctr);
        b4 = alcp_shuffle_epi8(c4, swap_ctr);

        AesEncryptNoLoad_4x512Rounds14(b1, b2, b3, b4, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);
        a3 = alcp_xor(b3, a3);
        a4 = alcp_xor(b4, a4);

        // increment counter
        c1 = alcp_add_epi64(c1, four_x);

        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);
        alcp_storeu(p_out_x + 2, a3);
        alcp_storeu(p_out_x + 3, a4);

        p_in_x += 4;
        p_out_x += 4;
    }

    for (; blocks >= blockCount2; blocks -= blockCount2) {
        c2 = alcp_add_epi64(c1, one_x);

        a1 = alcp_loadu(p_in_x);
        a2 = alcp_loadu(p_in_x + 1);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);
        b2 = alcp_shuffle_epi8(c2, swap_ctr);

        AesEncryptNoLoad_2x512Rounds14(b1, b2, keys);

        a1 = alcp_xor(b1, a1);
        a2 = alcp_xor(b2, a2);

        // increment counter
        c1 = alcp_add_epi64(c1, two_x);
        alcp_storeu(p_out_x, a1);
        alcp_storeu(p_out_x + 1, a2);

        p_in_x += 2;
        p_out_x += 2;
    }

    for (; blocks >= blockCount1; blocks -= blockCount1) {
        a1 = alcp_loadu(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds14(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_x);

        alcp_storeu(p_out_x, a1);

        p_in_x += 1;
        p_out_x += 1;
    }

    // residual block=1 when factor = 2, load and store only lower half.
    for (; blocks != 0; blocks--) {
        a1 = alcp_loadu_128(p_in_x);

        // re-arrange as per spec
        b1 = alcp_shuffle_epi8(c1, swap_ctr);

        AesEncryptNoLoad_1x512Rounds14(b1, keys);

        a1 = alcp_xor(b1, a1);

        // increment counter
        c1 = alcp_add_epi64(c1, one_lo);

        alcp_storeu_128(p_out_x, a1);
        p_in_x  = (__m512i*)(((__uint128_t*)p_in_x) + 1);
        p_out_x = (__m512i*)(((__uint128_t*)p_out_x) + 1);
    }

    // clear all keys in registers.
    alcp_clear_keys_zmm_14rounds(keys);

    return blocks;
}

Uint64
ctrProcessAvx512_128(const Uint8*   p_in_x,
                     Uint8*         p_out_x,
                     Uint64         blocks,
                     const __m128i* pkey128,
                     const Uint8*   pIv,
                     int            nRounds)
{

    auto p_in_512  = reinterpret_cast<const __m512i*>(p_in_x);
    auto p_out_512 = reinterpret_cast<__m512i*>(p_out_x);

    return ctrBlk128(p_in_512, p_out_512, blocks, pkey128, pIv, nRounds, 4);
}

Uint64
ctrProcessAvx512_192(const Uint8*   p_in_x,
                     Uint8*         p_out_x,
                     Uint64         blocks,
                     const __m128i* pkey128,
                     const Uint8*   pIv,
                     int            nRounds)
{

    auto p_in_512  = reinterpret_cast<const __m512i*>(p_in_x);
    auto p_out_512 = reinterpret_cast<__m512i*>(p_out_x);

    return ctrBlk192(p_in_512, p_out_512, blocks, pkey128, pIv, nRounds, 4);
}

Uint64
ctrProcessAvx512_256(const Uint8*   p_in_x,
                     Uint8*         p_out_x,
                     Uint64         blocks,
                     const __m128i* pkey128,
                     const Uint8*   pIv,
                     int            nRounds)
{

    auto p_in_512  = reinterpret_cast<const __m512i*>(p_in_x);
    auto p_out_512 = reinterpret_cast<__m512i*>(p_out_x);

    return ctrBlk256(p_in_512, p_out_512, blocks, pkey128, pIv, nRounds, 4);
}

} // namespace alcp::cipher::vaes512