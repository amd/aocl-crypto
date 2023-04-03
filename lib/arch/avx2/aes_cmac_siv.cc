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

#include "alcp/base.hh"
#include "alcp/cipher/aes_cmac_siv_arch.hh"
#include "alcp/utils/copy.hh"
#include "immintrin.h"

namespace alcp::cipher::avx2 {

inline void
left_shift(__m128i& memory)
{
    __m128i reg      = _mm_setzero_si128();
    int     mask_bit = 0;

    __m128i shuffle_mask =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    // Reverse the bytes for Uint64 correctly from Uint8
    memory = _mm_shuffle_epi8(memory, shuffle_mask);

    reg                = _mm_slli_epi64(memory, 1);
    mask_bit           = _mm_movemask_epi8(memory);
    const int cLostBit = mask_bit & 0x80;
    if (cLostBit) {
        reg = _mm_add_epi64(
            reg, _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0));
    }

    // Reverse the bytes for Uint8 correctly from Uint64
    memory = _mm_shuffle_epi8(reg, shuffle_mask);
}

void
dbl(Uint8 data[])
{
    __m128i data128 = _mm_load_si128(reinterpret_cast<__m128i*>(data));
    bool    msb     = _mm_movemask_epi8(data128) & 0x01;

    // clang-format off
    __m128i rb      = _mm_set_epi8(static_cast<Int8>(0x87),0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0);
    // clang-format on
    left_shift(data128);
    if (msb) {
        data128 = _mm_xor_si128(data128, rb);
    }
    _mm_store_si128(reinterpret_cast<__m128i*>(data), data128);
}

void
processAad(Uint8                            cmacTemp[],
           std::vector<std::vector<Uint8>>& m_additionalDataProcessed,
           Uint64                           m_additionalDataProcessedSize)
{
    __m128i data1_128 = _mm_load_si128(reinterpret_cast<__m128i*>(cmacTemp));
    __m128i rb        = _mm_set_epi8(
        static_cast<Int8>(0x87), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    for (Uint64 i = 0; i < m_additionalDataProcessedSize; i++) {
        __m128i data2_128 = _mm_load_si128(
            reinterpret_cast<__m128i*>(&m_additionalDataProcessed.at(i).at(0)));
        bool msb = _mm_movemask_epi8(data1_128) & 0x01;

        left_shift(data1_128);
        if (msb) {
            data1_128 = _mm_xor_si128(data1_128, rb);
        }
        data1_128 = _mm_xor_si128(data1_128, data2_128);
    }
    _mm_store_si128(reinterpret_cast<__m128i*>(cmacTemp), data1_128);
}

} // namespace alcp::cipher::avx2