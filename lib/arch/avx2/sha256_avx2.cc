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

#include "digest.hh"
#include "error.hh"
#include <x86intrin.h>

#define SHA256_CHUNK_NUM_VECT_AVX                                              \
    4 // Number of mm registers needed to load an input chunk
#define SHA256_CHUNK_NUM_VECT_AVX2                                             \
    2 // Number of mm registers needed to load an input chunk
#define SHA256_MSG_SCH_NUM_VECT_AVX                                            \
    16 // Number of registers needed for accomodating the message scheduling
       // array
#define SHA256_MSG_SCH_NUM_VECT_AVX2                                           \
    8 // Number of registers needed for accomodating the message scheduling
      // array

namespace alcp::digest { namespace avx2 {

    // Loads data into the 128 bit registers
    inline void load_data(__m128i        x[SHA256_CHUNK_NUM_VECT_AVX],
                          const uint8_t* data)
    {
        const __m128i shuf_mask =
            _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

        for (uint32_t i = 0; i < SHA256_CHUNK_NUM_VECT_AVX; i++) {
            x[i] =
                _mm_loadu_si128((const __m128i*)(&data[sizeof(__m128i) * i]));
            x[i] = _mm_shuffle_epi8(x[i], shuf_mask);
        }
    }

    // Loads data into the 256 bit registers
    inline void load_data(__m256i        x[2 * SHA256_CHUNK_NUM_VECT_AVX2],
                          const uint8_t* data)
    {
        const __m256i mask = _mm256_setr_epi32(0x00010203,
                                               0x04050607,
                                               0x08090a0b,
                                               0x0c0d0e0f,
                                               0x00010203,
                                               0x04050607,
                                               0x08090a0b,
                                               0x0c0d0e0f);

        for (size_t i = 0; i < SHA256_CHUNK_NUM_VECT_AVX2 * 2; i++) {
            const uint32_t pos0 = (sizeof(__m256i) / 2) * i;
            const uint32_t pos1 = pos0 + 64;

            x[i] = _mm256_insertf128_si256(
                x[i], _mm_loadu_si128((__m128i*)&data[pos1]), 1);
            x[i] = _mm256_insertf128_si256(
                x[i], _mm_loadu_si128((__m128i*)&data[pos0]), 0);
            x[i] = _mm256_shuffle_epi8(x[i], mask);
        }
    }

    // Extends the 16 word message into 64 word message.
    // The processing has been done using 128 bit registers.
    // One block is processed at a time.
    inline void extend_msg(__m128i   x[SHA256_CHUNK_NUM_VECT_AVX],
                           uint32_t* msg_sch_array)
    {
        const __m128i lo_mask = _mm_setr_epi32(0x03020100, 0x0b0a0908, -1, -1);
        const __m128i hi_mask = _mm_setr_epi32(-1, -1, 0x03020100, 0x0b0a0908);

        __m128i temp[5];

        for (uint32_t i = 0; i < 4; i++) {
            _mm_store_si128((__m128i*)&(msg_sch_array[i * 4]), x[i]);
        }

        for (uint32_t j = 0; j < SHA256_MSG_SCH_NUM_VECT_AVX - 4; j++) {
            // Calculation of s0
            size_t index = j;
            temp[0] =
                _mm_alignr_epi8(x[(index + 1) % 4], x[(index + 0) % 4], 4);

            temp[1] = _mm_srli_epi32(temp[0], 7);
            temp[2] = _mm_slli_epi32(temp[0], 32 - 7);
            temp[1] |= temp[2];

            temp[2] = _mm_srli_epi32(temp[0], 18);
            temp[3] = _mm_slli_epi32(temp[0], 32 - 18);
            temp[2] |= temp[3];

            temp[3] = _mm_srli_epi32(temp[0], 3);

            // x[(index + 4)] = temp[1] ^ temp[2] ^ temp[3];
            temp[4] = temp[1] ^ temp[2] ^ temp[3];

            temp[3] =
                _mm_alignr_epi8(x[(index + 3) % 4], x[(index + 2) % 4], 4);
            temp[3] = _mm_add_epi32(x[(index + 0) % 4], temp[3]);
            // x[(index + 4)] = _mm_add_epi32(x[(index + 4)], temp[3]);
            temp[4] = _mm_add_epi32(temp[4], temp[3]);

            // Calculation of s1
            temp[0] = _mm_shuffle_epi32(x[(index + 3) % 4], 0xfa);
            temp[1] = _mm_srli_epi32(temp[0], 17);
            temp[2] = _mm_slli_epi32(temp[0], 32 - 17);
            temp[1] |= temp[2];

            temp[2] = _mm_srli_epi32(temp[0], 19);
            temp[3] = _mm_slli_epi32(temp[0], 32 - 19);
            temp[2] |= temp[3];

            temp[3] = _mm_srli_epi32(temp[0], 10);
            temp[3] = temp[1] ^ temp[2] ^ temp[3];
            temp[3] = _mm_shuffle_epi8(temp[3], lo_mask);

            // x[(index + 4)] = _mm_add_epi32(x[(index + 4)], temp[3]);
            temp[4] = _mm_add_epi32(temp[4], temp[3]);

            temp[0] = _mm_shuffle_epi32(temp[4], 0x50);
            temp[1] = _mm_srli_epi32(temp[0], 17);
            temp[2] = _mm_slli_epi32(temp[0], 32 - 17);
            temp[1] |= temp[2];
            temp[2] = _mm_srli_epi32(temp[0], 19);
            temp[3] = _mm_slli_epi32(temp[0], 32 - 19);
            temp[2] |= temp[3];
            temp[3]            = _mm_srli_epi32(temp[0], 10);
            temp[3]            = temp[1] ^ temp[2] ^ temp[3];
            temp[3]            = _mm_shuffle_epi8(temp[3], hi_mask);
            x[(index + 4) % 4] = _mm_add_epi32(temp[4], temp[3]);
            // Store the result
            _mm_store_si128((__m128i*)&(msg_sch_array[(index + 4) * 4]),
                            x[(index + 4) % 4]);
        }
    }
    // Extends the 16 word message into 64 word message.
    // The processing has been done using 256 bit registers.
    // Two blocks are processed at a time.
    inline void extend_msg(__m256i   x[SHA256_CHUNK_NUM_VECT_AVX2 * 2],
                           uint32_t* msg_sch_array1,
                           uint32_t* msg_sch_array2)
    {
        const __m256i lo_mask = _mm256_setr_epi32(
            0x03020100, 0x0b0a0908, -1, -1, 0x03020100, 0x0b0a0908, -1, -1);
        const __m256i hi_mask = _mm256_setr_epi32(
            -1, -1, 0x03020100, 0x0b0a0908, -1, -1, 0x03020100, 0x0b0a0908);

        __m256i temp[5];

        for (uint32_t i = 0; i < 4; i++) {
            //_mm_store_si128((__m128i*)&(msg_sch_array[i * 4]), x[i]);
            _mm_store_si128((__m128i*)&(msg_sch_array2[i * 4]),
                            _mm256_extracti128_si256(x[i], 1));
            _mm_store_si128((__m128i*)&(msg_sch_array1[i * 4]),
                            _mm256_extracti128_si256(x[i], 0));
        }

        for (uint32_t j = 0; j < 2 * SHA256_MSG_SCH_NUM_VECT_AVX2 - 4; j++) {
            uint32_t index = j;
            // Calculation of s0
            temp[0] =
                _mm256_alignr_epi8(x[(index + 1) % 4], x[(index + 0) % 4], 4);

            temp[1] = _mm256_srli_epi32(temp[0], 7);
            temp[2] = _mm256_slli_epi32(temp[0], 32 - 7);
            temp[1] |= temp[2];

            temp[2] = _mm256_srli_epi32(temp[0], 18);
            temp[3] = _mm256_slli_epi32(temp[0], 32 - 18);
            temp[2] |= temp[3];

            temp[3] = _mm256_srli_epi32(temp[0], 3);

            // x[index + 4] = temp[1] ^ temp[2] ^ temp[3];
            temp[4] = temp[1] ^ temp[2] ^ temp[3];

            temp[3] =
                _mm256_alignr_epi8(x[(index + 3) % 4], x[(index + 2) % 4], 4);
            temp[3] = _mm256_add_epi32(x[(index + 0) % 4], temp[3]);
            // x[index + 4] = _mm256_add_epi32(x[index + 4], temp[3]);
            temp[4] = _mm256_add_epi32(temp[4], temp[3]);

            // Calculation of s1
            temp[0] = _mm256_shuffle_epi32(x[(index + 3) % 4], 0xfa);
            temp[1] = _mm256_srli_epi32(temp[0], 17);
            temp[2] = _mm256_slli_epi32(temp[0], 32 - 17);
            temp[1] |= temp[2];

            temp[2] = _mm256_srli_epi32(temp[0], 19);
            temp[3] = _mm256_slli_epi32(temp[0], 32 - 19);
            temp[2] |= temp[3];

            temp[3] = _mm256_srli_epi32(temp[0], 10);
            temp[3] = temp[1] ^ temp[2] ^ temp[3];
            temp[3] = _mm256_shuffle_epi8(temp[3], lo_mask);

            // x[index + 4] = _mm256_add_epi32(x[index + 4], temp[3]);
            temp[4] = _mm256_add_epi32(temp[4], temp[3]);

            // temp[0] = _mm256_shuffle_epi32(x[index + 4], 0x50);
            temp[0] = _mm256_shuffle_epi32(temp[4], 0x50);
            temp[1] = _mm256_srli_epi32(temp[0], 17);
            temp[2] = _mm256_slli_epi32(temp[0], 32 - 17);
            temp[1] |= temp[2];
            temp[2] = _mm256_srli_epi32(temp[0], 19);
            temp[3] = _mm256_slli_epi32(temp[0], 32 - 19);
            temp[2] |= temp[3];
            temp[3]            = _mm256_srli_epi32(temp[0], 10);
            temp[3]            = temp[1] ^ temp[2] ^ temp[3];
            temp[3]            = _mm256_shuffle_epi8(temp[3], hi_mask);
            x[(index + 4) % 4] = _mm256_add_epi32(temp[4], temp[3]);
            // Store the result
            _mm_store_si128((__m128i*)&(msg_sch_array2[(index + 4) * 4]),
                            _mm256_extracti128_si256(x[(index + 4) % 4], 1));
            _mm_store_si128((__m128i*)&(msg_sch_array1[(index + 4) * 4]),
                            _mm256_extracti128_si256(x[(index + 4) % 4], 0));
        }
    }
    inline void compress_msg(uint32_t*       pMsgSchArray,
                             uint32_t*       pHash,
                             const uint32_t* pHashConstants)
    {
        uint32_t a, b, c, d, e, f, g, h;
        a = pHash[0];
        b = pHash[1];
        c = pHash[2];
        d = pHash[3];
        e = pHash[4];
        f = pHash[5];
        g = pHash[6];
        h = pHash[7];
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t s1, ch, temp1, s0, maj, temp2;
            s1    = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
            ch    = (e & f) ^ (~e & g);
            temp1 = h + s1 + ch + pHashConstants[i] + pMsgSchArray[i];
            s0    = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
            maj   = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;
            h     = g;
            g     = f;
            f     = e;
            e     = d + temp1;
            d     = c;
            c     = b;
            b     = a;
            a     = temp1 + temp2;
        }

        pHash[0] += a;
        pHash[1] += b;
        pHash[2] += c;
        pHash[3] += d;
        pHash[4] += e;
        pHash[5] += f;
        pHash[6] += g;
        pHash[7] += h;
    }
    alc_error_t ShaUpdate256(uint32_t*       pHash,
                             const uint8_t*  pSrc,
                             uint64_t        src_len,
                             const uint32_t* pHashConstants)
    {
        uint32_t num_blocks = src_len / 64;
        // if num of blocks are odd, then need to process
        // a block with 128 bit registers. The rest can be
        // processed using 256 bit registers
        if (num_blocks & 1) {
            __m128i  chunk_vect[SHA256_CHUNK_NUM_VECT_AVX];
            uint32_t msg_sch_array[64];
            load_data(chunk_vect, pSrc);
            extend_msg(chunk_vect, msg_sch_array);
            compress_msg(msg_sch_array, pHash, pHashConstants);
            pSrc += 64;
            src_len -= 64;
        }
        while (src_len >= 128) {
            __m256i  chunk_vect[SHA256_CHUNK_NUM_VECT_AVX2 * 2];
            uint32_t msg_sch_array_1[64];
            uint32_t msg_sch_array_2[64];
            load_data(chunk_vect, pSrc);
            extend_msg(chunk_vect, msg_sch_array_1, msg_sch_array_2);
            compress_msg(msg_sch_array_1, pHash, pHashConstants);
            compress_msg(msg_sch_array_2, pHash, pHashConstants);
            pSrc += 128;
            src_len -= 128;
        }
        return ALC_ERROR_NONE;
    }

}} // namespace alcp::digest::avx2
