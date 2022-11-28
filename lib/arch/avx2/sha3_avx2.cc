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
#include "digest/sha3.hh"
#include "error.hh"
#include "utils/copy.hh"

#include <x86intrin.h>

#if defined(__GNUC__)
#define UNROLL_8  _Pragma("GCC unroll 8")
#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_80 _Pragma("GCC unroll 80")
#else
#define UNROLL_8
#define UNROLL_16
#define UNROLL_80
#endif

// clang-format off
static constexpr Uint64 cRoundConstants[24] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};

static constexpr Uint8 cRotationConstants [5][5] =
{
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};

namespace alcp::digest { namespace avx2 {
    static constexpr Uint64 cNumRounds = 24;



    inline void fFunction( Uint64 state[5][5])
    {
        for (Uint64 i = 0; i < cNumRounds; ++i) {
                    // theta stage
        Uint64 c[5], d[5];

        for (int x = 0; x < 5; ++x) {
            c[x] = state[0][x];
            for (int y = 1; y < 5; ++y) {
                c[x] ^= state[y][x];
            }
        }

        for (int x = 0; x < 5; ++x) {
            d[x] = c[(5 + x - 1) % 5]
                   ^ alcp::digest::RotateLeft(c[(x + 1) % 5], 1);
        }

        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x][y] ^= d[y];
            }
        }

        // Rho stage
        Uint64 temp[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                temp[x][y] = alcp::digest::RotateLeft(state[x][y],
                                                      cRotationConstants[x][y]);
            }
        }

        // pi stage
        for (int x = 0; x < 5; ++x) {
            int x_indx = 2 * x;
            for (int y = 0; y < 5; ++y) {
                state[(x_indx + 3 * y) % 5][y] = temp[y][x];
            }
        }

        // xi stage
        utils::CopyBytes(temp, state, sizeof(temp));
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x][y] =
                    temp[x][y]
                    ^ (~temp[x][(y + 1) % 5] & temp[x][(y + 2) % 5]);
            }
        }

        // iota stage
        state[0][0] ^= cRoundConstants[i];
        }
    }

    inline void absorbChunk(Uint64* pSrc, Uint64 chunk_size_u64, Uint64* state)
    {
        // check if we do gcc unroll here
        for (Uint64 i = 0; i < chunk_size_u64; ++i) {
            state[i] ^= pSrc[i];
        }
        fFunction((Uint64 (*)[5])state);
    }

    void Sha3Finalize(Uint8* state, Uint8* hash, Uint64 hash_size, Uint64 chunk_size)
    {
        Uint64 hash_copied = 0;
        while (chunk_size <= hash_size - hash_copied) {
            Uint64 data_chunk_copied = std::min(hash_size, chunk_size);

        utils::CopyBytes(
            &hash[hash_copied], state, data_chunk_copied);
        hash_copied += data_chunk_copied;

        if (hash_copied < hash_size) {
            fFunction((Uint64 (*)[5])state);
        }
    }

    if (hash_size > hash_copied) {
        utils::CopyBytes(&hash[hash_copied],
                         (Uint8*)state,
                         hash_size - hash_copied);
    }
}

    alc_error_t Sha3Update(Uint64* state,
                           Uint64* pSrc,
                           Uint64  msg_size,
                           Uint64  chunk_size)
    {

        Uint32 num_chunks     = msg_size / chunk_size;
        Uint64 chunk_size_u64 = chunk_size / 8;

        for (Uint32 i = 0; i < num_chunks; i++) {
            absorbChunk(pSrc, chunk_size_u64, state);
            pSrc += chunk_size_u64;
        }

        return ALC_ERROR_NONE;
    }

}} // namespace alcp::digest::avx2
