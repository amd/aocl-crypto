/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
 */

#pragma once

#include "alcp/rsa.h"
#include "alcp/types.hh"
#include <memory>

namespace alcp::rsa {
enum DigestIndex
{
    MD5,
    SHA1,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHA_UNKNOWN
};
template<alc_rsa_key_size T>
struct RsaPublicKeyBignum
{
    Uint64 m_mod[T / 64]{};
    Uint64 m_public_exponent = 0;
    Uint64 m_size            = 0;
};

template<alc_rsa_key_size T>
struct RsaPrivateKeyBignum
{
    Uint64 m_dp[T / (2 * 64)]{};
    Uint64 m_dq[T / (2 * 64)]{};
    Uint64 m_p[T / (2 * 64)]{};
    Uint64 m_q[T / (2 * 64)]{};
    Uint64 m_qinv[T / (2 * 64)]{};
    Uint64 m_mod[T / 64]{};
    Uint64 m_size = 0;
};

template<alc_rsa_key_size T>
struct MontContextBignum
{
    Uint64 m_r1[T / 64]{}; // Montgomery identity
    Uint64 m_r2[T / 64]{}; // Montgomery converter
    Uint64 m_r3[T / 64]{}; // Montgomery optimizer
    Uint64 m_r2_radix_52_bit[T / 52
                             + 1]{}; // Montgomery converter in radix 52 bit.
    Uint64 m_mod_radix_52_bit[T / 52 + 1]{}; // Modulus in radix 52.
    Uint64 m_k0;                             // Montgomery parameter
    Uint64 m_size = 0;
};

static inline Uint64*
CreateBigNum(const Uint8* bytes, Uint64 size)
{
    constexpr Uint8 BytesBignum = 8;
    // convert the binary data from Uint8 to Unit64 format
    // one all the implementation is done and working This will be
    // transmitted to the bignum alcp implementation

    Uint64 big_num_size = size / BytesBignum;

    auto   res_buffer_bignum = new Uint64[big_num_size]{};
    Uint8* p_res             = reinterpret_cast<Uint8*>(res_buffer_bignum);

    if (bytes == nullptr)
        return res_buffer_bignum;

    // check if it can be optimized using vector instruction
    for (Int64 i = size - 1, j = 0; i >= 0; --i, ++j) {
        p_res[j] = bytes[i];
    }

    return res_buffer_bignum;
}

static inline void
ConvertToBigNum(const Uint8* bytes, Uint64* bigNum, Uint64 size)
{
    Uint8* p_res = reinterpret_cast<Uint8*>(bigNum);

    // check if it can be optimized using vector instruction
    for (Int64 i = size - 1, j = 0; i >= 0; --i, ++j) {
        p_res[j] = bytes[i];
    }
}

static inline bool
IsLess(Uint64* inp1, Uint64* inp2, Uint64 size)
{
    for (Int64 i = size - 1; i >= 0; i--) {
        if (inp1[i] != inp2[i])
            return inp1[i] < inp2[i];
    }
    return false;
}

} // namespace alcp::rsa
