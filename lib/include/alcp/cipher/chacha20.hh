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

#pragma once

#include "alcp/base.hh"
#include "alcp/utils/cpuid.hh"
#include <alcp/error.h>

namespace alcp::cipher::chacha20::zen4 {
alc_error_t
ProcessInput(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             const Uint8 plaintext[],
             Uint64      plaintextLength,
             Uint8       ciphertext[]);
alc_error_t
getKeyStream(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             Uint8       output_key_stream[],
             Uint64      key_stream_length);
} // namespace alcp::cipher::chacha20::zen4

namespace alcp::cipher::chacha20 {
using utils::CpuCipherFeatures;
using utils::CpuId;

static constexpr Uint32 Chacha20Constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};
template<CpuCipherFeatures cpu_cipher_feature = CpuCipherFeatures::eDynamic>
class ALCP_API_EXPORT ChaCha20
{

    static constexpr Uint64 cMKeylen = 256 / 8;
    alignas(16) Uint8 m_key[cMKeylen];
    static constexpr Uint64 cMIvlen = (128 / 8);
    alignas(16) Uint8 m_iv[cMIvlen];

  public:
    alc_error_t setKey(const Uint8 key[], Uint64 keylen);

    alc_error_t setIv(const Uint8 iv[], Uint64 ivlen);

    alc_error_t processInput(const Uint8 plaintext[],
                             Uint64      plaintext_length,
                             Uint8       ciphertext[]) const;

    static alc_error_t validateKey(const Uint8* key, Uint64 keylen);
    static alc_error_t validateIv(const Uint8 iv[], Uint64 iVlen);

    alc_error_t getKeyStream(Uint8  output_key_stream[],
                             Uint64 key_stream_length);
};

} // namespace alcp::cipher::chacha20
