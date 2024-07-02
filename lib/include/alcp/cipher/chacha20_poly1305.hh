/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/cipher_common.hh"
#include "alcp/mac/poly1305.hh"

namespace alcp::cipher {

// These will be used to store the length of the ciphertext
union len_input_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

union len_aad_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

using utils::CpuArchFeature;

namespace vaes512 {

    class ALCP_API_EXPORT ChaChaPlusPoly
        : public ChaCha256
        , public alcp::mac::poly1305::Poly1305<CpuArchFeature::eDynamic>
    {
      protected:
        Uint8               m_poly1305_key[32]{};
        const Uint8         m_zero_padding[16]{};
        len_input_processed m_len_input_processed{};
        len_aad_processed   m_len_aad_processed{};

      public:
        ChaChaPlusPoly(Uint32 keyLen_in_bytes){};
        virtual ~ChaChaPlusPoly() = default;

        alc_error_t setIv(const Uint8* iv, Uint64 ivLen);
        alc_error_t setKey(const Uint8* key, Uint64 keylen);
    };

    class ALCP_API_EXPORT ChaChaPoly : public ChaChaPlusPoly
    {

      public:
        ChaChaPoly(Uint32 keyLen_in_bytes)
            : ChaChaPlusPoly(keyLen_in_bytes){}; /* fixed keyLen*/
        virtual ~ChaChaPoly() = default;
        alc_error_t init(const Uint8* pKey,
                         Uint64       keyLen,
                         const Uint8* pIv,
                         Uint64       ivLen);
    };

    AEAD_AUTH_CLASS_GEN(ChaChaPolyAuth, ChaChaPoly, virtual CipherAuth);

    CIPHER_CLASS_GEN_(ChaChaPoly256,
                      ChaChaPolyAuth,
                      virtual iCipherAead,
                      256 / 8);

} // namespace vaes512

#if 0

namespace ref {


} // namespace ref

#endif

} // namespace alcp::cipher