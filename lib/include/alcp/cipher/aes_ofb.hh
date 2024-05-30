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

#ifndef _CIPHER_AES_OFB_HH_
#define _CIPHER_AES_OFB_HH_ 2

#include <cstdint>

#include "alcp/error.h"

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {

class ALCP_API_EXPORT Ofb
    : public Aes
    , public virtual CipherInterface
{
  public:
    Ofb(Uint32 keyLen_in_bytes)
        : Aes(keyLen_in_bytes)
    {
        setMode(ALC_AES_MODE_CFB);
        m_ivLen_max = 16;
        m_ivLen_min = 16;
    };
    ~Ofb() {}
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen) override
    {
        return Aes::init(pKey, keyLen, pIv, ivLen);
    }
};

// aesni classes
CIPHER_CLASS_GEN_N(aesni, Ofb128, Ofb, virtual CipherInterface, 128 / 8)
CIPHER_CLASS_GEN_N(aesni, Ofb192, Ofb, virtual CipherInterface, 192 / 8)
CIPHER_CLASS_GEN_N(aesni, Ofb256, Ofb, virtual CipherInterface, 256 / 8)

} // namespace alcp::cipher

#endif /* _CIPHER_AES_OFB_HH_ */
