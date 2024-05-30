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
 *
 */

#pragma once

#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/cipher_error.hh"
#include "alcp/cipher/common.hh"
#include "alcp/utils/cpuid.hh"

#include "alcp/cipher/aes_cmac_siv_arch.hh"

#include "alcp/mac/cmac.hh"
#include "alcp/utils/copy.hh"
#include <new>
#include <vector>

using Cmac = alcp::mac::Cmac;
#define SIZE_CMAC 128 / 8
namespace alcp::cipher {

using utils::CpuId;

// RFC5297

//#define MAX_ADD_SIZE_SIV (126 * 16) // 126*16

class ALCP_API_EXPORT Siv : public Aes
{
  public:
    alc_error_t init(const Uint8* pKey,
                     Uint64       keyLen,
                     const Uint8* pIv,
                     Uint64       ivLen);

  protected:
    // FIXME: simplify the vector code, unnecessary complication! Just allocate
    // max data size
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    // alignas(16) Uint8 m_additionalDataProcessed[MAX_ADD_SIZE] = {};

    alignas(16) Uint8 m_cmacTemp[SIZE_CMAC]    = {};
    Uint64       m_additionalDataProcessedSize = {};
    const Uint8* m_key1                        = {};
    const Uint8* m_key2                        = {};
    Uint64       m_padLen                      = {};
    Cmac         m_cmac;

    Status      cmacWrapper(const Uint8 data[],
                            Uint64      size,
                            Uint8       mac[],
                            Uint64      macSize);
    Status      cmacWrapperMultiData(const Uint8 data1[],
                                     Uint64      size1,
                                     const Uint8 data2[],
                                     Uint64      size2,
                                     Uint8       mac[],
                                     Uint64      macSize);
    Status      addAdditionalInput(const Uint8* pAad, Uint64 aadLen);
    alc_error_t setKeys(const Uint8 key1[], Uint64 length);
    Status      s2v(const Uint8 plainText[], Uint64 size);

    Siv() = default;
    Siv(alc_cipher_data_t* ctx);
};

AEAD_AUTH_CLASS_GEN(SivHash, Siv);

// Declare AEAD Classes
namespace aesni {
    CIPHER_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace aesni

namespace vaes {
    CIPHER_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace vaes

namespace vaes512 {
    CIPHER_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    CIPHER_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace vaes512

} // namespace alcp::cipher