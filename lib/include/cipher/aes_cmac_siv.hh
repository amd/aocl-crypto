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
#include "cipher/aes.hh"

#include "mac/cmac.hh"
#include "utils/copy.hh"
#include <vector>

using Cmac = alcp::mac::Cmac;

namespace alcp::cipher {
// RFC5297

class ALCP_API_EXPORT CmacSiv : public Aes
{
  private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // FIXME: Need to be private or need some friend function thing
  protected:
    Status s2v(const Uint8 plainText[], Uint64 size);

  public:
    CmacSiv();
    CmacSiv(const alc_cipher_algo_info_t& aesInfo,
            const alc_key_info_t& keyInfo); // Depriciated, implemented for CAPI
    Status setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length);
    Status setPaddingLen(Uint64 len);
    // Section 2.4 in RFC
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);

    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        const Uint8* pIv) const;

    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        const Uint8* pIv) const;
    // FIXME: Needs to be removed from Cipher as a whole
    // Cipher support should end in capi
    bool isSupported(const alc_cipher_info_t& cipherInfo);

    Status      getTag(Uint8 out[]);
    alc_error_t getTag(Uint8 out[], Uint64 len); // Depriciated
};

class CmacSiv::Impl
{
  private:
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    Uint64             m_additionalDataProcessedSize = {};
    const Uint8*       m_key1                        = {};
    const Uint8*       m_key2                        = {};
    Uint64             m_keyLength                   = {};
    const Uint64       m_sizeCmac                    = 128 / 8;
    Uint64             m_padLen                      = {};
    std::vector<Uint8> m_cmacTemp = std::vector<Uint8>(m_sizeCmac, 0);
    Cmac               m_cmac;
    Ctr                m_ctr;

  public:
    Impl(){};
    Status s2v(const Uint8 plainText[], Uint64 size);
    Status setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length);
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);
    Status setPaddingLen(Uint64 len);
    Status encrypt(const Uint8 plainText[], Uint8 cipherText[], Uint64 len);
    Status decrypt(const Uint8  cipherText[],
                   Uint8        plainText[],
                   Uint64       len,
                   const Uint8* iv);
    Status getTag(Uint8 out[]);
    Status cmacWrapper(const Uint8 key[],
                       Uint64      keySize,
                       const Uint8 data[],
                       Uint64      size,
                       Uint8       mac[],
                       Uint64      macSize);
    Status ctrWrapper(const Uint8 key[],
                      Uint64      keySize,
                      const Uint8 in[],
                      Uint8       out[],
                      Uint64      size,
                      Uint8       iv[],
                      bool        enc);
    Status cmacWrapperMultiData(const Uint8 key[],
                                Uint64      keySize,
                                const Uint8 data1[],
                                Uint64      size1,
                                const Uint8 data2[],
                                Uint64      size2,
                                Uint8       mac[],
                                Uint64      macSize);
};

} // namespace alcp::cipher