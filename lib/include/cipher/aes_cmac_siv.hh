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

#include "cipher/aes.hh"

#include "utils/copy.hh"
#include <vector>

namespace alcp::cipher {
// RFC5297
class ALCP_API_EXPORT CmacSiv : public Aes
{
  private:
    /*
        m_additionalDataProcessedProcessed keeps the vector of additional
       data processed with CMAC m_additionalDataProcessedProcessedLen keeps
       the vector of the length of corrosponding memory in m_additionalData
        m_additionalDataProcessedProcessedSize current actual size of the
       vector, for reducing allocs.

       m_additionalDataSize is allocated as a pool of 10 values, this
       reduces the number of allocations needed to keep all additional data.
    */
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    Uint64       m_additionalDataProcessedSize = {};
    Uint8*       m_key1                        = {};
    Uint8*       m_key2                        = {};
    Uint64       m_keyLength                   = {};
    const Uint64 m_sizeCmac                    = 128 / 8;

    Status dbl(std::vector<Uint8>& in);

    // FIXME: Need to be private or need some friend function thing
  protected:
    Status             s2v(const Uint8 plainText[], Uint64 size);
    std::vector<Uint8> m_cmacTemp = std::vector<Uint8>(m_sizeCmac);

  public:
    CmacSiv() = default;
    Status setKeys(Uint8 key1[], Uint8 key2[], Uint64 length);
    // Section 2.4 in RFC
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);

    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        const Uint8* pIv) const;

    Status encrypt(const Uint8 plainText[], Uint8 cipherText[], Uint64 len);

    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        const Uint8* pIv) const;

    Status decrypt(const Uint8  cipherText[],
                   Uint8        plainText[],
                   Uint64       len,
                   const Uint8* iv);

    Status getTag(Uint8 out[]);

    bool isSupported(const alc_cipher_info_t& cipherInfo);
};
} // namespace alcp::cipher