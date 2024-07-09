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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once
#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "mac.hh"
#include <immintrin.h>
#include <memory>

namespace alcp::mac {
class Cmac final
    : public IMac
    , public cipher::Aes
{
  public:
    ALCP_API_EXPORT Cmac();
    ALCP_API_EXPORT ~Cmac();
    ALCP_API_EXPORT Cmac(const Cmac& cmac);
    /**
     * @brief Reset CMAC. After resetting update can be called by the same key
     */
    ALCP_API_EXPORT alc_error_t reset() override;

    /**
     * @brief Update CMAC with plaintext Message
     *
     * @param pMsgBuf   Plaintext Message Buffer bytes to be updated
     * @param size      Size of the Plaintext Message Buffer in bytes
     */
    ALCP_API_EXPORT alc_error_t update(const Uint8* pMsgBuf,
                                       Uint64       size) override;

    ALCP_API_EXPORT alc_error_t init(const Uint8* pKey, Uint64 keyLen);
    /**
     * @brief Call Finalize to copy the digest
     *
     * @param pMsgBuf   cmac buffer
     * @param size      Size of the cmac in bytes
     */
    ALCP_API_EXPORT alc_error_t finalize(Uint8* pMsgBuf, Uint64 size) override;

  private:
    void                 getSubkeys();
    static constexpr int cAESBlockSize = 16;
    alignas(16) Uint8 m_k1[cAESBlockSize]{};
    alignas(16) Uint8 m_k2[cAESBlockSize]{};
    const Uint8* m_encrypt_keys = nullptr; // expanded keys ptr
    alignas(16) Uint8
        m_buff[cAESBlockSize]{}; // temp buffer for plaintext data processing
    int m_buff_offset = 0;       // buffer offset
    alignas(16)
        Uint32 m_buffEnc[cAESBlockSize / 4]{}; // temp buffer for encrypted data
    Uint8* m_pBuffEnc  = reinterpret_cast<Uint8*>(m_buffEnc);
    bool   m_finalized = false;
};

namespace avx2 {

    ALCP_API_EXPORT void get_subkeys(Uint8*       k1,
                                     Uint8*       k2,
                                     const Uint8* encrypt_keys,
                                     const Uint32 cNRounds);

    ALCP_API_EXPORT void update(const Uint8* pPlaintext,
                                Uint8*       pBuffer,
                                const Uint8* pEncryptKeys,
                                Uint8*       pEnc,
                                Uint32       rounds,
                                const Uint32 cNBlocks);

    ALCP_API_EXPORT void finalize(Uint8*       pBuff,
                                  Uint32       buff_offset,
                                  const Uint32 cBlockSize,
                                  const Uint8* pSubKey1,
                                  const Uint8* pSubKey2,
                                  const Uint32 cRounds,
                                  Uint8*       pEnc,
                                  const Uint8* pEncryptKeys);

} // namespace avx2
} // namespace alcp::mac