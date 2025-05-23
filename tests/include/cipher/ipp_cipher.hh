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

/* C/C++ Headers */
#include <alcp/types.h>
#include <iostream>
#include <ippcp.h>
#include <stdio.h>
#include <string.h>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "cipher.hh"

namespace alcp::testing {
class IPPCipherBase : public CipherBase
{
  private:
    alc_cipher_mode_t m_mode{};
    IppsAESSpec*      m_ctx     = NULL;
    IppsAES_XTSSpec*  m_ctx_xts = NULL;
    IppsAES_GCMState* m_ctx_gcm = NULL;
    IppsAES_CCMState* m_ctx_ccm = NULL;

    const Uint8* m_iv{};
    const Uint8* m_key{};
    Uint32       m_key_len    = 0;
    const Uint8* m_tkey       = NULL;
    int          m_ctxSize    = 0;
    Uint64       m_block_size = 0;
    Uint8        m_key_final[64];
    void         PrintErrors(IppStatus status);
    bool alcpModeToFuncCall(const Uint8* in, Uint8* out, size_t len, bool enc);
#if 0
    bool alcpGCMModeToFuncCall(alcp_data_ex_t data, bool enc);
    bool alcpCCMModeToFuncCall(alcp_data_ex_t data, bool enc);
    bool alcpSIVModeToFuncCall(alcp_data_ex_t data, bool enc);
#endif

  public:
    /**
     * @brief Construct a new Cipher Base object
     *
     * @param cipher_type  Type of Cipher AES, CHACHA etc..
     * @param mode         Mode of Cipher XTS, CTR, GCM etc..
     * @param iv           Initialization vector or start of counter (CTR mode)
     */
    IPPCipherBase(const alc_cipher_mode_t mode, const Uint8* iv);

    /**
     * @brief Construct a new Cipher Base object
     *
     * @param cipher_type  Type of Cipher AES, CHACHA etc..
     * @param mode         Mode of Cipher XTS, CTR, GCM etc..
     * @param iv           Initialization vector or start of counter (CTR mode)
     * @param iv_len       Length of initialization vector
     * @param key          Binary(RAW) Key 128/192/256 bits
     * @param key_len      Length of the Key
     * @param tkey         Tweak key for XTS
     * @param block_size   Size of the block division in bytes
     */
    IPPCipherBase(const alc_cipher_mode_t mode,
                  const Uint8*            iv,
                  const Uint32            iv_len,
                  const Uint8*            key,
                  const Uint32            key_len,
                  const Uint8*            tkey,
                  const Uint64            block_size);

    ~IPPCipherBase();

    /**
     * @brief Initialize or Reinitialize Cipher Base
     *
     * @param iv           Initialization vector or start of counter (CTR mode)
     * @param iv_len       Length of initialization vector
     * @param key          Binary(RAW) Key 128/192/256 bits
     * @param key_len      Length of the Key
     * @param tkey         Tweak key for XTS
     * @param block_size   Size of the block division in bytes
     * @return true -  if no failure
     * @return false - if there is some failure
     */
    bool init(const Uint8* iv,
              const Uint32 iv_len,
              const Uint8* key,
              const Uint32 key_len,
              const Uint8* tkey,
              const Uint64 block_size);

    /**
     * @brief Initialize or Reinitialize Cipher Base
     *
     * @param key          Binary(RAW) Key 128/192/256 bits
     * @param key_len      Length of the Key
     * @return true -  if no failure
     * @return false - if there is some failure
     */
    bool init(const Uint8* key, const Uint32 key_len);
    // FIXME: Legacy functions needs to be removed like the one below
    bool encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt);
    bool encrypt(alcp_dc_ex_t& data);
    bool decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt);
    bool decrypt(alcp_dc_ex_t& data);
    bool reset();
};
} // namespace alcp::testing