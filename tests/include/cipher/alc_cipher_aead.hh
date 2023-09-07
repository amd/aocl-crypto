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

#include "cipher.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <malloc.h>
#include <vector>

#pragma once
namespace alcp::testing {
class AlcpCipherAeadBase : public CipherAeadBase
{
  private:
    alc_cipher_handle_p    m_handle = nullptr;
    alc_cipher_aead_info_t m_cinfo;
    alc_key_info_t         m_keyinfo;
    alc_cipher_mode_t      m_mode;
    const Uint8*           m_iv;
    const Uint8*           m_tkey = nullptr;

  public:
    AlcpCipherAeadBase() {}
    /**
     * @brief Construct a new Alcp Cipher Base object
     *
     * @param mode
     * @param iv
     * @param key
     * @param key_len
     * @param tkey
     */
    AlcpCipherAeadBase(const alc_cipher_mode_t mode,
                       const Uint8*            iv,
                       const Uint32            iv_len,
                       const Uint8*            key,
                       const Uint32            key_len,
                       const Uint8*            tkey,
                       const Uint64            block_size);
    /**
     * @brief Construct a new Alcp Base object - Manual initilization needed,
     * run alcpInit
     *
     * @param mode
     * @param iv
     */
    AlcpCipherAeadBase(const alc_cipher_mode_t mode, const Uint8* iv);

    /**
     * @brief Construct a new Alcp Base object - Initlized and ready to go
     *
     * @param mode
     * @param iv
     * @param key
     * @param key_len
     */
    AlcpCipherAeadBase(const alc_cipher_mode_t mode,
                       const Uint8*            iv,
                       const Uint8*            key,
                       const Uint32            key_len);

    bool alcpGCMModeToFuncCall(alcp_dca_ex_t data, bool enc);
    bool alcpCCMModeToFuncCall(alcp_dca_ex_t aead_data, bool enc);
    bool alcpSIVModeToFuncCall(alcp_dca_ex_t aead_data, bool enc);

    /**
     * @brief         Initialization/Reinitialization function, created handle
     *
     * @param iv      Intilization vector or start of counter (CTR mode)
     * @param key     Binary(RAW) Key 128/192/256 bits
     * @param key_len Length of the Key
     * @return true -  if no failure
     * @return false - if there is some failure
     */
    ~AlcpCipherAeadBase();

    bool init(const Uint8* iv,
              const Uint32 iv_len,
              const Uint8* key,
              const Uint32 key_len,
              const Uint8* tkey,
              const Uint64 block_size);
    bool init(const Uint8* iv,
              Uint32       iv_len,
              const Uint8* key,
              const Uint32 key_len);
    bool init(const Uint8* iv, const Uint8* key, const Uint32 key_len);
    bool init(const Uint8* key, const Uint32 key_len);
    bool encrypt(alcp_dc_ex_t& data);
    bool decrypt(alcp_dc_ex_t& data);
    bool reset();
};

} // namespace alcp::testing