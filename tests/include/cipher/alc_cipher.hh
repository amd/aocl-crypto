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

#include "cipher.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <malloc.h>
#include <vector>

#pragma once
namespace alcp::testing {
typedef struct _alc_cipher_info
{
    // request params
    alc_cipher_mode_t ci_mode;   /*! Mode: ALC_AES_MODE_CTR etc */
    Uint64            ci_keyLen; /*! Key length in bits */

    // init params
    const Uint8* ci_key;   /*! key data */
    const Uint8* ci_iv;    /*! Initialization Vector */
    Uint64       ci_ivLen; /*! Initialization Vector length */

} alc_cipher_info_t;
class AlcpCipherBase : public CipherBase
{
  private:
    alc_cipher_handle_p m_handle = nullptr;
    alc_cipher_mode_t   m_mode{};
    const Uint8*        m_iv{};
    Uint8               m_key[64]{};
    const Uint8*        m_tkey = nullptr;

  public:
    AlcpCipherBase() {}

    /**
     * @brief Construct a new Cipher Base object
     *
     * @param cipher_type  Type of Cipher AES, CHACHA etc..
     * @param mode         Mode of Cipher XTS, CTR, GCM etc..
     * @param iv           Initialization vector or start of counter (CTR mode)
     */
    AlcpCipherBase(const alc_cipher_mode_t mode, const Uint8* iv);

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
    AlcpCipherBase(const alc_cipher_mode_t mode,
                   const Uint8*            iv,
                   const Uint32            iv_len,
                   const Uint8*            key,
                   const Uint32            key_len,
                   const Uint8*            tkey,
                   const Uint64            block_size);

    ~AlcpCipherBase();

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
    bool encrypt(alcp_dc_ex_t& data);
    bool decrypt(alcp_dc_ex_t& data);
    bool reset();
};

} // namespace alcp::testing