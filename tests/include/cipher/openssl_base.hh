/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "base.hh"
#include <alcp/alcp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

namespace alcp::testing {
class OpenSSLCipherBase : public CipherBase
{
  private:
    EVP_CIPHER_CTX*   m_ctx_enc       = nullptr;
    EVP_CIPHER_CTX*   m_ctx_dec       = nullptr;
    alc_cipher_mode_t m_mode          = {};
    const uint8_t*    m_iv            = nullptr;
    uint32_t          m_iv_len        = 12;
    const uint8_t*    m_key           = nullptr;
    uint32_t          m_key_len       = 0;
    const uint8_t*    m_tkey          = nullptr;
    OSSL_PROVIDER*    m_alcp_provider = nullptr;
    // const uint64_t    m_block_size = 0;

    void              handleErrors();
    const EVP_CIPHER* alcpModeKeyLenToCipher(alc_cipher_mode_t mode,
                                             size_t            keylen);

  public:
    OpenSSLCipherBase(const alc_cipher_mode_t mode, const uint8_t* iv);
    OpenSSLCipherBase(const alc_cipher_mode_t mode,
                      const uint8_t*          iv,
                      const uint8_t*          key,
                      const uint32_t          key_len);
    OpenSSLCipherBase(const alc_cipher_mode_t mode,
                      const uint8_t*          iv,
                      const uint32_t          iv_len,
                      const uint8_t*          key,
                      const uint32_t          key_len,
                      const uint8_t*          tkey,
                      const uint64_t          block_size);
    OpenSSLCipherBase(const alc_cipher_mode_t mode,
                      const uint8_t*          iv,
                      const uint32_t          iv_len,
                      const uint8_t*          key,
                      const uint32_t          key_len);
    ~OpenSSLCipherBase();
    bool init(const uint8_t* iv,
              const uint32_t iv_len,
              const uint8_t* key,
              const uint32_t key_len);
    bool init(const uint8_t* iv,
              const uint32_t iv_len,
              const uint8_t* key,
              const uint32_t key_len,
              const uint8_t* tkey,
              const uint64_t block_size);
    bool init(const uint8_t* iv, const uint8_t* key, const uint32_t key_len);
    bool init(const uint8_t* key, const uint32_t key_len);
    bool encrypt(const uint8_t* plaintxt, size_t len, uint8_t* ciphertxt);
    bool encrypt(alcp_data_ex_t data);
    bool decrypt(const uint8_t* ciphertxt, size_t len, uint8_t* plaintxt);
    bool decrypt(alcp_data_ex_t data);
    void reset();
};
} // namespace alcp::testing
