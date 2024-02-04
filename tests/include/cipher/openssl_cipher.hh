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

// This define needs to be on the top so that it affects all the includes
/*
   FIXME: Need to change this implementation, selection of provider
   needs to be taken as a command line argument
*/
/*  Loading ALCP-Provider can be used
    to test/benchmark provider.       */
// #define USE_PROVIDER
#define OPENSSL_PROVIDER_PATH "."
#if 1
#define OPENSSL_PROVIDER_NAME "libopenssl-compat"
#else
#define OPENSSL_PROVIDER_NAME "libopenssl-compat_DEBUG"
#endif

#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/utils/copy.hh"
#include "cipher.hh"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifdef USE_PROVIDER
#include <openssl/provider.h>
#endif

namespace alcp::testing {
class OpenSSLCipherBase : public CipherBase
{
  private:
    EVP_CIPHER_CTX*   m_ctx_enc = nullptr;
    EVP_CIPHER_CTX*   m_ctx_dec = nullptr;
    EVP_CIPHER*       m_cipher  = nullptr;
    _alc_cipher_type  m_cipher_type{};
    alc_cipher_mode_t m_mode    = {};
    const Uint8*      m_iv      = nullptr;
    Uint32            m_iv_len  = 12;
    const Uint8*      m_key     = nullptr;
    Uint32            m_key_len = 0;
    const Uint8*      m_tkey    = nullptr;
    Uint8             m_key_final[64];
#ifdef USE_PROVIDER
    OSSL_PROVIDER* m_alcp_provider = nullptr;
#endif

    void              handleErrors();
    const EVP_CIPHER* alcpModeKeyLenToCipher(_alc_cipher_type  cipher_type,
                                             alc_cipher_mode_t mode,
                                             size_t            keylen);

  public:
    OpenSSLCipherBase(const _alc_cipher_type  cipher_type,
                      const alc_cipher_mode_t mode,
                      const Uint8*            iv);
    OpenSSLCipherBase(const _alc_cipher_type  cipher_type,
                      const alc_cipher_mode_t cMode,
                      const Uint8*            iv,
                      const Uint8*            key,
                      const Uint32            key_len);
    OpenSSLCipherBase(const _alc_cipher_type  cipher_type,
                      const alc_cipher_mode_t mode,
                      const Uint8*            iv,
                      const Uint32            iv_len,
                      const Uint8*            key,
                      const Uint32            key_len,
                      const Uint8*            tkey,
                      const Uint64            block_size);
    OpenSSLCipherBase(const _alc_cipher_type  cipher_type,
                      const alc_cipher_mode_t mode,
                      const Uint8*            iv,
                      const Uint32            iv_len,
                      const Uint8*            key,
                      const Uint32            key_len);
    ~OpenSSLCipherBase();
    bool init(const Uint8* iv,
              const Uint32 iv_len,
              const Uint8* key,
              const Uint32 key_len,
              const Uint8* tkey,
              const Uint64 block_size);
    bool init(const Uint8* key, const Uint32 key_len);
    // FIXME: Legacy functions needs to be removed like the one below
    bool encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt);
    bool encrypt(alcp_dc_ex_t& data);
    bool decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt);
    bool decrypt(alcp_dc_ex_t& data);
    bool reset();
};
} // namespace alcp::testing
