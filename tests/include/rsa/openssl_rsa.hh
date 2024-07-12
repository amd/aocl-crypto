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
#include "alcp/alcp.h"
#include "alcp/rsa.h"
#include "openssl/conf.h"
#include "openssl/core_names.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/rsaerr.h"
#include "rsa/rsa.hh"
#include "rsa/rsa_keys.hh"
#include <iostream>
#include <malloc.h>
#include <openssl/param_build.h>
#include <vector>

#pragma once
namespace alcp::testing {
class OpenSSLRsaBase : public RsaBase
{
    EVP_PKEY* m_pkey_pub = nullptr;
    EVP_PKEY* m_pkey_pvt = nullptr;

    EVP_PKEY_CTX* m_rsa_handle_keyctx_pub = nullptr;
    EVP_PKEY_CTX* m_rsa_handle_keyctx_pvt = nullptr;

    EVP_MD_CTX* m_SignCtx   = nullptr;
    EVP_MD_CTX* m_VerifyCtx = nullptr;

    EVP_PKEY_CTX* m_SigningKeyCtx = nullptr;
    EVP_PKEY_CTX* m_VerifyKeyCtx  = nullptr;

    /* will be used for Signing a hash */
    EVP_PKEY_CTX* m_SigningKeyCtxDirect = nullptr;
    EVP_PKEY_CTX* m_VerifyKeyCtxDirect  = nullptr;

    OSSL_PARAM*   m_params = nullptr;
    OSSL_LIB_CTX* m_libctx = nullptr;

    const EVP_MD* m_md_type = nullptr;

    const char* m_digest_str;

    Uint64 m_sig_len = 0;

  public:
    OpenSSLRsaBase();
    ~OpenSSLRsaBase();

    bool init();
    bool reset();

    bool SetPublicKey(const alcp_rsa_data_t& data);
    bool SetPrivateKey(const alcp_rsa_data_t& data);
    bool ValidateKeys();
    int  EncryptPubKey(const alcp_rsa_data_t& data);
    int  DecryptPvtKey(const alcp_rsa_data_t& data);
    bool DigestSign(const alcp_rsa_data_t& data);
    bool DigestVerify(const alcp_rsa_data_t& data);
    bool Sign(const alcp_rsa_data_t& data);
    bool Verify(const alcp_rsa_data_t& data);
};

} // namespace alcp::testing
