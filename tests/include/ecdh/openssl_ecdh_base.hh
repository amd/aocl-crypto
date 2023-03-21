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
#include "alcp/alcp.h"
#include "alcp/ec.h"
#include "alcp/ecdh.h"
#include "ecdh/ecdh_base.hh"
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include <iostream>
#include <malloc.h>
#include <vector>

#pragma once
namespace alcp::testing {
class OpenSSLEcdhBase : public EcdhBase
{
    OSSL_LIB_CTX* m_ec_handle1{};
    OSSL_LIB_CTX* m_ec_handle2{};
    EVP_PKEY*     m_pPrivateKeyData1;
    EVP_PKEY*     m_pPrivateKeyData2;
    EVP_PKEY*     m_pPublicKeyData1;
    EVP_PKEY*     m_pPublicKeyData2;

    std::string st = "X25519"; //"prime256v1"; // P-256

    const char*   m_pkeytype = st.c_str();
    alc_ec_info_t m_info;

    Uint8* m_pvt_key1 = {};
    Uint8* m_pvt_key2 = {};
    Uint8* m_pub_key1 = {};
    Uint8* m_pub_key2 = {};

    std::string m_name, m_keytype;

  public:
    OpenSSLEcdhBase(const alc_ec_info_t& info);
    ~OpenSSLEcdhBase();

    bool init(const alc_ec_info_t& info, const alcp_ecdh_data_t& data);
    bool reset();

    bool GeneratePublicKeys(const alcp_ecdh_data_t& data);
    bool ComputeSecretKeys(const alcp_ecdh_data_t& data);
};

} // namespace alcp::testing
