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

#include "rsa/openssl_rsa.hh"
#include <cstddef>
#include <cstring>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <ostream>

namespace alcp::testing {

OpenSSLRsaBase::OpenSSLRsaBase() {}

OpenSSLRsaBase::~OpenSSLRsaBase()
{
    EVP_PKEY_CTX_free(m_rsa_handle);
    EVP_PKEY_free(m_pkey);
}

bool
OpenSSLRsaBase::init()
{
    m_rsa_handle = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (m_rsa_handle == nullptr) {
        std::cout << "EVP_PKEY_CTX_new_from_name returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::GetPublicKey(const alcp_rsa_data_t& data)
{
    ENGINE*      eng    = NULL;
    unsigned int primes = 3;
    /*TODO: change this later*/
    unsigned int bits = 1024;
    OSSL_PARAM   params[3];

    if (1 != EVP_PKEY_keygen_init(m_rsa_handle)) {
        std::cout << "EVP_PKEY_keygen_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();

    if (1 != EVP_PKEY_CTX_set_params(m_rsa_handle, params)) {
        std::cout << "EVP_PKEY_CTX_set_params failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    if (1 != EVP_PKEY_generate(m_rsa_handle, &m_pkey)) {
        std::cout << "EVP_PKEY_generate failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    m_rsa_handle = EVP_PKEY_CTX_new(m_pkey, eng);
    if (m_rsa_handle == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

int
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    size_t outlen;
    int    ret_val = 0;

    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_encrypt_init failed: Error:" << ret_val
                  << std::endl;
        return ret_val;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle, RSA_NO_PADDING)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:" << ret_val
                  << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_encrypt(
            m_rsa_handle, NULL, &outlen, data.m_msg, data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_encrypt failed: Error:" << ret_val << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle,
                            data.m_encrypted_data,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_encrypt failed: Error:" << ret_val << std::endl;
        return ret_val;
    }
    return 0;
}

int
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    size_t outlen;
    int    ret_val = 0;
    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 0;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle, RSA_NO_PADDING)) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 0;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_decrypt failed: Error:" << ret_val << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << "EVP_PKEY_decrypt failed: Error:" << ret_val << std::endl;
        return ret_val;
    }
    return 0;
}

bool
OpenSSLRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
