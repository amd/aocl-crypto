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
    if (m_rsa_handle != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle);
        m_rsa_handle = nullptr;
    }
    if (m_pkey != nullptr) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
    }
}

bool
OpenSSLRsaBase::init()
{
    if (m_rsa_handle != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle);
        m_rsa_handle = nullptr;
    }
    m_rsa_handle = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (m_rsa_handle == nullptr) {
        std::cout << "EVP_PKEY_CTX_new_from_name returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    ENGINE*       eng   = NULL;
    unsigned long rsa_n = 0x400;
    unsigned long rsa_e = 0x10001; // 0x10001
    unsigned long rsa_d = 0x7b133399;

    static const Uint8 Modulus_1024[] = {
        0xef, 0x4f, 0xa2, 0xcd, 0x00, 0xea, 0x99, 0xeb, 0x12, 0xa8, 0x3a, 0x1b,
        0xc5, 0x5d, 0x49, 0x04, 0x18, 0xcd, 0x96, 0x69, 0xc9, 0x28, 0x2c, 0x36,
        0x40, 0x9a, 0x15, 0x40, 0x05, 0x6b, 0x35, 0x6f, 0x89, 0x76, 0xf3, 0xb9,
        0xe3, 0xac, 0x4d, 0x2a, 0xe4, 0xba, 0xd9, 0x6e, 0xb8, 0xa4, 0x05, 0x0b,
        0xc5, 0x8e, 0xdf, 0x15, 0x33, 0xfc, 0x81, 0x2b, 0xb5, 0xf4, 0x3a, 0x0b,
        0x67, 0x2d, 0x7d, 0x7c, 0x41, 0x8c, 0xc0, 0x46, 0x93, 0x7d, 0xe9, 0x95,
        0x90, 0x1e, 0xdd, 0xc0, 0xf4, 0xfc, 0x23, 0x90, 0xbb, 0x14, 0x73, 0x5e,
        0xcc, 0x86, 0x45, 0x6a, 0x9c, 0x15, 0x46, 0x92, 0xf3, 0xac, 0x24, 0x8f,
        0x0c, 0x28, 0x25, 0x17, 0xb1, 0xb8, 0x3f, 0xa5, 0x9c, 0x61, 0xbd, 0x2c,
        0x10, 0x7a, 0x5c, 0x47, 0xe0, 0xa2, 0xf1, 0xf3, 0x24, 0xca, 0x37, 0xc2,
        0x06, 0x78, 0xa4, 0xad, 0x0e, 0xbd, 0x72, 0xeb
    };

    OSSL_PARAM_BLD* bld  = OSSL_PARAM_BLD_new();
    BIGNUM*         n_bn = BN_bin2bn(Modulus_1024, 128, NULL);
    // OSSL_PARAM_BLD_push_BN(bld, OSSL_KEY_PARAM_RSA, n_bn);

    OSSL_PARAM params[] = { OSSL_PARAM_ulong("n", &rsa_n),
                            OSSL_PARAM_ulong("e", &rsa_e),
                            OSSL_PARAM_ulong("d", &rsa_d),
                            OSSL_PARAM_END };

    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle)) {
        std::cout << "EVP_PKEY_fromdata_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_fromdata(
            m_rsa_handle, &m_pkey, EVP_PKEY_PUBLIC_KEY, params)) {
        std::cout << "EVP_PKEY_fromdata failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
    // ENGINE*      eng    = NULL;
    // unsigned int primes = 3;
    // /*TODO: change this later*/
    // unsigned int bits = 1024;
    // if (m_key_len * 8 == 1024) {
    //     bits = 1024;
    // } else if (m_key_len * 8 == 2048) {
    //     bits = 2048;
    // } else {
    //     std::cout << "Invalid key size passed to OpenSSL SetPublicKey"
    //               << std::endl;
    //     return false;
    // }

    // OSSL_PARAM params[3];

    // if (1 != EVP_PKEY_keygen_init(m_rsa_handle)) {
    //     std::cout << "EVP_PKEY_keygen_init failed: Error:"
    //               << ERR_GET_REASON(ERR_get_error()) << std::endl;
    //     return false;
    // }

    // params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    // params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    // params[2] = OSSL_PARAM_construct_end();

    // if (1 != EVP_PKEY_CTX_set_params(m_rsa_handle, params)) {
    //     std::cout << "EVP_PKEY_CTX_set_params failed: Error:"
    //               << ERR_GET_REASON(ERR_get_error()) << std::endl;
    //     return false;
    // }
    // if (1 != EVP_PKEY_generate(m_rsa_handle, &m_pkey)) {
    //     std::cout << "EVP_PKEY_generate failed: Error:"
    //               << ERR_GET_REASON(ERR_get_error()) << std::endl;
    //     return false;
    // }
    // if (m_rsa_handle != nullptr) {
    //     EVP_PKEY_CTX_free(m_rsa_handle);
    //     m_rsa_handle = nullptr;
    // }
    // m_rsa_handle = EVP_PKEY_CTX_new(m_pkey, eng);
    // if (m_rsa_handle == nullptr) {
    //     std::cout << "EVP_PKEY_CTX_new returned null: Error:"
    //               << ERR_GET_REASON(ERR_get_error()) << std::endl;
    //     return false;
    // }
    // return true;
}

bool
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    return true;
}

bool
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    ENGINE* eng = NULL;
    size_t  outlen;
    m_rsa_handle_keyctx = EVP_PKEY_CTX_new(m_pkey, eng);

    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle_keyctx)) {
        std::cout << "EVP_PKEY_encrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* FIXME: parameterize the padding scheme */
    if (1
        != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx, RSA_NO_PADDING)) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_encrypt(
            m_rsa_handle_keyctx, NULL, &outlen, data.m_msg, data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx,
                            data.m_encrypted_data,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    size_t outlen;
    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1 != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle, RSA_NO_PADDING)) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
