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
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    if (m_pkey != nullptr) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
    }
    if (m_pkey_pvt != nullptr) {
        EVP_PKEY_free(m_pkey_pvt);
        m_pkey_pvt = nullptr;
    }
}

bool
OpenSSLRsaBase::init()
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    const char* strPublicKey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxiJ0nHJBUK15SY2NNgyNtm0hr\n"
        "a52HbdoWsBnN8d0QtMU1vKoAjEBB4aBXkUkP2TyJtLyyR+d9JLIvmrlqpSDm1N7T\n"
        "Dijcrz+IEU+lAkaR5/GTskcRW3u72ulHf+ul1xeWUwmmar6O5EXf5xKAeIZlR/lK\n"
        "5ZDW3AwNWlrOEsobCQIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

    // encrypt
    BIO* bioPublic = BIO_new_mem_buf(strPublicKey, -1);
    m_pkey         = PEM_read_bio_PUBKEY(bioPublic, &m_pkey, nullptr, nullptr);
    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    return true;
}

bool
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    const char* strPrivateKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPGInScckFQrXlJj\n"
        "Y02DI22bSGtrnYdt2hawGc3x3RC0xTW8qgCMQEHhoFeRSQ/ZPIm0vLJH530ksi+a\n"
        "uWqlIObU3tMOKNyvP4gRT6UCRpHn8ZOyRxFbe7va6Ud/66XXF5ZTCaZqvo7kRd/n\n"
        "EoB4hmVH+UrlkNbcDA1aWs4SyhsJAgMBAAECgYAFvAyfJRp4JR90LU/qQzbQH2O0\n"
        "yTVQRddrunqiXR+2idQ01mni4XGVHtpDuftWGP5K9rOUOAjS+9APOUk1sv348T1x\n"
        "EKxYLQvXLPJcVtYE8sJgJIO6PX0ZpO0upMocX08U8naQUwNPeMC2jr9OzwZmK9BL\n"
        "RW6E6rVSyZNro9bBUQJBAP35x2lsO2CP7CfHUEIp8IGbqet758FYBFLAB4Qy0/Jy\n"
        "QZyWXIQUnmO6CpjNVqtHC9WnQzAM9WLRO6INft84mksCQQDzdXKd7IgSI2XRlpj+\n"
        "5rOyyULNZVy7z5+BxfKpVeoCWZuIdsdWmbyAhAysurTvRRNS+/hJ817338Fy1qbZ\n"
        "rEt7AkEAlpYlIGLmCekL8sIA2loXmiF77H34+fCAD7iAPGgOty/7qyaUEFRRXXwP\n"
        "kG4ft0pWwAV+ltz4GfFJVFqAIUZkZQJAVI6UMnl2gSY+NN8jYFTsUMpKI2BzJt/j\n"
        "vITt1RZ74jkRJgJrFY7rw48Zf9yQ/xF0trvA7p5Se7EBVUtsQ+nthQJAZZXXeu6C\n"
        "94JyNMuRvyVlRwMeW+koxp705xsklQRyMAeapwmYsRtXw6jRGHXKXwKN15lj3zQf\n"
        "UmR8Qxe3QXnFQg==\n"
        "-----END PRIVATE KEY-----\n";

    // encrypt
    BIO* bioPrivate = BIO_new_mem_buf(strPrivateKey, -1);
    m_pkey_pvt =
        PEM_read_bio_PrivateKey(bioPrivate, &m_pkey_pvt, nullptr, nullptr);

    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, nullptr);
    if (m_rsa_handle_keyctx_pvt == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    size_t outlen;
    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_encrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* FIXME: parameterize the padding scheme */
    if (1
        != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                        RSA_NO_PADDING)) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            NULL,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
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
    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* FIXME: parameterize the padding scheme */
    if (1
        != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                        RSA_NO_PADDING)) {
        std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
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
