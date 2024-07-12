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

#include "rsa/alc_rsa.hh"
#include "alcp/rsa.h"
#include "rsa/rsa.hh"
#include "rsa/rsa_keys.hh"
#include <cstring>

namespace alcp::testing {

AlcpRsaBase::AlcpRsaBase() {}

bool
AlcpRsaBase::init()
{
    alc_error_t err  = ALC_ERROR_NONE;
    Uint64      size = 0;
    if (m_key_len * 8 == KEY_SIZE_1024)
        size = alcp_rsa_context_size(KEY_SIZE_1024);
    else if (m_key_len * 8 == KEY_SIZE_2048)
        size = alcp_rsa_context_size(KEY_SIZE_2048);
    else {
        std::cout << "Invalid keysize in RSA Init" << std::endl;
        return false;
    }

    if (m_rsa_handle == nullptr) {
        m_rsa_handle          = new alc_rsa_handle_t;
        m_rsa_handle->context = malloc(size);
    } else if (m_rsa_handle->context == nullptr) {
        m_rsa_handle->context = malloc(size);
    } else {
        alcp_rsa_finish(m_rsa_handle);
    }

    if (m_key_len * 8 == KEY_SIZE_1024)
        err = alcp_rsa_request(KEY_SIZE_1024, m_rsa_handle);
    else if (m_key_len * 8 == KEY_SIZE_2048)
        err = alcp_rsa_request(KEY_SIZE_2048, m_rsa_handle);

    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_request " << err << std::endl;
        return false;
    }

    /* only for padding mode*/
    if (m_padding_mode != ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_add_digest(m_rsa_handle, m_digest_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_rsa_add_digest" << err << std::endl;
            return err;
        }
        /*call mask gen function */
        err = alcp_rsa_add_mgf(m_rsa_handle, m_mgf_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_rsa_add_mgf " << err << std::endl;
            return err;
        }
    }
    return true;
}

AlcpRsaBase::~AlcpRsaBase()
{
    if (m_rsa_handle != nullptr) {
        alcp_rsa_finish(m_rsa_handle);
        if (m_rsa_handle->context != nullptr) {
            free(m_rsa_handle->context);
            m_rsa_handle->context = nullptr;
        }
        delete m_rsa_handle;
    }
}

bool
AlcpRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    /*FIXME: where should this be defined? */
    m_pub_key_exp = 0x10001;
    alc_error_t err;

    /* Adding the public key for applying encryption */
    if (m_key_len * 8 == KEY_SIZE_1024) {
        err = alcp_rsa_set_publickey(
            m_rsa_handle, m_pub_key_exp, PubKey_Modulus_1024, data.m_key_len);
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        err = alcp_rsa_set_publickey(
            m_rsa_handle, m_pub_key_exp, PubKey_Modulus_2048, data.m_key_len);
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKey" << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_set_publickey " << err << std::endl;
        return false;
    }

    return true;
}

bool
AlcpRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_key_len * 8 == KEY_SIZE_1024) {
        err = alcp_rsa_set_privatekey(m_rsa_handle,
                                      PvtKey_DP_EXP_1024,
                                      PvtKey_DQ_EXP_1024,
                                      PvtKey_P_Modulus_1024,
                                      PvtKey_Q_Modulus_1024,
                                      PvtKey_Q_ModulusINV_1024,
                                      PvtKey_Modulus_1024,
                                      sizeof(PvtKey_P_Modulus_1024));
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        err = alcp_rsa_set_privatekey(m_rsa_handle,
                                      PvtKey_DP_EXP_2048,
                                      PvtKey_DQ_EXP_2048,
                                      PvtKey_P_Modulus_2048,
                                      PvtKey_Q_Modulus_2048,
                                      PvtKey_Q_ModulusINV_2048,
                                      PvtKey_Modulus_2048,
                                      sizeof(PvtKey_P_Modulus_2048));
    } else {
        std::cout << "Invalid key len detected in alcp_rsa_set_privatekey "
                  << err << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_set_privatekey " << err << std::endl;
        return false;
    }
    return true;
}

bool
AlcpRsaBase::ValidateKeys()
{
    return true;
}

int
AlcpRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    alc_error_t err;

    /* no padding mode */
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_publickey_encrypt(m_rsa_handle,
                                         ALCP_RSA_PADDING_NONE,
                                         data.m_msg,
                                         data.m_key_len,
                                         data.m_encrypted_data);
        if (alcp_is_error(err)) {
            return err;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        // Encrypt text
        err = alcp_rsa_publickey_encrypt_oaep(m_rsa_handle,
                                              data.m_msg,
                                              data.m_msg_len,
                                              data.m_label,
                                              data.m_label_size,
                                              data.m_pseed,
                                              data.m_encrypted_data);
        if (alcp_is_error(err)) {
            return err;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    return 0;
}

int
AlcpRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    alc_error_t err;
    Uint64      text_size = 0;

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_privatekey_decrypt(m_rsa_handle,
                                          ALCP_RSA_PADDING_NONE,
                                          data.m_encrypted_data,
                                          data.m_key_len,
                                          data.m_decrypted_data);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        err = alcp_rsa_privatekey_decrypt_oaep(m_rsa_handle,
                                               data.m_encrypted_data,
                                               data.m_key_len,
                                               data.m_label,
                                               data.m_label_size,
                                               data.m_decrypted_data,
                                               &text_size);
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_privatekey_decrypt " << err
                  << std::endl;
        return err;
    }
    return 0;
}

/* sign verify */
bool
AlcpRsaBase::Sign(const alcp_rsa_data_t& data)
{
    return true;
}
bool
AlcpRsaBase::Verify(const alcp_rsa_data_t& data)
{
    return true;
}
bool
AlcpRsaBase::DigestSign(const alcp_rsa_data_t& data)
{
    alc_error_t err;

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_privatekey_sign_pss(m_rsa_handle,
                                           true,
                                           data.m_msg,
                                           data.m_msg_len,
                                           data.m_salt,
                                           data.m_salt_len,
                                           data.m_signature);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        /* sign function */
        err = alcp_rsa_privatekey_sign_pkcs1v15(
            m_rsa_handle, true, data.m_msg, data.m_msg_len, data.m_signature);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_rsa_privatekey_sign_pkcs1v15 " << err
                      << std::endl;
            return false;
        }
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa sign function" << err << std::endl;
        return false;
    }
    return true;
}

bool
AlcpRsaBase::DigestVerify(const alcp_rsa_data_t& data)
{
    alc_error_t err;
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_publickey_verify_pss(
            m_rsa_handle, data.m_msg, data.m_msg_len, data.m_signature);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        err = alcp_rsa_publickey_verify_pkcs1v15(
            m_rsa_handle, data.m_msg, data.m_msg_len, data.m_signature);
    } else {
        std::cout << "Unsupported padding mode!" << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_publickey_verify" << err << std::endl;
        return false;
    }
    return true;
}

bool
AlcpRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
