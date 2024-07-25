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

static inline void
convert_to_bignum(const Uint8* bytes, Uint64* bigNum, Uint64 size)
{
    Uint8* p_res = (Uint8*)(bigNum);
    for (Int64 i = size - 1, j = 0; i >= 0; --i, ++j) {
        p_res[j] = bytes[i];
    }
}

namespace alcp::testing {

AlcpRsaBase::AlcpRsaBase() {}

bool
AlcpRsaBase::init()
{
    alc_error_t err  = ALC_ERROR_NONE;
    Uint64      size = 0;
    if (m_key_len * 8 == KEY_SIZE_1024)
        size = alcp_rsa_context_size();
    else if (m_key_len * 8 == KEY_SIZE_2048)
        size = alcp_rsa_context_size();
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
        err = alcp_rsa_request(m_rsa_handle);
    else if (m_key_len * 8 == KEY_SIZE_2048)
        err = alcp_rsa_request(m_rsa_handle);

    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_request " << err << std::endl;
        return false;
    }

    /* only for padding mode*/
    if (m_padding_mode != ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_add_digest(m_rsa_handle, m_digest_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_rsa_add_digest" << err << std::endl;
            return false;
        }
        /*call mask gen function */
        err = alcp_rsa_add_mgf(m_rsa_handle, m_mgf_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_rsa_add_mgf " << err << std::endl;
            return false;
        }
        /* call this only for PKCS*/
        if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
            m_digest_info_index =
                alcp_rsa_get_digest_info_index(m_digest_info.dt_mode);
            if (m_digest_info_index == -1) {
                std::cout << "Error in alcp_rsa_get_digest_info_index"
                          << std::endl;
                return false;
            }
            m_digest_info_size =
                alcp_rsa_get_digest_info_size(m_digest_info.dt_mode);
            if (m_digest_info_size == 0) {
                std::cout << "Error in alcp_rsa_get_digest_info_size"
                          << std::endl;
                return false;
            }
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
    /* free this only for PKCS */
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        free(m_pkcs_hash_with_info);
    }
}

bool
AlcpRsaBase::SetPublicKeyBigNum(const alcp_rsa_data_t& data)
{
    alc_error_t err       = ALC_ERROR_NONE;
    Uint64      size_2048 = 0, size_1024 = 0;

    m_pub_key_exp     = 0x10001;
    BigNum public_key = { &m_pub_key_exp, 1 };

    size_2048 = sizeof(PubKey_Modulus_2048);
    size_1024 = sizeof(PubKey_Modulus_1024);

    /* for keysize 2048*/
    Uint64 Modulus_BigNum_2048[size_2048 / 8];
    convert_to_bignum(PubKey_Modulus_2048, Modulus_BigNum_2048, size_2048);
    BigNum m_modulus_2048 = { Modulus_BigNum_2048, size_2048 / 8 };

    Uint64 Modulus_BigNum_1024[size_1024 / 8];
    convert_to_bignum(PubKey_Modulus_1024, Modulus_BigNum_1024, size_1024);
    BigNum m_modulus_1024 = { Modulus_BigNum_1024, size_1024 / 8 };

    /* set bignum keys */
    if (m_key_len * 8 == KEY_SIZE_2048) {
        err = alcp_rsa_set_bignum_public_key(
            m_rsa_handle, &public_key, &m_modulus_2048);
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        err = alcp_rsa_set_bignum_public_key(
            m_rsa_handle, &public_key, &m_modulus_1024);
    } else {
        std::cout << "Invalid keysize in RSA SetPublicKeyBigNum" << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_set_publickey " << err << "for keysize "
                  << m_key_len * 8 << std::endl;
        return false;
    }
    return true;
}

bool
AlcpRsaBase::SetPrivateKeyBigNum(const alcp_rsa_data_t& data)
{
    alc_error_t err       = ALC_ERROR_NONE;
    Uint64      size_2048 = 0, size_1024 = 0;

    size_2048 = sizeof(PvtKey_DP_EXP_2048);
    size_1024 = sizeof(PvtKey_DP_EXP_1024);

    Uint64 Modulus_BigNum_2048[sizeof(PubKey_Modulus_2048) / 8];
    convert_to_bignum(
        PubKey_Modulus_2048, Modulus_BigNum_2048, sizeof(PubKey_Modulus_2048));
    BigNum m_modulus_2048 = { Modulus_BigNum_2048,
                              sizeof(PubKey_Modulus_2048) / 8 };

    Uint64 Modulus_BigNum_1024[sizeof(PubKey_Modulus_1024) / 8];
    convert_to_bignum(
        PubKey_Modulus_1024, Modulus_BigNum_1024, sizeof(PubKey_Modulus_1024));
    BigNum m_modulus_1024 = { Modulus_BigNum_1024,
                              sizeof(PubKey_Modulus_1024) / 8 };

    /* key size 2048 */
    Uint64 DP_BigNum_2048[size_2048 / 8];
    Uint64 DQ_BigNum_2048[size_2048 / 8];
    Uint64 P_BigNum_2048[size_2048 / 8];
    Uint64 Q_BigNum_2048[size_2048 / 8];
    Uint64 QINV_BigNum_2048[size_2048 / 8];

    Uint64 DP_BigNum_1024[size_1024 / 8];
    Uint64 DQ_BigNum_1024[size_1024 / 8];
    Uint64 P_BigNum_1024[size_1024 / 8];
    Uint64 Q_BigNum_1024[size_1024 / 8];
    Uint64 QINV_BigNum_1024[size_1024 / 8];

    convert_to_bignum(PvtKey_DP_EXP_2048, DP_BigNum_2048, size_2048);
    convert_to_bignum(PvtKey_DQ_EXP_2048, DQ_BigNum_2048, size_2048);
    convert_to_bignum(PvtKey_P_Modulus_2048, P_BigNum_2048, size_2048);
    convert_to_bignum(PvtKey_Q_Modulus_2048, Q_BigNum_2048, size_2048);
    convert_to_bignum(PvtKey_Q_ModulusINV_2048, QINV_BigNum_2048, size_2048);

    convert_to_bignum(PvtKey_DP_EXP_1024, DP_BigNum_1024, size_1024);
    convert_to_bignum(PvtKey_DQ_EXP_1024, DQ_BigNum_1024, size_1024);
    convert_to_bignum(PvtKey_P_Modulus_1024, P_BigNum_1024, size_1024);
    convert_to_bignum(PvtKey_Q_Modulus_1024, Q_BigNum_1024, size_1024);
    convert_to_bignum(PvtKey_Q_ModulusINV_1024, QINV_BigNum_1024, size_1024);

    BigNum dp_2048   = { DP_BigNum_2048, size_2048 / 8 };
    BigNum dq_2048   = { DQ_BigNum_2048, size_2048 / 8 };
    BigNum p_2048    = { P_BigNum_2048, size_2048 / 8 };
    BigNum q_2048    = { Q_BigNum_2048, size_2048 / 8 };
    BigNum qinv_2048 = { QINV_BigNum_2048, size_2048 / 8 };

    BigNum dp_1024   = { DP_BigNum_1024, size_1024 / 8 };
    BigNum dq_1024   = { DQ_BigNum_1024, size_1024 / 8 };
    BigNum p_1024    = { P_BigNum_1024, size_1024 / 8 };
    BigNum q_1024    = { Q_BigNum_1024, size_1024 / 8 };
    BigNum qinv_1024 = { QINV_BigNum_1024, size_1024 / 8 };

    if (m_key_len * 8 == KEY_SIZE_2048) {
        err = alcp_rsa_set_bignum_private_key(m_rsa_handle,
                                              &dp_2048,
                                              &dq_2048,
                                              &p_2048,
                                              &q_2048,
                                              &qinv_2048,
                                              &m_modulus_2048);
    } else if (m_key_len * 8 == KEY_SIZE_1024) {
        err = alcp_rsa_set_bignum_private_key(m_rsa_handle,
                                              &dp_1024,
                                              &dq_1024,
                                              &p_1024,
                                              &q_1024,
                                              &qinv_1024,
                                              &m_modulus_1024);
    } else {
        std::cout << "Invalid keysize in RSA SetPrivateKeyBigNum" << std::endl;
        return false;
    }
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_set_bignum_private_key " << err
                  << "for keysize " << m_key_len * 8 << std::endl;
        return false;
    }
    return true;
}

bool
AlcpRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    /*FIXME: where should this be defined? */
    m_pub_key_exp   = 0x10001;
    alc_error_t err = ALC_ERROR_NONE;

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
    alc_error_t err = ALC_ERROR_NONE;

    /* no padding mode */
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_publickey_encrypt(
            m_rsa_handle, data.m_msg, data.m_key_len, data.m_encrypted_data);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        err = alcp_rsa_publickey_encrypt_pkcs1v15(m_rsa_handle,
                                                  data.m_msg,
                                                  data.m_msg_len,
                                                  data.m_encrypted_data,
                                                  data.m_random_pad);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        err = alcp_rsa_publickey_encrypt_oaep(m_rsa_handle,
                                              data.m_msg,
                                              data.m_msg_len,
                                              data.m_label,
                                              data.m_label_size,
                                              data.m_pseed,
                                              data.m_encrypted_data);
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    if (alcp_is_error(err)) {
        return err;
    }
    return 0;
}

int
AlcpRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    alc_error_t err       = ALC_ERROR_NONE;
    Uint64      text_size = 0;

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        err = alcp_rsa_privatekey_decrypt(m_rsa_handle,
                                          ALCP_RSA_PADDING_NONE,
                                          data.m_encrypted_data,
                                          data.m_key_len,
                                          data.m_decrypted_data);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        err = alcp_rsa_privatekey_decrypt_pkcs1v15(m_rsa_handle,
                                                   data.m_encrypted_data,
                                                   data.m_decrypted_data,
                                                   &text_size);
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

/* sign verify on a calculated digest */
bool
AlcpRsaBase::Sign(const alcp_rsa_data_t& data)
{
    /* first sign then digest */
    alc_error_t err = ALC_ERROR_NONE;

    if (m_rsa_digest_handle == nullptr) {
        m_rsa_digest_handle          = new alc_digest_handle_t;
        m_rsa_digest_handle->context = malloc(alcp_digest_context_size());
    } else if (m_rsa_digest_handle->context == nullptr) {
        m_rsa_digest_handle->context = malloc(alcp_digest_context_size());
    } else {
        alcp_digest_finish(m_rsa_digest_handle);
        if (m_rsa_digest_handle->context != nullptr) {
            free(m_rsa_digest_handle->context);
            m_rsa_digest_handle->context = nullptr;
        }
        delete m_rsa_digest_handle;
        m_rsa_digest_handle          = nullptr;
        m_rsa_digest_handle          = new alc_digest_handle_t;
        m_rsa_digest_handle->context = malloc(alcp_digest_context_size());
    }

    err = alcp_digest_request(m_digest_info.dt_mode, m_rsa_digest_handle);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_request:" << err << std::endl;
        return false;
    }
    err = alcp_digest_init(m_rsa_digest_handle);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_init:" << err << std::endl;
        return false;
    }
    if (data.m_msg != nullptr && data.m_msg_len > 0) {
        err =
            alcp_digest_update(m_rsa_digest_handle, data.m_msg, data.m_msg_len);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_digest_update:" << err
                      << std::endl;
            return false;
        }
    }
    err = alcp_digest_finalize(m_rsa_digest_handle, data.m_digest, m_hash_len);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_finalize:" << err << std::endl;
        return false;
    }

    if (m_rsa_digest_handle != nullptr) {
        alcp_digest_finish(m_rsa_digest_handle);
        if (m_rsa_digest_handle->context != nullptr) {
            free(m_rsa_digest_handle->context);
            m_rsa_digest_handle->context = nullptr;
        }
        delete m_rsa_digest_handle;
        m_rsa_digest_handle = nullptr;
    }

    /* now calculate signature on data.m_digest */
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_add_digest(m_rsa_handle, m_digest_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_rsa_add_digest:" << err
                      << std::endl;
            return false;
        }
        err = alcp_rsa_add_mgf(m_rsa_handle, m_digest_info.dt_mode);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_rsa_add_mgf:" << err << std::endl;
            return false;
        }
        err = alcp_rsa_privatekey_sign_hash_pss(m_rsa_handle,
                                                data.m_digest,
                                                m_hash_len,
                                                data.m_salt,
                                                data.m_salt_len,
                                                data.m_signature);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_rsa_privatekey_sign_hash_pss:"
                      << err << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        if (m_pkcs_hash_with_info != nullptr) {
            free(m_pkcs_hash_with_info);
        }
        m_pkcs_hash_with_info = (Uint8*)malloc(m_digest_info_size + m_hash_len);
        memcpy(m_pkcs_hash_with_info,
               DigestInfo[m_digest_info_index],
               m_digest_info_size);
        memcpy(m_pkcs_hash_with_info + m_digest_info_size,
               data.m_digest,
               m_hash_len);
        err = alcp_rsa_privatekey_sign_hash_pkcs1v15(m_rsa_handle,
                                                     m_pkcs_hash_with_info,
                                                     m_digest_info_size
                                                         + m_hash_len,
                                                     data.m_signature);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_digest_finalize:" << err
                      << std::endl;
            return false;
        }
    } else {
        std::cout << "Invalid/Unsupported padding mode for ALCP RSA Digest Sign"
                  << std::endl;
        return false;
    }
    return true;
}
bool
AlcpRsaBase::Verify(const alcp_rsa_data_t& data)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        err = alcp_rsa_publickey_verify_hash_pkcs1v15(m_rsa_handle,
                                                      m_pkcs_hash_with_info,
                                                      m_digest_info_size
                                                          + m_hash_len,
                                                      data.m_signature);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_rsa_publickey_verify_hash_pkcs1v15"
                      << err << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_publickey_verify_hash_pss(
            m_rsa_handle, data.m_digest, m_hash_len, data.m_signature);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_rsa_publickey_verify_hash_pss"
                      << err << std::endl;
            return false;
        }
    } else {
        std::cout
            << "Invalid/Unsupported padding mode for ALCP RSA Digest Verify"
            << std::endl;
        return false;
    }

    return true;
}

/* Perform sign on an arbitrary len message. First calculate digest,and
 * sign*/
bool
AlcpRsaBase::DigestSign(const alcp_rsa_data_t& data)
{
    alc_error_t err = ALC_ERROR_NONE;

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
    alc_error_t err = ALC_ERROR_NONE;
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
