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
    if (m_pkey_pub != nullptr) {
        EVP_PKEY_free(m_pkey_pub);
        m_pkey_pub = nullptr;
    }
    if (m_pkey_pvt != nullptr) {
        EVP_PKEY_free(m_pkey_pvt);
        m_pkey_pvt = nullptr;
    }
    if (m_params != nullptr) {
        OSSL_PARAM_free(m_params);
        m_params = nullptr;
    }
    if (m_libctx != nullptr) {
        OSSL_LIB_CTX_free(m_libctx);
        m_libctx = nullptr;
    }
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    if (m_SigningKeyCtxDirect != nullptr) {
        EVP_PKEY_CTX_free(m_SigningKeyCtxDirect);
        m_SigningKeyCtxDirect = nullptr;
    }
    if (m_VerifyKeyCtxDirect != nullptr) {
        EVP_PKEY_CTX_free(m_VerifyKeyCtxDirect);
        m_VerifyKeyCtxDirect = nullptr;
    }
    if (m_SignCtx != nullptr) {
        EVP_MD_CTX_free(m_SignCtx);
        m_SignCtx = nullptr;
    }
    if (m_VerifyCtx != nullptr) {
        EVP_MD_CTX_free(m_VerifyCtx);
        m_VerifyCtx = nullptr;
    }
}

bool
OpenSSLRsaBase::init()
{
    /* digest params to be added only for PADDED mode*/
    if (m_padding_mode != ALCP_TEST_RSA_NO_PADDING) {
        switch (m_digest_info.dt_len) {
            /* FIXME: add more cases here */
            case ALC_DIGEST_LEN_256:
                m_digest_str = "sha256";
                break;
            case ALC_DIGEST_LEN_512:
                m_digest_str = "sha512";
                break;
            default:
                std::cout << __func__ << ":" << "Invalid digest length"
                          << std::endl;
                return false;
        }
        m_md_type = EVP_get_digestbyname(m_digest_str);
        if (m_md_type == nullptr) {
            std::cout << __func__ << ":" << "Digest type is invalid"
                      << std::endl;
            return false;
        }
    }

    /* now build key params */
    unsigned long Exponent = 0x10001;
    BIGNUM *      mod_BN = nullptr, *pvt_exponent_BN = nullptr, *P_BN = nullptr,
           *Q_BN = nullptr, *DP_BN = nullptr, *DQ_BN = nullptr,
           *QINV_BN = nullptr;

    if (m_key_len * 8 == KEY_SIZE_1024) {
        mod_BN =
            BN_bin2bn(PubKey_Modulus_1024, sizeof(PubKey_Modulus_1024), NULL);
        pvt_exponent_BN =
            BN_bin2bn(PvtKey_Exponent_1024, sizeof(PvtKey_Exponent_1024), NULL);
        P_BN = BN_bin2bn(
            PvtKey_P_Modulus_1024, sizeof(PvtKey_P_Modulus_1024), NULL);
        Q_BN = BN_bin2bn(
            PvtKey_Q_Modulus_1024, sizeof(PvtKey_Q_Modulus_1024), NULL);
        DP_BN = BN_bin2bn(PvtKey_DP_EXP_1024, sizeof(PvtKey_DP_EXP_1024), NULL);
        DQ_BN = BN_bin2bn(PvtKey_DQ_EXP_1024, sizeof(PvtKey_DQ_EXP_1024), NULL);
        QINV_BN = BN_bin2bn(
            PvtKey_Q_ModulusINV_1024, sizeof(PvtKey_Q_ModulusINV_1024), NULL);
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        mod_BN =
            BN_bin2bn(PubKey_Modulus_2048, sizeof(PubKey_Modulus_2048), NULL);
        pvt_exponent_BN =
            BN_bin2bn(PvtKey_Exponent_2048, sizeof(PvtKey_Exponent_2048), NULL);
        P_BN = BN_bin2bn(
            PvtKey_P_Modulus_2048, sizeof(PvtKey_P_Modulus_2048), NULL);
        Q_BN = BN_bin2bn(
            PvtKey_Q_Modulus_2048, sizeof(PvtKey_Q_Modulus_2048), NULL);
        DP_BN = BN_bin2bn(PvtKey_DP_EXP_2048, sizeof(PvtKey_DP_EXP_2048), NULL);
        DQ_BN = BN_bin2bn(PvtKey_DQ_EXP_2048, sizeof(PvtKey_DQ_EXP_2048), NULL);
        QINV_BN = BN_bin2bn(
            PvtKey_Q_ModulusINV_2048, sizeof(PvtKey_Q_ModulusINV_2048), NULL);
    } else {
        std::cout << __func__ << ":" << "Invalid key len value" << std::endl;
        return false;
    }

    /* build the params needed to generate keys */
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();

    /* components for public key */
    OSSL_PARAM_BLD_push_BN(param_bld, "n", mod_BN);
    OSSL_PARAM_BLD_push_ulong(param_bld, "e", Exponent);

    /* components for pvt key */
    OSSL_PARAM_BLD_push_BN(param_bld, "d", pvt_exponent_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor1", P_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor2", Q_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent1", DP_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent2", DQ_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-coefficient1", QINV_BN);

    OSSL_PARAM_free(m_params);

    m_params = OSSL_PARAM_BLD_to_param(param_bld);

    OSSL_PARAM_BLD_free(param_bld);

    /* free all these Bignums after use */
    BN_free(mod_BN);
    BN_free(pvt_exponent_BN);
    BN_free(P_BN);
    BN_free(Q_BN);
    BN_free(DP_BN);
    BN_free(DQ_BN);
    BN_free(QINV_BN);

    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}

bool
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    return true;
    UNREF(data);
}

bool
OpenSSLRsaBase::SetPublicKeyBigNum(const alcp_rsa_data_t& data)
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pub)) {
        std::cout << __func__ << ":" << "EVP_PKEY_fromdata_init failed"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_fromdata(
            m_rsa_handle_keyctx_pub, &m_pkey_pub, EVP_PKEY_PUBLIC_KEY, m_params)
        != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_fromdata failed"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << __func__ << ":" << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_pkey_pub == nullptr) {
        std::cout << __func__ << ":"
                  << "m_pkey is Null: Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }

    /* Set encrypt/decrypt context */
    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey_pub, NULL);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << __func__ << ":" << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_encrypt_init(m_rsa_handle_keyctx_pub) != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_encrypt_init returned Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* set signing key context*/
    if (m_VerifyCtx != nullptr) {
        EVP_MD_CTX_free(m_VerifyCtx);
        m_VerifyCtx = nullptr;
    }
    m_VerifyCtx = EVP_MD_CTX_new();
    if (m_VerifyCtx == NULL) {
        std::cout << __func__ << ":" << "EVP_MD_CTX_new failed" << std::endl;
        return false;
    }
    if (1
        != EVP_DigestVerifyInit(
            m_VerifyCtx, &m_VerifyKeyCtx, m_md_type, NULL, m_pkey_pub)) {
        std::cout << __func__ << ":"
                  << "EVP_DigestVerifyInit_ex returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    /* set verify key context for verifying signature of a hash (direct) */
    if (m_VerifyKeyCtxDirect != nullptr) {
        EVP_PKEY_CTX_free(m_VerifyKeyCtxDirect);
        m_VerifyKeyCtxDirect = nullptr;
    }
    m_VerifyKeyCtxDirect =
        EVP_PKEY_CTX_new_from_pkey(m_libctx, m_pkey_pub, NULL);
    if (m_VerifyKeyCtxDirect == nullptr) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_CTX_new_from_pkey returned null Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_verify_init(m_VerifyKeyCtxDirect) != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_verify_init Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* only called for Non Padded modes */
    if (m_padding_mode != ALCP_TEST_RSA_NO_PADDING) {
        if (EVP_PKEY_CTX_set_signature_md(m_VerifyKeyCtxDirect, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_signature_md returned: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    }
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                         RSA_NO_PADDING)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        /* set padding mode parameters */
        if (EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                         RSA_PKCS1_OAEP_PADDING)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pub, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_oaep_md returned Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pub, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_mgf1_md returned Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    }
    /* set Sign/verify padding mode*/
    else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_VerifyKeyCtx,
                                            RSA_PKCS1_PSS_PADDING)) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        /* for pss direct */
        EVP_PKEY_CTX_set_rsa_padding(m_VerifyKeyCtxDirect,
                                     RSA_PKCS1_PSS_PADDING);
        if (1
            != EVP_PKEY_CTX_set_rsa_pss_saltlen(m_VerifyKeyCtx,
                                                data.m_salt_len)) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_pss_saltlen "
                         "returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_VerifyKeyCtx,
                                            RSA_PKCS1_PADDING)) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned "
                         "null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        /* for pkcs direct */
        EVP_PKEY_CTX_set_rsa_padding(m_VerifyKeyCtxDirect, RSA_PKCS1_PADDING);
    } else {
        std::cout << __func__ << ":" << "Invalid padding mode!" << std::endl;
        return false;
    }

    return true;
}

bool
OpenSSLRsaBase::SetPrivateKeyBigNum(const alcp_rsa_data_t& data)
{
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (m_rsa_handle_keyctx_pvt == nullptr) {
        std::cout << __func__
                  << ":EVP_PKEY_CTX_new_from_name returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pvt) != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_fromdata_init failed"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_fromdata(m_rsa_handle_keyctx_pvt,
                          &m_pkey_pvt,
                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                          m_params)
        != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_fromdata failed"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_pkey_pvt == nullptr) {
        std::cout << __func__ << ":" << "Null pvt key key : Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }

    /* create context for encrypt / decrypt */
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, NULL);
    if (EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt) != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_decrypt_init failed: Error: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* create ctx for signing an arbitrary length message */
    if (m_SignCtx != nullptr) {
        EVP_MD_CTX_free(m_SignCtx);
        m_SignCtx = nullptr;
    }
    m_SignCtx = EVP_MD_CTX_new();
    if (m_SignCtx == NULL) {
        std::cout << __func__ << ":" << "EVP_MD_CTX_new failed" << std::endl;
        return false;
    }
    if (EVP_DigestSignInit(
            m_SignCtx, &m_SigningKeyCtx, m_md_type, nullptr, m_pkey_pvt)
        != 1) {
        std::cout << __func__ << ":"
                  << "EVP_DigestSignInit returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    /* create signing key context for Signing a Hash (Direct) */
    /* now pass the digest output to sign */
    if (m_SigningKeyCtxDirect != nullptr) {
        EVP_PKEY_CTX_free(m_SigningKeyCtxDirect);
        m_SigningKeyCtxDirect = nullptr;
    }
    m_SigningKeyCtxDirect =
        EVP_PKEY_CTX_new_from_pkey(m_libctx, m_pkey_pvt, NULL);
    if (m_SigningKeyCtxDirect == nullptr) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_CTX_new_from_pkey returned null Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_sign_init(m_SigningKeyCtxDirect) != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_sign_init Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    /* this need not be called for padding mode */
    if (m_rsa_algo.compare("SignVerify") == 0
        || m_rsa_algo.compare("DigestSignVerify") == 0) {
        if (EVP_PKEY_CTX_set_signature_md(m_SigningKeyCtxDirect, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_signature_md returned: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    }

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                         RSA_NO_PADDING)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding failed: Error: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_OAEP) {
        if (EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                         RSA_PKCS1_OAEP_PADDING)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding failed: Error: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pvt, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_oaep_md failed: Error: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pvt, m_md_type)
            != 1) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_mgf1_md failed: Error: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_SigningKeyCtx,
                                            RSA_PKCS1_PSS_PADDING)) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        /* set salt len */
        if (1
            != EVP_PKEY_CTX_set_rsa_pss_saltlen(m_SigningKeyCtx,
                                                data.m_salt_len)) {
            std::cout
                << __func__ << ":"
                << "EVP_PKEY_CTX_set_rsa_pss_saltlen returned null: Error:"
                << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        /* for pss direct */
        EVP_PKEY_CTX_set_rsa_padding(m_SigningKeyCtxDirect,
                                     RSA_PKCS1_PSS_PADDING);
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_SigningKeyCtx,
                                            RSA_PKCS1_PADDING)) {
            std::cout << __func__ << ":"
                      << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
        /* for pkcs direct */
        EVP_PKEY_CTX_set_rsa_padding(m_SigningKeyCtxDirect, RSA_PKCS1_PADDING);
    } else {
        std::cout << __func__ << ":"
                  << "SetPrivateKey: Error: Invalid padding mode!" << std::endl;
        return false;
    }

    return true;
}

bool
OpenSSLRsaBase::ValidateKeys()
{
    return true;
}

int
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    int    ret_val = 0;
    size_t outlen;

    /* call encrypt */
    if (EVP_PKEY_encrypt(
            m_rsa_handle_keyctx_pub, NULL, &outlen, data.m_msg, data.m_msg_len)
        != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_encrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                         data.m_encrypted_data,
                         &outlen,
                         data.m_msg,
                         data.m_msg_len)
        != 1) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }

    return ret_val;
}

int
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    int    ret_val = 0;
    size_t outlen  = 0;

    /* now call decrypt */
    if (EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                         NULL,
                         &outlen,
                         data.m_encrypted_data,
                         outlen)
        != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    if (EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                         data.m_decrypted_data,
                         &outlen,
                         data.m_encrypted_data,
                         outlen)
        != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    return ret_val;
}

/* sign verify */
bool
OpenSSLRsaBase::Sign(const alcp_rsa_data_t& data)
{
    unsigned int outsize   = 0;
    size_t       sign_size = 0;

    /* calculate digest and then pass the digest output to sign */
    if (EVP_DigestInit(m_SignCtx, m_md_type) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestInit returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestUpdate(m_SignCtx, data.m_msg, data.m_msg_len) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestUpdate returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestFinal_ex(m_SignCtx, data.m_digest, &outsize) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestFinal_ex returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    /* calculate signature length */
    if (EVP_PKEY_sign(
            m_SigningKeyCtxDirect, NULL, &sign_size, data.m_digest, outsize)
        != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_sign returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    m_sig_len = sign_size;
    if (EVP_PKEY_sign(m_SigningKeyCtxDirect,
                      data.m_signature,
                      &sign_size,
                      data.m_digest,
                      outsize)
        != 1) {
        std::cout << __func__ << ":" << "EVP_PKEY_sign returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::Verify(const alcp_rsa_data_t& data)
{
    unsigned int outsize = 0;
    /* calculate digest and then pass the digest output to verify, to do
     * signature verification */
    if (EVP_DigestInit(m_VerifyCtx, m_md_type) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestInit returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestUpdate(m_VerifyCtx, data.m_msg, data.m_msg_len) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestUpdate returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestFinal_ex(m_VerifyCtx, data.m_digest, &outsize) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestFinal_ex returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_PKEY_verify(m_VerifyKeyCtxDirect,
                        data.m_signature,
                        m_sig_len,
                        data.m_digest,
                        outsize)
        != 1) {
        std::cout << __func__ << ":"
                  << "EVP_PKEY_verify returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLRsaBase::DigestSign(const alcp_rsa_data_t& data)
{
    size_t sig_len = 0;

    if (EVP_DigestSignUpdate(m_SignCtx, data.m_msg, data.m_msg_len) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestSignUpdate returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestSignFinal(m_SignCtx, NULL, &sig_len) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestSignFinal returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestSignFinal(m_SignCtx, data.m_signature, &sig_len) != 1) {
        std::cout << __func__ << ":" << "EVP_DigestSignFinal returned: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}
bool
OpenSSLRsaBase::DigestVerify(const alcp_rsa_data_t& data)
{
    size_t sig_len = m_hash_len * 8;
    /* update padding mode*/
    if (EVP_DigestVerifyUpdate(m_VerifyCtx, data.m_msg, data.m_msg_len) != 1) {
        std::cout << __func__ << ":"
                  << "Error: EVP_DigestVerifyUpdate returned:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (EVP_DigestVerifyFinal(m_VerifyCtx, data.m_signature, sig_len) != 1) {
        std::cout << __func__ << ":" << "Error: EVP_DigestVerifyFinal:"
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
