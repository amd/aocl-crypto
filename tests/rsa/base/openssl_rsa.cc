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
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
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
    // if (m_mdctx != nullptr) {
    //     EVP_MD_CTX_free(m_mdctx);
    //     m_mdctx = nullptr;
    // }
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
    char* digest_str;
    switch (m_digest_info.dt_len) {
        /* FIXME: add more cases here */
        case ALC_DIGEST_LEN_256:
            digest_str = "sha256";
            break;
        case ALC_DIGEST_LEN_512:
            digest_str = "sha512";
            break;
        default:
            std::cout << "Invalid digest length" << std::endl;
            return 1;
    }
    m_md_type = EVP_get_digestbyname(digest_str);
    if (m_md_type == nullptr) {
        std::cout << "Digest type is invalid" << std::endl;
        return 1;
    }
    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    unsigned long Exponent = 0x10001;
    int           ret_val;
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
        std::cout << "Invalid key len value" << std::endl;
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

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_fromdata_init failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (1
        != EVP_PKEY_fromdata(m_rsa_handle_keyctx_pub,
                             &m_pkey_pub,
                             EVP_PKEY_PUBLIC_KEY,
                             m_params)) {
        std::cout << "EVP_PKEY_fromdata failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_pkey_pub == nullptr) {
        std::cout << "Null key : Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }

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
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    int retval;
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (m_rsa_handle_keyctx_pvt == nullptr) {
        std::cout << "EVP_PKEY_CTX_new_from_name returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_fromdata_init failed" << std::endl;
        retval = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (1
        != EVP_PKEY_fromdata(m_rsa_handle_keyctx_pvt,
                             &m_pkey_pvt,
                             OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                             m_params)) {
        std::cout << "EVP_PKEY_fromdata failed" << std::endl;
        retval = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (m_pkey_pvt == nullptr) {
        std::cout << "Null key : Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
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

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey_pub, NULL);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }
    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_encrypt_init failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        /* set padding mode parameters */
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pub,
                                            m_md_type)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pub,
                                            m_md_type)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }

    /* call encrypt */
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            NULL,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            data.m_encrypted_data,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    return 0;
}

int
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    int    ret_val = 0;
    size_t outlen;

    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, NULL);
    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {

        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pvt,
                                            m_md_type)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pvt,
                                            m_md_type)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    /* now call decrypt */
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    return 0;
}

/* sign verify */
int
OpenSSLRsaBase::Sign(const alcp_rsa_data_t& data)
{
    size_t sig_len = 0;

    m_mdctx = EVP_MD_CTX_new();
    if (m_mdctx == NULL) {
        std::cout << "EVP_MD_CTX_new failed" << std::endl;
        return 1;
    }
    /* Initialize MD context for signing. */
    if (1 != EVP_DigestSignInit(m_mdctx, NULL, m_md_type, NULL, m_pkey_pvt)) {
        std::cout << "EVP_DigestSignInit returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }

    /* set RSA padding scheme and salt len*/
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, NULL);
    if (1
        != EVP_DigestSignInit(
            m_mdctx, &m_rsa_handle_keyctx_pvt, m_md_type, NULL, m_pkey_pvt)) {
        std::cout << "EVP_DigestSignInit returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }

    /* update padding mode*/
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_PSS_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_pss_saltlen(m_rsa_handle_keyctx_pvt,
                                                data.m_salt_len)) {
            std::cout
                << "EVP_PKEY_CTX_set_rsa_pss_saltlen returned null: Error:"
                << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
        if (1 != EVP_DigestSignUpdate(m_mdctx, data.m_salt, data.m_salt_len)) {
            std::cout << "EVP_DigestSignUpdate salt len returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
    } else {
        std::cout << "Error: invalid padding mode" << std::endl;
        return 1;
    }
    /*
     * Feed data to be signed into the algorithm. This may
     * be called multiple times.
     */
    if (1 != EVP_DigestSignUpdate(m_mdctx, data.m_msg, data.m_msg_len)) {
        std::cout << "EVP_DigestSignUpdate returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }
    /* Determine signature length. */
    if (1 != EVP_DigestSignFinal(m_mdctx, NULL, &sig_len)) {
        std::cout << "EVP_DigestSignFinal returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }
    /* Generate signature. */
    if (1 != EVP_DigestSignFinal(m_mdctx, data.m_signature, &sig_len)) {
        std::cout << "EVP_DigestSignFinal returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }
    return 0;
}
int
OpenSSLRsaBase::Verify(const alcp_rsa_data_t& data)
{
    size_t sig_len = m_hash_len * 8;

    m_mdctx = EVP_MD_CTX_new();
    if (m_mdctx == NULL) {
        std::cout << "EVP_MD_CTX_new failed" << std::endl;
        return 1;
    }
    /* Initialize MD context for signing. */
    if (1 != EVP_DigestVerifyInit(m_mdctx, NULL, m_md_type, NULL, m_pkey_pub)) {
        std::cout << "EVP_DigestVerifyInit_ex returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey_pub, NULL);
    if (1
        != EVP_DigestVerifyInit(
            m_mdctx, &m_rsa_handle_keyctx_pub, m_md_type, NULL, m_pkey_pub)) {
        std::cout << "EVP_DigestVerifyInit_ex returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }

    /* set rsa padding mode*/
    if (m_padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_PSS_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_pss_saltlen(m_rsa_handle_keyctx_pub,
                                                data.m_salt_len)) {
            std::cout
                << "EVP_PKEY_CTX_set_rsa_pss_saltlen returned null: Error:"
                << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
        if (1
            != EVP_DigestVerifyUpdate(m_mdctx, data.m_salt, data.m_salt_len)) {
            std::cout << "EVP_DigestVerifyUpdate returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding returned null: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return 1;
        }
    } else {
        std::cout << "Error: Invalid padding mode for RSA verify" << std::endl;
        return 1;
    }

    /*
     * Feed data to be signed into the algorithm. This may
     * be called multiple times.
     */

    if (1 != EVP_DigestVerifyUpdate(m_mdctx, data.m_msg, data.m_msg_len)) {
        std::cout << "EVP_DigestVerifyUpdate returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }
    /* Verify signature. */
    if (1 != EVP_DigestVerifyFinal(m_mdctx, data.m_signature, sig_len)) {
        std::cout << "EVP_DigestVerifyFinal returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return 1;
    }

    return 0;
}

bool
OpenSSLRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
