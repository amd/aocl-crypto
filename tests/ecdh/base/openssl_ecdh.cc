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

#include "ecdh/openssl_ecdh.hh"
#include <cstddef>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <ostream>

namespace alcp::testing {

OpenSSLEcdhBase::OpenSSLEcdhBase(const alc_ec_info_t& info)
    : m_info{ info }
{
}

OpenSSLEcdhBase::~OpenSSLEcdhBase()
{
    OSSL_LIB_CTX_free(m_ec_handle);
    EVP_PKEY_free(m_pPrivateKey);
}

bool
OpenSSLEcdhBase::init(const alc_ec_info_t& info)
{
    m_info = info;
    switch (info.ecCurveId) {
        case ALCP_EC_SECP256R1:
            m_st = "prime256v1";
            break;
        case ALCP_EC_CURVE25519:
        default:
            m_st = "X25519";
    }
    m_pkeytype = m_st.c_str();
    return true;
}

bool
OpenSSLEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    Uint64 keyLength;

    EVP_PKEY_free(m_pPrivateKey);

    /*Initialize handle, generate or load KAT private key*/
    m_pPrivateKey = EVP_PKEY_new_raw_private_key_ex(m_ec_handle,
                                                    m_pkeytype,
                                                    NULL,
                                                    data.m_Peer_PvtKey,
                                                    data.m_Peer_PvtKeyLen);
    if (m_pPrivateKey == nullptr) {
        std::cout << "EVP_PKEY_new_raw_private_key_ex returned null: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }
    /* Get public key corresponding to the private key */
    if (1
        != EVP_PKEY_get_octet_string_param(m_pPrivateKey,
                                           "pub",
                                           data.m_Peer_PubKey,
                                           data.m_Peer_PubKeyLen,
                                           &keyLength)) {
        std::cout << "EVP_PKEY_get_octet_string_param: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLEcdhBase::SetPrivateKey(Uint8 private_key[], Uint64 len)
{
    if (m_info.ecCurveId == ALCP_EC_CURVE25519) {
        m_pPrivateKey = EVP_PKEY_new_raw_private_key_ex(
            m_ec_handle, m_pkeytype, NULL, private_key, len);
        if (m_pPrivateKey == nullptr) {
            std::cout << "EVP_PKEY_new_raw_private_key_ex returned null: Error:"
                      << ERR_get_error() << std::endl;
            return false;
        }
    } else {
        /* Private Key Creation */
        OSSL_PARAM_BLD* param_bld;
        BIGNUM*         priv;
        EVP_PKEY_CTX*   ctx_pkey;
        OSSL_PARAM*     params = nullptr;

        // Create the BigNumber representation of the Private key
        priv = BN_bin2bn(private_key, len, NULL);
        // Initiate the Pram Builder
        param_bld = OSSL_PARAM_BLD_new();
        // Build the Params
        if (priv != NULL && param_bld != NULL
            && OSSL_PARAM_BLD_push_utf8_string(
                param_bld, "group", m_pkeytype, 0)
            && OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv))
            params = OSSL_PARAM_BLD_to_param(param_bld);
        // Context for RAW to PKey conversion
        ctx_pkey = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        // Initiate RAW to PKey conversion
        if (ctx_pkey == NULL || params == NULL
            || EVP_PKEY_fromdata_init(ctx_pkey) <= 0
            || EVP_PKEY_fromdata(
                   ctx_pkey, &m_pPrivateKey, EVP_PKEY_KEYPAIR, params)
                   <= 0) {
            ERR_print_errors_fp(stderr);
            return false; // Error Status
        }
        // Free unused resources
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(priv);
        EVP_PKEY_CTX_free(ctx_pkey);
        OSSL_PARAM_free(params);
    }
    return true;
}

bool
OpenSSLEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data_peer1,
                                  const alcp_ecdh_data_t& data_peer2)
{
    // m_pPrivateKey is supposed to be populated by SetPrivateKey method
    Uint64        SecretkeyLength;
    EVP_PKEY*     externalPeerPubKey = nullptr;
    EVP_PKEY_CTX* KeyExchangeCtx     = nullptr;

    if (m_st == "X25519") {
        /* Load public key for other peer. */
        externalPeerPubKey =
            EVP_PKEY_new_raw_public_key_ex(m_ec_handle,
                                           m_pkeytype,
                                           NULL,
                                           data_peer2.m_Peer_PubKey,
                                           data_peer1.m_Peer_PubKeyLen);
        if (externalPeerPubKey == nullptr) {
            std::cout << "EVP_PKEY_new_raw_public_key_ex returned null: Error:"
                      << ERR_get_error() << std::endl;
            return false;
        }
        /* Create key exchange context. */
        KeyExchangeCtx =
            EVP_PKEY_CTX_new_from_pkey(m_ec_handle, m_pPrivateKey, NULL);
        if (KeyExchangeCtx == NULL) {
            std::cout << "EVP_PKEY_CTX_new_from_pkey returned null: Error:"
                      << ERR_get_error() << std::endl;
            return false;
        }
    } else if (m_st == "prime256v1") {
        OSSL_PARAM_BLD* param_bld;
        EVP_PKEY_CTX*   ctx_pkey;
        OSSL_PARAM*     params = nullptr;

        /* Public Key Creation */

        // Initiate the Pram Builder
        param_bld = OSSL_PARAM_BLD_new();
        // Build the Params
        if (param_bld != NULL
            && OSSL_PARAM_BLD_push_utf8_string(
                param_bld, "group", m_pkeytype, 0)
            && OSSL_PARAM_BLD_push_octet_string(param_bld,
                                                "pub",
                                                data_peer2.m_Peer_PubKey,
                                                data_peer2.m_Peer_PubKeyLen))
            params = OSSL_PARAM_BLD_to_param(param_bld);
        // Context for RAW to PKey conversion
        ctx_pkey = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (ctx_pkey == NULL || params == NULL
            || EVP_PKEY_fromdata_init(ctx_pkey) <= 0
            || EVP_PKEY_fromdata(
                   ctx_pkey, &externalPeerPubKey, EVP_PKEY_PUBLIC_KEY, params)
                   <= 0) {
            ERR_print_errors_fp(stderr);
            return false; // Error Status
        }
        // Free unused resources
        OSSL_PARAM_BLD_free(param_bld);
        EVP_PKEY_CTX_free(ctx_pkey);
        OSSL_PARAM_free(params);

        KeyExchangeCtx = EVP_PKEY_CTX_new(m_pPrivateKey, NULL);
    }

    /* Initialize derivation process. */
    if (EVP_PKEY_derive_init(KeyExchangeCtx) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cout << "EVP_PKEY_derive_init : Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* Configure each peer with the other peer's public key. */
    if (EVP_PKEY_derive_set_peer(KeyExchangeCtx, externalPeerPubKey) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cout << "EVP_PKEY_derive_set_peer : Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* Determine the secret length. */
    if (EVP_PKEY_derive(KeyExchangeCtx, NULL, &SecretkeyLength) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cout << "EVP_PKEY_derive secret len: Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* derive the shared secret key */
    if (EVP_PKEY_derive(
            KeyExchangeCtx, data_peer1.m_Peer_SecretKey, &SecretkeyLength)
        <= 0) {
        ERR_print_errors_fp(stderr);
        std::cout << "EVP_PKEY_derive : Error:" << ERR_get_error() << std::endl;
        return false;
    }

    /* dealloc peer pubkey data and context */
    EVP_PKEY_free(externalPeerPubKey);
    EVP_PKEY_CTX_free(KeyExchangeCtx);

    return true;
}

bool
OpenSSLEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
