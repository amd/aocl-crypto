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

#include "ecdh/openssl_ecdh_base.hh"
#include <cstddef>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <ostream>

namespace alcp::testing {

OpenSSLEcdhBase::OpenSSLEcdhBase(const alc_ec_info_t& info) {}

OpenSSLEcdhBase::~OpenSSLEcdhBase()
{
    if (m_ec_handle1 != nullptr) {
        OSSL_LIB_CTX_free(m_ec_handle1);
    }
    if (m_ec_handle2 != nullptr) {
        OSSL_LIB_CTX_free(m_ec_handle2);
    }
}

bool
OpenSSLEcdhBase::init(const alc_ec_info_t& info, const alcp_ecdh_data_t& data)
{
    m_info = info;
    /*Initialize handle, generate or load KAT private key*/
    m_pPrivateKeyData1 =
        EVP_PKEY_new_raw_private_key_ex(m_ec_handle1,
                                        m_pkeytype,
                                        NULL,
                                        data.m_Peer1_PvtKey,
                                        data.m_Peer1_PvtKeyLen);
    if (m_pPrivateKeyData1 == nullptr) {
        printf("EVP_PKEY_new_raw_private_key_ex returned null");
        return false;
    }
    m_pPrivateKeyData2 =
        EVP_PKEY_new_raw_private_key_ex(m_ec_handle2,
                                        m_pkeytype,
                                        NULL,
                                        data.m_Peer2_PvtKey,
                                        data.m_Peer2_PvtKeyLen);
    if (m_pPrivateKeyData1 == nullptr) {
        printf("EVP_PKEY_new_raw_private_key_ex returned null");
        return false;
    }
    return true;
}

bool
OpenSSLEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    Uint64 keyLength1, keyLength2;

    /* Get public key corresponding to the private key */
    if (1
        != EVP_PKEY_get_octet_string_param(
            m_pPrivateKeyData1,
            "pub",
            data.m_Peer1_PubKey,
            data.m_Peer1_PubKeyLen, // sizeof(m_publicKeyData),
            &keyLength1)) {
        printf("EVP_PKEY_get_octet_string_param() failed\n");
        return false;
    }
    if (1
        != EVP_PKEY_get_octet_string_param(
            m_pPrivateKeyData2,
            "pub",
            data.m_Peer2_PubKey,
            data.m_Peer2_PubKeyLen, // sizeof(m_publicKeyData),
            &keyLength2)) {
        printf("EVP_PKEY_get_octet_string_param() failed\n");
        return false;
    }
    return true;
}

bool
OpenSSLEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data)
{
    EVP_PKEY_CTX *ctx1 = NULL, *ctx2 = NULL;
    Uint64        SecretkeyLength1, SecretkeyLength2;

    /* Load public key for remote peer. */
    m_pPublicKeyData1 = EVP_PKEY_new_raw_public_key_ex(m_ec_handle1,
                                                       m_pkeytype,
                                                       NULL,
                                                       data.m_Peer1_PubKey,
                                                       data.m_Peer1_PubKeyLen);
    if (m_pPublicKeyData1 == nullptr) {
        printf("EVP_PKEY_new_raw_private_key_ex returned null");
        return false;
    }
    m_pPublicKeyData2 = EVP_PKEY_new_raw_public_key_ex(m_ec_handle2,
                                                       m_pkeytype,
                                                       NULL,
                                                       data.m_Peer2_PubKey,
                                                       data.m_Peer2_PubKeyLen);
    if (m_pPublicKeyData2 == nullptr) {
        printf("EVP_PKEY_new_raw_public_key_ex returned null");
        return false;
    }

    /* Create key exchange context. */
    ctx1 = EVP_PKEY_CTX_new_from_pkey(m_ec_handle1, m_pPrivateKeyData1, NULL);
    if (ctx1 == NULL) {
        printf("Ctx creation for key exchange failed\n");
        return false;
    }
    ctx2 = EVP_PKEY_CTX_new_from_pkey(m_ec_handle2, m_pPrivateKeyData2, NULL);
    if (ctx2 == NULL) {
        printf("Ctx creation for key exchange failed\n");
        return false;
    }

    /* Initialize derivation process. */
    if (EVP_PKEY_derive_init(ctx1) == 0) {
        printf("EVP_PKEY_derive_init() failed\n");
        return false;
    }
    if (EVP_PKEY_derive_init(ctx2) == 0) {
        printf("EVP_PKEY_derive_init() failed\n");
        return false;
    }

    /* Configure each peer with the other peer's public key. */
    if (1 != EVP_PKEY_derive_set_peer(ctx1, m_pPublicKeyData1)) {
        printf("EVP_PKEY_derive_set_peer() failed\n");
        return false;
    }
    if (1 != EVP_PKEY_derive_set_peer(ctx2, m_pPublicKeyData2)) {
        printf("EVP_PKEY_derive_set_peer() failed\n");
        return false;
    }

    /* Determine the secret length. */
    if (1 != EVP_PKEY_derive(ctx1, NULL, &SecretkeyLength1)) {
        printf("EVP_PKEY_derive() len failed\n");
        return false;
    }
    if (1 != EVP_PKEY_derive(ctx2, NULL, &SecretkeyLength2)) {
        printf("EVP_PKEY_derive() len failed\n");
        return false;
    }

    /* derive the shared secret key */
    if (1 != EVP_PKEY_derive(ctx1, data.m_Peer1_SecretKey, &SecretkeyLength1)) {
        printf("EVP_PKEY_derive() failed\n");
        return false;
    }
    if (1 != EVP_PKEY_derive(ctx2, data.m_Peer2_SecretKey, &SecretkeyLength2)) {
        printf("EVP_PKEY_derive() failed\n");
        return false;
    }
    return true;
}

bool
OpenSSLEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
