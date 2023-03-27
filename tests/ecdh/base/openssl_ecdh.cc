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

#include "ecdh/openssl_ecdh.hh"
#include <cstddef>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <ostream>

namespace alcp::testing {

OpenSSLEcdhBase::OpenSSLEcdhBase(const alc_ec_info_t& info) {}

OpenSSLEcdhBase::~OpenSSLEcdhBase()
{
    if (m_ec_handle != nullptr) {
        OSSL_LIB_CTX_free(m_ec_handle);
    }
}

bool
OpenSSLEcdhBase::init(const alc_ec_info_t& info)
{
    m_info = info;
    return true;
}

bool
OpenSSLEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    Uint64 keyLength;
    /*Initialize handle, generate or load KAT private key*/
    m_pPrivateKeyData = EVP_PKEY_new_raw_private_key_ex(m_ec_handle,
                                                        m_pkeytype,
                                                        NULL,
                                                        data.m_Peer_PvtKey,
                                                        data.m_Peer_PvtKeyLen);
    if (m_pPrivateKeyData == nullptr) {
        std::cout << "EVP_PKEY_new_raw_private_key_ex returned null: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }
    /* Get public key corresponding to the private key */
    if (1
        != EVP_PKEY_get_octet_string_param(
            m_pPrivateKeyData,
            "pub",
            data.m_Peer_PubKey,
            data.m_Peer_PubKeyLen, // sizeof(m_publicKeyData),
            &keyLength)) {
        std::cout << "EVP_PKEY_get_octet_string_param: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data_peer1,
                                  const alcp_ecdh_data_t& data_peer2)
{
    EVP_PKEY_CTX* ctx       = NULL;
    EVP_PKEY*     peer_pubk = NULL;
    Uint64        SecretkeyLength;

    /* Load public key for other peer. */
    peer_pubk = EVP_PKEY_new_raw_public_key_ex(m_ec_handle,
                                               m_pkeytype,
                                               NULL,
                                               data_peer2.m_Peer_PubKey,
                                               data_peer1.m_Peer_PubKeyLen);
    if (peer_pubk == nullptr) {
        std::cout << "EVP_PKEY_new_raw_public_key_ex returned null: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }
    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(m_ec_handle, m_pPrivateKeyData, NULL);
    if (ctx == NULL) {
        std::cout << "EVP_PKEY_CTX_new_from_pkey returned null: Error:"
                  << ERR_get_error() << std::endl;
        return false;
    }

    /* Initialize derivation process. */
    if (1 != EVP_PKEY_derive_init(ctx)) {
        std::cout << "EVP_PKEY_derive_init : Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* Configure each peer with the other peer's public key. */
    /*FIXME, this to be done with other's peer*/
    if (1 != EVP_PKEY_derive_set_peer(ctx, peer_pubk)) {
        std::cout << "EVP_PKEY_derive_set_peer : Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* Determine the secret length. */
    if (1 != EVP_PKEY_derive(ctx, NULL, &SecretkeyLength)) {
        std::cout << "EVP_PKEY_derive secret len: Error:" << ERR_get_error()
                  << std::endl;
        return false;
    }

    /* derive the shared secret key */
    if (1
        != EVP_PKEY_derive(
            ctx, data_peer1.m_Peer_SecretKey, &SecretkeyLength)) {
        std::cout << "EVP_PKEY_derive : Error:" << ERR_get_error() << std::endl;
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
