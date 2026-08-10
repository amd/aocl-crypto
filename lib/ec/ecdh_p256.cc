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

#include <iostream>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include "alcp/ec/ecdh.hh"
#include "alcp/utils/copy.hh"

using alcp::utils::CopyBytes;
static constexpr Uint32 KeySize = 32;
// PublicKeySize: uncompressed SEC1 point (X||Y); caller buffer has no 0x04 prefix.
static constexpr Uint32 PublicKeySize = KeySize * 2;
namespace alcp::ec {
Status
P256::setPrivateKey(const Uint8* pPrivKey, Uint64 privKeyLen)
{
    if (privKeyLen != sizeof(m_PrivKey)) {
        return status::InvalidArgument(
            "Private key length does not match the curve key size");
    }

    Status          s                = StatusOk();
    OSSL_PARAM_BLD* p_param_bld_priv = {};
    OSSL_PARAM*     p_params         = {};
    EVP_PKEY_CTX*   p_ctx_priv       = {};

    CopyBytes(m_PrivKey, pPrivKey, sizeof(m_PrivKey));

    BIGNUM* p_priv = BN_bin2bn(m_PrivKey, sizeof(m_PrivKey), NULL);

    p_param_bld_priv = OSSL_PARAM_BLD_new();
    if (p_priv != NULL && p_param_bld_priv != NULL
        && OSSL_PARAM_BLD_push_utf8_string(
            p_param_bld_priv, "group", "prime256v1", 0)
        && OSSL_PARAM_BLD_push_BN(p_param_bld_priv, "priv", p_priv))
        p_params = OSSL_PARAM_BLD_to_param(p_param_bld_priv);

    p_ctx_priv = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (p_ctx_priv == NULL || p_params == NULL
        || EVP_PKEY_fromdata_init(p_ctx_priv) <= 0
        || EVP_PKEY_fromdata(
               p_ctx_priv, &m_pSelfKey, EVP_PKEY_KEYPAIR, p_params)
               <= 0) {
        ERR_print_errors_fp(stderr);
        s.update(status::InternalError("PKEY Error!"));
    }

    OSSL_PARAM_free(p_params);
    BN_free(p_priv);
    OSSL_PARAM_BLD_free(p_param_bld_priv);
    EVP_PKEY_CTX_free(p_ctx_priv);
    return s;
}

Status
P256::generatePublicKey(Uint8*       pPublicKey,
                        Uint64       pubKeyLen,
                        const Uint8* pPrivKey,
                        Uint64       privKeyLen)
{
    // To be implemented
    Status s = StatusOk();
    s.update(
        status::NotImplemented("This functionality is yet to be implemented!"));
    return s;
}

Status
P256::computeSecretKey(Uint8*       pSecretKey,
                       Uint64       secretKeyLen,
                       const Uint8* pPublicKey,
                       Uint64       pubKeyLen,
                       Uint64*      pKeyLength)
{
    if (secretKeyLen < KeySize) {
        return status::InvalidArgument(
            "Secret key buffer is smaller than the shared secret size");
    }

    Status s = validatePublicKey(pPublicKey, pubKeyLen);
    if (!s.ok()) {
        return s;
    }

    OSSL_PARAM_BLD*    p_param_bld_pub = {};
    OSSL_PARAM*        p_params        = {};
    EVP_PKEY_CTX*      p_ctx_pub       = {};
    std::vector<Uint8> pub_key(1 + PublicKeySize);
    EVP_PKEY_CTX*      p_key_derivation_ctx = {};

    pub_key.at(0) = 0x04; // 0x04 is UNCOMPRESSED_POINT format
    CopyBytes(&pub_key.at(1), pPublicKey, PublicKeySize);

    p_param_bld_pub = OSSL_PARAM_BLD_new();
    if (p_param_bld_pub != NULL
        && OSSL_PARAM_BLD_push_utf8_string(
            p_param_bld_pub, "group", "prime256v1", 0)
        && OSSL_PARAM_BLD_push_octet_string(
            p_param_bld_pub, "pub", &pub_key.at(0), pub_key.size()))
        p_params = OSSL_PARAM_BLD_to_param(p_param_bld_pub);
    // From the built "prarms" derive the PKEY Public Key.
    p_ctx_pub = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (p_ctx_pub == NULL || p_params == NULL
        || EVP_PKEY_fromdata_init(p_ctx_pub) <= 0
        || EVP_PKEY_fromdata(
               p_ctx_pub, &m_pPeerKey, EVP_PKEY_PUBLIC_KEY, p_params)
               <= 0) {
        ERR_print_errors_fp(stderr);
        s.update(status::InternalError("PKEY Error!"));
    }
    OSSL_PARAM_free(p_params);
    OSSL_PARAM_BLD_free(p_param_bld_pub);
    EVP_PKEY_CTX_free(p_ctx_pub);

    p_key_derivation_ctx = EVP_PKEY_CTX_new(m_pSelfKey, NULL);

    if (p_key_derivation_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        s.update(status::InternalError("Key Derivation CTX creation failed!"));
    }

    // Initialize Key Derivation
    if (EVP_PKEY_derive_init(p_key_derivation_ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        s.update(
            status::InternalError("Initializing Key Derivation CTX failed!"));
    }

    // Setup the second peer (fist peer is alice) as bob with his public key
    if (EVP_PKEY_derive_set_peer(p_key_derivation_ctx, m_pPeerKey) <= 0) {
        ERR_print_errors_fp(stderr);
        s.update(status::InternalError("Key Derivation Set Peer failed!"));
    }

    // Skip derive if setup failed — m_pPeerKey may be stale from a prior call.
    if (s.ok()) {
        // Query size into a local; caller's pKeyLength is written only on success.
        Uint64 derive_len = 0;
        if (EVP_PKEY_derive(p_key_derivation_ctx, NULL, &derive_len) <= 0) {
            ERR_print_errors_fp(stderr);
            s.update(status::InternalError(
                "Key Derivation Secret Key Size Query failed!"));
        } else if (derive_len > secretKeyLen) {
            s.update(status::InvalidArgument(
                "Secret key buffer is smaller than the derived secret"));
        } else if (EVP_PKEY_derive(
                       p_key_derivation_ctx, pSecretKey, &derive_len)
                   <= 0) {
            // OpenSSL rejects derive when len exceeds the output it will produce.
            ERR_print_errors_fp(stderr);
            s.update(status::InternalError("Key Derivation Failed!"));
        } else {
            *pKeyLength = derive_len;
        }
    }

    EVP_PKEY_CTX_free(p_key_derivation_ctx);
    return s;
}

Status
P256::validatePublicKey(const Uint8* pPublicKey, Uint64 pKeyLength)
{
    // Length only. The point itself is validated by OpenSSL when the peer key
    // is built from it; this curve has no independent on-curve test.
    if (pKeyLength != PublicKeySize) {
        return status::InvalidArgument(
            "Public key length does not match the curve public key size");
    }

    return StatusOk();
}

Uint64
P256::getKeySize()
{
    return KeySize;
}

Uint64
P256::getPublicKeySize()
{
    return PublicKeySize;
}

void
P256::reset()
{
}

P256::~P256()
{
    if (m_pSelfKey != nullptr) {
        EVP_PKEY_free(m_pSelfKey);
    }
    if (m_pPeerKey != nullptr) {
        EVP_PKEY_free(m_pPeerKey);
    }
}

} // namespace alcp::ec