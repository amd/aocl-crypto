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

#include <cstring>

#include "ecdh/ecdh.hh"
#include "ecdh/openssl_ecdh.hh"

namespace alcp::testing {

using namespace std;

alc_error_t
OpenSSLEcdh::init_private_key(const Uint8* pPrivKey_input_data)
{
    if (m_peerId >= ALC_PEER_MAX) {
        m_handle = nullptr;
        return ALC_ERROR_NOT_SUPPORTED;
    }
    static const char* pPropq = NULL;

    /*
     *   Initialize handle, generate or load KAT private key
     */
    if (pPrivKey_input_data != NULL) {
        m_pPrivateKeyData = EVP_PKEY_new_raw_private_key_ex(
            m_handle, m_pkeytype, pPropq, pPrivKey_input_data, 32);

    } else {
        m_pPrivateKeyData = EVP_PKEY_Q_keygen(m_handle, pPropq, m_pkeytype);
    }

    if (m_pPrivateKeyData == NULL) {
        EVP_PKEY_free(m_pPrivateKeyData);
        m_pPrivateKeyData = NULL;
        OSSL_LIB_CTX_free(m_handle);
        m_handle = NULL;
        return ALC_ERROR_INVALID_DATA;
    }

    // if (m_handle == nullptr) {
    //    return ALC_ERROR_GENERIC; // FIXME: add proper error name in the
    //    table.
    //}
    return ALC_ERROR_NONE;
}

OpenSSLEcdh::OpenSSLEcdh(const char* pKeytype, alc_peer_id_t peerId)
{
    if (m_handle != nullptr) {
        OSSL_LIB_CTX_free(m_handle);
        m_handle = nullptr;
    }
    string st  = "peer" + to_string((int)peerId);
    m_name     = st.c_str();
    m_pkeytype = pKeytype;
    m_peerId   = peerId;
}

OpenSSLEcdh::~OpenSSLEcdh()
{
    if (m_handle != nullptr) {
        OSSL_LIB_CTX_free(m_handle);
    }
}

// temp hack to be removed.
#define OSSL_PKEY_PARAM_PUB_KEY "pub"

alc_error_t
OpenSSLEcdh::generate_public_key(Uint8*       pPublicKeyData,
                                 const Uint8* pPrivKey_input_data)
{

#if 0
    //alternative method:

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);

#else
    if (init_private_key(pPrivKey_input_data) != ALC_ERROR_NONE) {
        fprintf(stderr, "privatekey is not set \n");
        return ALC_ERROR_INVALID_DATA;
    }

    /* Get public key corresponding to the private key */
    if (EVP_PKEY_get_octet_string_param(m_pPrivateKeyData,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        pPublicKeyData,
                                        32, // sizeof(m_publicKeyData),
                                        &m_publicKey_len)
        == 0) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() failed\n");

        // free
        EVP_PKEY_free(m_pPrivateKeyData);
        m_pPrivateKeyData = NULL;
        return ALC_ERROR_GENERIC;
    }

    /* X25519 public keys are always 32 bytes */
    if (m_publicKey_len != 32) {
        fprintf(stderr,
                "EVP_PKEY_get_octet_string_param() "
                "yielded wrong length\n");

        // free
        EVP_PKEY_free(m_pPrivateKeyData);
        m_pPrivateKeyData = NULL;
        return ALC_ERROR_INVALID_SIZE;
    }
#endif
    return ALC_ERROR_NONE;
}

alc_error_t
OpenSSLEcdh::compute_secret_key(Uint8*       pSecret_key,
                                const Uint8* pPublicKeyDataRemote,
                                Uint64*      pKeyLength)
{
    int           rv               = 0;
    EVP_PKEY*     remote_peer_pubk = NULL;
    EVP_PKEY_CTX* ctx              = NULL;

    m_pSecret = NULL;

    static const char* pPropq = NULL;

    /* Load public key for remote peer. */
    remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(
        m_handle, m_pkeytype, pPropq, pPublicKeyDataRemote, 32);
    if (remote_peer_pubk == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_public_key_ex() failed\n");
        goto end;
    }

    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(m_handle, m_pPrivateKeyData, pPropq);

    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto end;
    }

    /* Initialize derivation process. */
    if (EVP_PKEY_derive_init(ctx) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_init() failed\n");
        goto end;
    }

    /* Configure each peer with the other peer's public key. */
    if (EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer() failed\n");
        goto end;
    }

    /* Determine the secret length. */
    if (EVP_PKEY_derive(ctx, NULL, &m_secretLength) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    /*
     * We are using X25519, so the secret generated will always be 32 bytes.
     * However for exposition, the code below demonstrates a generic
     * implementation for arbitrary lengths.
     */
    if (m_secretLength != 32) { /* unreachable */
        fprintf(stderr, "Secret is always 32 bytes for X25519\n");
        goto end;
    }

    /* Allocate memory for shared secrets. */
    m_pSecret = (Uint8*)OPENSSL_malloc(m_secretLength);
    if (m_pSecret == NULL) {
        fprintf(stderr, "Could not allocate memory for secret\n");
        goto end;
    }

    /* Derive the shared secret. */
    if (EVP_PKEY_derive(ctx, m_pSecret, &m_secretLength) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    // cout << "\n Shared secret of peer id: " << m_peerId << endl;
    // BIO_dump_indent_fp(stdout, m_pSecret, m_secretLength, 2);
    // putchar('\n');

    // set key length and copy secret key.
    *pKeyLength = m_secretLength;
    memcpy(pSecret_key, m_pSecret, m_secretLength);

    rv = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(remote_peer_pubk);
    if (rv == 0) {
        OPENSSL_clear_free(m_pSecret, m_secretLength);
        m_pSecret = NULL;
    }
    if (rv == 1) {
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_GENERIC; // FIXME: replace with correct error code
    }

    return ALC_ERROR_NONE;
}

void
OpenSSLEcdh::reset()
{
    OSSL_LIB_CTX_free(m_handle);
    //
    // reinit
}

} // namespace alcp::testing
