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

/* C/C++ Headers */
#ifdef WIN32
#include <openssl/applink.c>
#endif

/* ALCP Headers */
#include "cipher/openssl_cipher.hh"

namespace alcp::testing {
using alcp::utils::CopyBytes;
void
OpenSSLCipherBase::handleErrors()
{
    ERR_print_errors_fp(stderr);
}
const EVP_CIPHER*
OpenSSLCipherBase::alcpModeKeyLenToCipher(alc_cipher_mode_t mode, size_t keylen)
{
    const EVP_CIPHER* p_mode = nullptr;
    switch (mode) {
        case ALC_AES_MODE_CBC:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_cbc();
                    break;
                case 192:
                    p_mode = EVP_aes_192_cbc();
                    break;
                case 256:
                    p_mode = EVP_aes_256_cbc();
                    break;
            }
            break;
        case ALC_AES_MODE_CTR:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_ctr();
                    break;
                case 192:
                    p_mode = EVP_aes_192_ctr();
                    break;
                case 256:
                    p_mode = EVP_aes_256_ctr();
                    break;
            }
            break;
        case ALC_AES_MODE_CFB:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_cfb();
                    break;
                case 192:
                    p_mode = EVP_aes_192_cfb();
                    break;
                case 256:
                    p_mode = EVP_aes_256_cfb();
                    break;
            }
            break;
        case ALC_AES_MODE_OFB:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_ofb();
                    break;
                case 192:
                    p_mode = EVP_aes_192_ofb();
                    break;
                case 256:
                    p_mode = EVP_aes_256_ofb();
                    break;
            }
            break;
        case ALC_AES_MODE_XTS:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_xts();
                    break;
                case 256:
                    p_mode = EVP_aes_256_xts();
                    break;
            }
            break;
        default:
            break;
    }
    return p_mode;
}
OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t cMode,
                                     const Uint8*            iv)
    : m_mode{ cMode }
    , m_iv{ iv }
{
}

OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t cMode,
                                     const Uint8*            iv,
                                     const Uint32            cIvLen,
                                     const Uint8*            key,
                                     const Uint32            cKeyLen,
                                     const Uint8*            tkey,
                                     const Uint64            cBlockSize)
    : m_mode{ cMode }
    , m_iv{ iv }
    , m_iv_len{ cIvLen }
    , m_key{ key }
    , m_key_len{ cKeyLen }
    , m_tkey{ tkey }
{
    init(iv, cIvLen, key, cKeyLen, tkey, cBlockSize);
}

OpenSSLCipherBase::~OpenSSLCipherBase()
{
    // Destroy call contexts
    EVP_CIPHER_CTX_free(m_ctx_enc);
    EVP_CIPHER_CTX_free(m_ctx_dec);
    EVP_CIPHER_free(m_cipher);
#ifdef USE_PROVIDER
    if (m_alcp_provider != nullptr) {
        OSSL_PROVIDER_unload(m_alcp_provider);
        m_alcp_provider = nullptr;
    }
#endif
}

bool
OpenSSLCipherBase::init(const Uint8* iv,
                        const Uint32 cIvLen,
                        const Uint8* key,
                        const Uint32 cKeyLen,
                        const Uint8* tkey,
                        const Uint64 cBlockSize)
{
    m_tkey   = tkey;
    m_iv     = iv;
    m_iv_len = cIvLen;
    return init(key, cKeyLen);
}

bool
OpenSSLCipherBase::init(const Uint8* key, const Uint32 cKeyLen)
{
    m_key     = key;
    m_key_len = cKeyLen;

#ifdef USE_PROVIDER
    if (m_alcp_provider == nullptr) {
        std::cout << "Using ALCP-OpenSSL-Compat Provider" << std::endl;
        OSSL_PROVIDER_set_default_search_path(NULL, OPENSSL_PROVIDER_PATH);
        m_alcp_provider = OSSL_PROVIDER_load(NULL, OPENSSL_PROVIDER_NAME);
    }
    if (NULL == m_alcp_provider) {
        printErrors("Failed to load ALCP provider");
        return false;
    }
#endif

    // FOR XTS OpenSSL needs the tweak key combined with the encryption key
    // Key
    if (m_mode == ALC_AES_MODE_XTS) {
        CopyBytes(m_key_final, m_key, cKeyLen / 8);
        CopyBytes(m_key_final + cKeyLen / 8, m_tkey, cKeyLen / 8);
        m_key = m_key_final;
    }

    // Create context for encryption and initialize
    EVP_CIPHER_CTX_free(m_ctx_enc);
    m_ctx_enc = EVP_CIPHER_CTX_new();
    if (m_ctx_enc == NULL) {
        m_ctx_enc = nullptr;
        handleErrors();
        return false;
    }

    /* for non AES types */
    if (isNonAESCipherType(m_mode)) {
        EVP_CIPHER_free(m_cipher);
        m_cipher = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
        if (1 != EVP_CipherInit_ex(m_ctx_enc, m_cipher, NULL, m_key, m_iv, 1)) {
            handleErrors();
            return false;
        }
    } else {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv)) {
            handleErrors();
            return false;
        }
    }
    // Create context for decryption and initalize
    EVP_CIPHER_CTX_free(m_ctx_dec);
    m_ctx_dec = EVP_CIPHER_CTX_new();
    if (m_ctx_dec == NULL) {
        m_ctx_dec = nullptr;
        handleErrors();
        return false;
    }

    /* for non AES types */
    if (isNonAESCipherType(m_mode)) {
        if (1 != EVP_CipherInit_ex(m_ctx_dec, m_cipher, NULL, m_key, m_iv, 1)) {
            handleErrors();
            return false;
        }
    } else {
        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv)) {
            handleErrors();
            return false;
        }
        if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_dec, 0)) {
            handleErrors();
            return false;
        }
    }
    return true;
}
bool
OpenSSLCipherBase::encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt)
{
    int len_ct;
    if (1 != EVP_EncryptUpdate(m_ctx_enc, ciphertxt, &len_ct, plaintxt, len)) {
        handleErrors();
        return false;
    }
    return true;
}
bool
OpenSSLCipherBase::encrypt(alcp_dc_ex_t& data)
{
    int len_ct = 0;
    /* for non aes*/
    if (isNonAESCipherType(m_mode)) {
        if (1
            != EVP_CipherUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: EVP_CipherUpdate" << std::endl;
            handleErrors();
            return false;
        }
        if (1 != EVP_CipherFinal_ex(m_ctx_enc, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: EVP_CipherFinal_ex" << std::endl;
            handleErrors();
            return false;
        }
    } else {
        if (1
            != EVP_EncryptUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Encrypt update" << std::endl;
            handleErrors();
            return false;
        }
    }
    return true;
}
bool
OpenSSLCipherBase::decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt)
{
    int len_pt;
    if (1 != EVP_DecryptUpdate(m_ctx_dec, plaintxt, &len_pt, ciphertxt, len)) {
        std::cout << "Error: Openssl Decrypt update" << std::endl;
        handleErrors();
        return false;
    }
    return true;
}
bool
OpenSSLCipherBase::decrypt(alcp_dc_ex_t& data)
{
    int len_pt = 0;
    /* for non aes*/
    if (isNonAESCipherType(m_mode)) {
        if (1
            != EVP_CipherUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            std::cout << "Error: EVP_CipherUpdate" << std::endl;
            handleErrors();
            return false;
        }
        if (1 != EVP_CipherFinal_ex(m_ctx_dec, data.m_out + len_pt, &len_pt)) {
            std::cout << "Error: EVP_CipherFinal_ex" << std::endl;
            handleErrors();
            return false;
        }
    } else {
        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            std::cout << "Error: Openssl Decrypt update" << std::endl;
            handleErrors();
            return false;
        }
    }
    return true;
}

bool
OpenSSLCipherBase::reset()
{
    return true;
}

} // namespace alcp::testing