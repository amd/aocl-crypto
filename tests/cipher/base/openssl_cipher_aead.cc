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

/* ALCP Headers */
#include "cipher/openssl_cipher_aead.hh"

namespace alcp::testing {
using alcp::utils::CopyBytes;
void
OpenSSLCipherAeadBase::handleErrors()
{
    ERR_print_errors_fp(stderr);
}
const EVP_CIPHER*
OpenSSLCipherAeadBase::alcpModeKeyLenToCipher(_alc_cipher_type  cipher_type,
                                              alc_cipher_mode_t mode,
                                              size_t            keylen)
{
    const EVP_CIPHER* p_mode = nullptr;
    switch (mode) {
        case ALC_AES_MODE_GCM:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_gcm();
                    break;
                case 192:
                    p_mode = EVP_aes_192_gcm();
                    break;
                case 256:
                    p_mode = EVP_aes_256_gcm();
                    break;
            }
            break;
        case ALC_AES_MODE_CCM:
            switch (keylen) {
                case 128:
                    p_mode = EVP_aes_128_ccm();
                    break;
                case 192:
                    p_mode = EVP_aes_192_ccm();
                    break;
                case 256:
                    p_mode = EVP_aes_256_ccm();
                    break;
            }
            break;
        case ALC_AES_MODE_SIV:
            // Using EVP_CIPHER_fetch here since no such API like
            // EVP_aes_128_siv();
            switch (keylen) {
                case 128:
                    p_mode = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
                    break;
                case 192:
                    p_mode = EVP_CIPHER_fetch(NULL, "AES-192-SIV", NULL);
                    break;
                case 256:
                    p_mode = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
                    break;
            }
            break;
        case ALC_CHACHA20_POLY1305:
            p_mode = EVP_chacha20_poly1305();
            break;
        default:
            break;
    }
    return p_mode;
}
OpenSSLCipherAeadBase::OpenSSLCipherAeadBase(const _alc_cipher_type  cIpherType,
                                             const alc_cipher_mode_t cMode,
                                             const Uint8*            iv)
    : m_mode{ cMode }
    , m_iv{ iv }
{
}
OpenSSLCipherAeadBase::OpenSSLCipherAeadBase(const _alc_cipher_type  cIpherType,
                                             const alc_cipher_mode_t cMode,
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

OpenSSLCipherAeadBase::OpenSSLCipherAeadBase(const _alc_cipher_type  cIpherType,
                                             const alc_cipher_mode_t cMode,
                                             const Uint8*            iv,
                                             const Uint8*            key,
                                             const Uint32            cKeyLen)
    : m_mode{ cMode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ cKeyLen }
{
    init(key, cKeyLen);
}

OpenSSLCipherAeadBase::OpenSSLCipherAeadBase(const _alc_cipher_type  cIpherType,
                                             const alc_cipher_mode_t cMode,
                                             const Uint8*            iv,
                                             const Uint32            cIvLen,
                                             const Uint8*            key,
                                             const Uint32            cKeyLen)
    : m_mode{ cMode }
    , m_iv{ iv }
    , m_iv_len{ cIvLen }
    , m_key{ key }
    , m_key_len{ cKeyLen }
{
    init(key, cKeyLen);
}
OpenSSLCipherAeadBase::~OpenSSLCipherAeadBase()
{
    // Destroy call contexts
    EVP_CIPHER_CTX_free(m_ctx_enc);
    EVP_CIPHER_CTX_free(m_ctx_dec);
    EVP_CIPHER_free((EVP_CIPHER*)m_cipher_siv);
#ifdef USE_PROVIDER
    if (m_alcp_provider != nullptr) {
        OSSL_PROVIDER_unload(m_alcp_provider);
        m_alcp_provider = nullptr;
    }
#endif
}

bool
OpenSSLCipherAeadBase::init(const Uint8* iv,
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
OpenSSLCipherAeadBase::init(const Uint8* iv,
                            const Uint32 cIvLen,
                            const Uint8* key,
                            const Uint32 cKeyLen)
{
    m_iv_len = cIvLen;
    return init(iv, key, cKeyLen);
}
bool
OpenSSLCipherAeadBase::init(const Uint8* iv,
                            const Uint8* key,
                            const Uint32 cKeyLen)
{
    m_iv = iv;
    return init(key, cKeyLen);
}
bool
OpenSSLCipherAeadBase::init(const Uint8* key, const Uint32 cKeyLen)
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

    // FOR SIV OpenSSL needs the Authentication key combined with  Encryption
    // Key
    if (m_mode == ALC_AES_MODE_SIV) {
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

    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            if (1
                != EVP_EncryptInit_ex(
                    m_ctx_enc,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_enc, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }

            if (1 != EVP_EncryptInit_ex(m_ctx_enc, NULL, NULL, m_key, m_iv)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_AES_MODE_CCM:
            if (1
                != EVP_EncryptInit_ex(
                    m_ctx_enc,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_enc, EVP_CTRL_CCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_AES_MODE_SIV:
            // For SIV (Synthetic Initialization Vector), there is no IV
            // passed from Application side.
            EVP_CIPHER_free((EVP_CIPHER*)m_cipher_siv);
            m_cipher_siv =
                alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len);
            if (1
                != EVP_EncryptInit_ex(
                    m_ctx_enc, m_cipher_siv, NULL, m_key, NULL)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_CHACHA20_POLY1305:
            if (1
                != EVP_EncryptInit_ex(
                    m_ctx_enc,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_enc, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }
            if (1 != EVP_EncryptInit_ex(m_ctx_enc, NULL, NULL, m_key, m_iv)) {
                handleErrors();
                return false;
            }
            break;
        default: // Should not come here
            return false;
    }

    // Create context for decryption and initalize
    EVP_CIPHER_CTX_free(m_ctx_dec);
    m_ctx_dec = EVP_CIPHER_CTX_new();
    if (m_ctx_dec == NULL) {
        m_ctx_dec = nullptr;
        handleErrors();
        return false;
    }

    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            if (1
                != EVP_DecryptInit_ex(
                    m_ctx_dec,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_dec, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }

            /* Initialise key and IV */
            if (1 != EVP_DecryptInit_ex(m_ctx_dec, NULL, NULL, m_key, m_iv)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_AES_MODE_CCM:
            if (1
                != EVP_DecryptInit_ex(
                    m_ctx_dec,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_dec, EVP_CTRL_CCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_AES_MODE_SIV:
            // For SIV (Synthetic Initialization Vector), there is no IV
            // passed from Application side.
            EVP_CIPHER_free((EVP_CIPHER*)m_cipher_siv);
            m_cipher_siv =
                alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len);
            if (1
                != EVP_DecryptInit_ex(
                    m_ctx_dec, m_cipher_siv, NULL, m_key, NULL)) {
                handleErrors();
                return false;
            }
            break;
        case ALC_CHACHA20_POLY1305:
            if (1
                != EVP_DecryptInit_ex(
                    m_ctx_dec,
                    alcpModeKeyLenToCipher(m_cipher_type, m_mode, m_key_len),
                    NULL,
                    NULL,
                    NULL)) {
                handleErrors();
                return false;
            }
            /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_dec, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL)) {
                handleErrors();
                return false;
            }
            /* Initialise key and IV */
            if (1 != EVP_DecryptInit_ex(m_ctx_dec, NULL, NULL, m_key, m_iv)) {
                handleErrors();
                return false;
            }
            break;
        default: // Should not come here
            return false;
    }
    return true;
}
bool
OpenSSLCipherAeadBase::encrypt(const Uint8* plaintxt,
                               size_t       len,
                               Uint8*       ciphertxt)
{
    int len_ct;
    if (1 != EVP_EncryptUpdate(m_ctx_enc, ciphertxt, &len_ct, plaintxt, len)) {
        handleErrors();
        return false;
    }
    return true;
}
bool
OpenSSLCipherAeadBase::encrypt(alcp_dc_ex_t& data_in)
{
    int           len_ct = 0;
    static Uint8  temp;
    alcp_dca_ex_t data = *reinterpret_cast<alcp_dca_ex_t*>(&data_in);
#if 1
    if (m_mode == ALC_AES_MODE_GCM) {
        if (data.m_adl > 0)
            if (1
                != EVP_EncryptUpdate(
                    m_ctx_enc, NULL, &len_ct, data.m_ad, data.m_adl)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }

        if (1
            != EVP_EncryptUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Encrypt Data" << std::endl;
            handleErrors();
            return false;
        }

        if (1 != EVP_EncryptFinal_ex(m_ctx_enc, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }

        /* Get the tag */
        if (data.m_tagl != 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_enc,
                                       EVP_CTRL_AEAD_GET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Creation Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
            }
    } else if (m_mode == ALC_CHACHA20_POLY1305) {
        if (data.m_adl > 0)
            if (1
                != EVP_EncryptUpdate(
                    m_ctx_enc, NULL, &len_ct, data.m_ad, data.m_adl)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }
        if (1
            != EVP_EncryptUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Encrypt Data" << std::endl;
            handleErrors();
            return false;
        }
        if (1 != EVP_EncryptFinal_ex(m_ctx_enc, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }
        /* Get the tag */
        if (data.m_tagl != 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_enc,
                                       EVP_CTRL_AEAD_GET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Creation Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
            }
    } else if (m_mode == ALC_AES_MODE_SIV) {
        // For processing Additional data, with EVP_EncryptUpdate, keep
        // out=null
        if (data.m_adl > 0) {
            if (1
                != EVP_EncryptUpdate(
                    m_ctx_enc, NULL, &len_ct, data.m_ad, data.m_adl)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }
        }

        // Update the plaintext
        if (1
            != EVP_EncryptUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Encrypt Data" << std::endl;
            handleErrors();
            return false;
        }

        // Finalize, currently this wont modify the ciphertext as all
        // plaintext was processed in the last call
        if (1 != EVP_EncryptFinal_ex(m_ctx_enc, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }
        /* Get the tag */
        if (data.m_tagl != 0) {
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_enc,
                                       EVP_CTRL_AEAD_GET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Creation Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
            }
        }
    }
    /* ccm */
    else if (m_mode == ALC_AES_MODE_CCM) {
        /* set the tag */
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_enc, EVP_CTRL_CCM_SET_TAG, data.m_tagl, NULL)) {
            std::cout << "Error: Tag Creation Failed" << std::endl;
            std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
            handleErrors();
            return false;
        }

        if (1 != EVP_EncryptInit_ex(m_ctx_enc, NULL, NULL, m_key, m_iv)) {
            handleErrors();
            return false;
        }

        if (1
            != EVP_EncryptUpdate(m_ctx_enc, NULL, &len_ct, NULL, data.m_inl)) {
            handleErrors();
            return false;
        }

        if (data.m_adl > 0)
            if (1
                != EVP_EncryptUpdate(
                    m_ctx_enc, NULL, &len_ct, data.m_ad, data.m_adl)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }

        /* FIXME: Hack for test data when PT is NULL */
        if (data.m_inl == 0) {
            data.m_out = &temp;
            data.m_in  = &temp;
        }

        if (1
            != EVP_EncryptUpdate(
                m_ctx_enc, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Encrypt Data" << std::endl;
            handleErrors();
            return false;
        }

        if (1 != EVP_EncryptFinal_ex(m_ctx_enc, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }

        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_enc, EVP_CTRL_CCM_GET_TAG, data.m_tagl, data.m_tag)) {
            handleErrors();
            return false;
        }
    }
#endif
    return true;
}
bool
OpenSSLCipherAeadBase::decrypt(const Uint8* ciphertxt,
                               size_t       len,
                               Uint8*       plaintxt)
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
OpenSSLCipherAeadBase::decrypt(alcp_dc_ex_t& data_in)
{
    int           len_pt = 0;
    static Uint8  temp;
    alcp_dca_ex_t data = *reinterpret_cast<alcp_dca_ex_t*>(&data_in);
#if 1
    if (m_mode == ALC_AES_MODE_GCM) {
        if (data.m_adl > 0)
            if (1
                != EVP_DecryptUpdate(
                    m_ctx_dec, NULL, &len_pt, data.m_ad, data.m_adl)) {
                std::cout << "Error: EVP_DecryptUpdate update" << std::endl;
                handleErrors();
                return false;
            }
        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            std::cout << "Error: EVP_DecryptUpdate" << std::endl;
            handleErrors();
            return false;
        }
        if (data.m_tagl > 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_dec,
                                       EVP_CTRL_AEAD_SET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Setting Failed" << std::endl;
                handleErrors();
                return false;
            }
        if (1 != EVP_DecryptFinal_ex(m_ctx_dec, data.m_out + len_pt, &len_pt)) {
            std::cout << "Error: EVP_DecryptFinal_ex Failed" << std::endl;
            handleErrors();
            return false;
        }
        return true;
    } else if (m_mode == ALC_CHACHA20_POLY1305) {
        if (data.m_adl > 0)
            if (1
                != EVP_DecryptUpdate(
                    m_ctx_dec, NULL, &len_pt, data.m_ad, data.m_adl)) {
                std::cout << "Error: EVP_DecryptUpdate update" << std::endl;
                handleErrors();
                return false;
            }
        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            std::cout << "Error: EVP_DecryptUpdate" << std::endl;
            handleErrors();
            return false;
        }
        if (data.m_tagl > 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_dec,
                                       EVP_CTRL_AEAD_SET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Setting Failed" << std::endl;
                handleErrors();
                return false;
            }
        if (1 != EVP_DecryptFinal_ex(m_ctx_dec, data.m_out + len_pt, &len_pt)) {
            std::cout << "Error: EVP_DecryptFinal_ex Failed" << std::endl;
            handleErrors();
            return false;
        }
        return true;
    } else if (m_mode == ALC_AES_MODE_SIV) {
        int len_ct;
        // For processing Additional data, with EVP_DecryptUpdate, keep
        // out=null
        if (data.m_adl > 0) {
            if (1
                != EVP_DecryptUpdate(
                    m_ctx_dec, NULL, &len_ct, data.m_ad, data.m_adl)) {
                std::cout << "Error: Additional Data" << std::endl;
                handleErrors();
                return false;
            }
        }

        /* Set the tag. For SIV, tag needs to be set before calling
         * EVP_DecryptUpdate to process the ciphertext. EVP_DecryptUpdate
         * can be called to set the additional data before setting the tag
         * as it is done here*/
        if (data.m_tagl != 0) {

            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_dec,
                                       EVP_CTRL_AEAD_SET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Setting Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
            }
        }
        // Process the ciphertext
        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_ct, data.m_in, data.m_inl)) {
            std::cout << "Error: Decrypt Data" << std::endl;
            handleErrors();
            return false;
        }
        // Finalize, currently this wont modify the plaintext(output) as all
        // ciphertext (input) was processed in the last call
        if (1 != EVP_DecryptFinal_ex(m_ctx_dec, data.m_out + len_ct, &len_ct)) {
            std::cout << "Error: Finalize" << std::endl;
            handleErrors();
            return false;
        }

    }

    /* ccm */
    else if (m_mode == ALC_AES_MODE_CCM) {
        /* set the tagl */
        if (data.m_tagl != 0) {
            if (1
                != EVP_CIPHER_CTX_ctrl(m_ctx_dec,
                                       EVP_CTRL_AEAD_SET_TAG,
                                       data.m_tagl,
                                       data.m_tag)) {
                std::cout << "Error: Tag Creation Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
            }
        }

        if (1 != EVP_DecryptInit_ex(m_ctx_dec, NULL, NULL, m_key, m_iv)) {
            std::cout << "Error: Openssl Decrypt Init" << std::endl;
            handleErrors();
            return false;
        }

        if (1
            != EVP_DecryptUpdate(m_ctx_dec, NULL, &len_pt, NULL, data.m_inl)) {
            std::cout << "Error: Openssl Decrypt update" << std::endl;
            handleErrors();
            return false;
        }

        if (data.m_adl > 0) {
            if (1
                != EVP_DecryptUpdate(
                    m_ctx_dec, NULL, &len_pt, data.m_ad, data.m_adl)) {
                std::cout << "Error: Openssl Decrypt update ADL" << std::endl;
                handleErrors();
                return false;
            }
        }

        /* FIXME: Hack for test data when CT is NULL */
        if (data.m_inl == 0) {
            data.m_out = &temp;
            data.m_in  = &temp;
        }

        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            std::cout << "Error: EVP_DecryptUpdate" << std::endl;
            handleErrors();
            return false;
        }
        return true;
    }
#endif
    return true;
}

bool
OpenSSLCipherAeadBase::reset()
{
    return true;
}

} // namespace alcp::testing