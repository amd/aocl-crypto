/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "cipher/openssl_cipher_base.hh"
#ifdef WIN32
EXTERN_C_BEGIN
#include <openssl/applink.c>
EXTERN_C_END
#endif

namespace alcp::testing {
void
OpenSSLCipherBase::handleErrors()
{
    ERR_print_errors_fp(stderr);
}
const EVP_CIPHER*
OpenSSLCipherBase::alcpModeKeyLenToCipher(alc_cipher_mode_t mode, size_t keylen)
{
    switch (mode) {
        case ALC_AES_MODE_CBC:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_cbc();
                case 192:
                    return EVP_aes_192_cbc();
                case 256:
                    return EVP_aes_256_cbc();
            }
        case ALC_AES_MODE_CTR:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_ctr();
                case 192:
                    return EVP_aes_192_ctr();
                case 256:
                    return EVP_aes_256_ctr();
            }
        case ALC_AES_MODE_CFB:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_cfb();
                case 192:
                    return EVP_aes_192_cfb();
                case 256:
                    return EVP_aes_256_cfb();
            }
        case ALC_AES_MODE_OFB:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_ofb();
                case 192:
                    return EVP_aes_192_ofb();
                case 256:
                    return EVP_aes_256_ofb();
            }
        case ALC_AES_MODE_GCM:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_gcm();
                case 192:
                    return EVP_aes_192_gcm();
                case 256:
                    return EVP_aes_256_gcm();
            }
        case ALC_AES_MODE_CCM:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_ccm();
                case 192:
                    return EVP_aes_192_ccm();
                case 256:
                    return EVP_aes_256_ccm();
            }
        case ALC_AES_MODE_XTS:
            switch (keylen) {
                case 128:
                    return EVP_aes_128_xts();
                case 256:
                    return EVP_aes_256_xts();
            }
        default:
            return nullptr;
    }
}
OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t mode,
                                     const Uint8*            iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}
OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t mode,
                                     const Uint8*            iv,
                                     const Uint32            iv_len,
                                     const Uint8*            key,
                                     const Uint32            key_len,
                                     const Uint8*            tkey,
                                     const Uint64            block_size)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_iv_len{ iv_len }
    , m_key{ key }
    , m_key_len{ key_len }
    , m_tkey{ tkey }
{
    init(iv, iv_len, key, key_len, tkey, block_size);
}

OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t mode,
                                     const Uint8*            iv,
                                     const Uint8*            key,
                                     const Uint32            key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_key{ key }
    , m_key_len{ key_len }
{
    init(key, key_len);
}

OpenSSLCipherBase::OpenSSLCipherBase(const alc_cipher_mode_t mode,
                                     const Uint8*            iv,
                                     const Uint32            iv_len,
                                     const Uint8*            key,
                                     const Uint32            key_len)
    : m_mode{ mode }
    , m_iv{ iv }
    , m_iv_len{ iv_len }
    , m_key{ key }
    , m_key_len{ key_len }
{
    init(key, key_len);
}
OpenSSLCipherBase::~OpenSSLCipherBase()
{
    // Destroy call contexts
    if (m_ctx_enc != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx_enc);
    }
    if (m_ctx_dec != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx_dec);
    }
#ifdef USE_PROVIDER
    if (m_alcp_provider != nullptr) {
        OSSL_PROVIDER_unload(m_alcp_provider);
        m_alcp_provider = nullptr;
    }
#endif
}

bool
OpenSSLCipherBase::init(const Uint8* iv,
                        const Uint32 iv_len,
                        const Uint8* key,
                        const Uint32 key_len,
                        const Uint8* tkey,
                        const Uint64 block_size)
{
    m_tkey   = tkey;
    m_iv     = iv;
    m_iv_len = iv_len;
    return init(key, key_len);
}

bool
OpenSSLCipherBase::init(const Uint8* iv,
                        const Uint32 iv_len,
                        const Uint8* key,
                        const Uint32 key_len)
{
    m_iv_len = iv_len;
    return init(iv, key, key_len);
}
bool
OpenSSLCipherBase::init(const Uint8* iv, const Uint8* key, const Uint32 key_len)
{
    m_iv = iv;
    return init(key, key_len);
}
bool
OpenSSLCipherBase::init(const Uint8* key, const Uint32 key_len)
{
    m_key     = key;
    m_key_len = key_len;

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

    /* xts */
    if (m_mode == ALC_AES_MODE_XTS) {
        /* add key with tkey for xts */
        utils::CopyBytes(m_key_final, m_key, key_len / 8);
        utils::CopyBytes(m_key_final + key_len / 8, m_tkey, key_len / 8);
        m_key = m_key_final;
    }

    // Create context for encryption and initialize
    if (m_ctx_enc != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx_enc);
    }
    m_ctx_enc = EVP_CIPHER_CTX_new();
    if (m_ctx_enc == NULL) {
        m_ctx_enc = nullptr;
        handleErrors();
        return false;
    }

    if (m_mode == ALC_AES_MODE_GCM) {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_enc, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL))
            handleErrors();

        if (1 != EVP_EncryptInit_ex(m_ctx_enc, NULL, NULL, m_key, m_iv))
            handleErrors();
    }

    /* ccm */
    else if (m_mode == ALC_AES_MODE_CCM) {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_enc, EVP_CTRL_CCM_SET_IVLEN, m_iv_len, NULL))
            handleErrors();
    }

    /* for cases other than gcm/ccm/xts */
    else {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv))
            handleErrors();

        if (m_ctx_dec != nullptr) {
            EVP_CIPHER_CTX_free(m_ctx_dec);
        }
    }

    // Create context for decryption and initalize
    m_ctx_dec = EVP_CIPHER_CTX_new();
    if (m_ctx_dec == NULL) {
        m_ctx_dec = nullptr;
        handleErrors();
        return false;
    }
    if (m_mode == ALC_AES_MODE_GCM) {
        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();
        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_dec, EVP_CTRL_GCM_SET_IVLEN, m_iv_len, NULL))
            handleErrors();

        /* Initialise key and IV */
        if (1 != EVP_DecryptInit_ex(m_ctx_dec, NULL, NULL, m_key, m_iv))
            handleErrors();
    }
    /* ccm */
    else if (m_mode == ALC_AES_MODE_CCM) {
        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();
        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if (1
            != EVP_CIPHER_CTX_ctrl(
                m_ctx_dec, EVP_CTRL_CCM_SET_IVLEN, m_iv_len, NULL))
            handleErrors();
    }

    /* for non gcm/ccm/xts */
    else {
        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv))
            handleErrors();

        if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_dec, 0))
            handleErrors();
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
OpenSSLCipherBase::encrypt(alcp_data_ex_t data)
{
    int          len_ct = 0;
    static Uint8 Temp;
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
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_enc, EVP_CTRL_GCM_GET_TAG, data.m_tagl, data.m_tag)) {
                std::cout << "Error: Tag Creation Failed" << std::endl;
                std::cout << "TAG_LEN: " << data.m_tagl << std::endl;
                handleErrors();
                return false;
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
        }

        if (1
            != EVP_EncryptUpdate(m_ctx_enc, NULL, &len_ct, NULL, data.m_inl)) {
            handleErrors();
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
            data.m_out = &Temp;
            data.m_in  = &Temp;
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
        }
    }

    else {
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
    }
    return true;
}
bool
OpenSSLCipherBase::decrypt(alcp_data_ex_t data)
{
    int          len_pt = 0;
    static Uint8 Temp;
    if (m_mode == ALC_AES_MODE_GCM) {

        if (data.m_adl > 0)
            if (1
                != EVP_DecryptUpdate(
                    m_ctx_dec, NULL, &len_pt, data.m_ad, data.m_adl)) {
                handleErrors();
                return false;
            }

        if (1
            != EVP_DecryptUpdate(
                m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl)) {
            handleErrors();
            return false;
        }

        if (data.m_tagl > 0)
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_dec, EVP_CTRL_GCM_SET_TAG, data.m_tagl, data.m_tag)) {
                std::cout << "Error: Tag Setting Failed" << std::endl;
                handleErrors();
                return false;
            }

        int ret = EVP_DecryptFinal_ex(m_ctx_dec, data.m_out + len_pt, &len_pt);
        if (ret > 0) {
            return true;
        } else {
            return false;
        }
    }

    /* ccm */
    else if (m_mode == ALC_AES_MODE_CCM) {
        /* set the tagl */
        if (data.m_tagl != 0) {
            if (1
                != EVP_CIPHER_CTX_ctrl(
                    m_ctx_dec, EVP_CTRL_CCM_SET_TAG, data.m_tagl, data.m_tag)) {
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
            data.m_out = &Temp;
            data.m_in  = &Temp;
        }

        int ret = EVP_DecryptUpdate(
            m_ctx_dec, data.m_out, &len_pt, data.m_in, data.m_inl);
        if (ret == 0) {
            return false;
        } else {
            return true;
        }
    }

    /* non gcm/ccm/xts*/
    else {
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

void
OpenSSLCipherBase::reset()
{
    EVP_CIPHER_CTX_reset(m_ctx_enc);
    EVP_CIPHER_CTX_reset(m_ctx_dec);
    if ((m_mode == ALC_AES_MODE_GCM) || (m_mode == ALC_AES_MODE_CCM)) {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();

        if (1 != EVP_EncryptInit_ex(m_ctx_enc, NULL, NULL, m_key, m_iv))
            handleErrors();

        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  NULL,
                                  NULL))
            handleErrors();

        if (1 != EVP_DecryptInit_ex(m_ctx_dec, NULL, NULL, m_key, m_iv))
            handleErrors();

    } else {
        if (1
            != EVP_EncryptInit_ex(m_ctx_enc,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv))
            handleErrors();
        if (1
            != EVP_DecryptInit_ex(m_ctx_dec,
                                  alcpModeKeyLenToCipher(m_mode, m_key_len),
                                  NULL,
                                  m_key,
                                  m_iv))
            handleErrors();
    }
    if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_enc, 0))
        handleErrors();
    if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_dec, 0))
        handleErrors();
}
} // namespace alcp::testing