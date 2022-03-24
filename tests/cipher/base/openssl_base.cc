/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
#include "openssl_base.hh"

namespace alcp::testing {
void
OpenSSLCipherBase::handleErrors()
{
    ERR_print_errors_fp(stderr);
}
const EVP_CIPHER*
OpenSSLCipherBase::alcpModeKeyLenToCipher(alc_aes_mode_t mode, size_t keylen)
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
        default:
            return nullptr;
    }
}
OpenSSLCipherBase::OpenSSLCipherBase(const alc_aes_mode_t mode,
                                     const uint8_t*       iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}
OpenSSLCipherBase::OpenSSLCipherBase(const alc_aes_mode_t mode,
                                     const uint8_t*       iv,
                                     const uint8_t*       key,
                                     const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
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
}
bool
OpenSSLCipherBase::init(const uint8_t* iv,
                        const uint8_t* key,
                        const uint32_t key_len)
{
    m_iv = iv;
    return init(key, key_len);
}
bool
OpenSSLCipherBase::init(const uint8_t* key, const uint32_t key_len)
{
    ;
    m_key     = key;
    m_key_len = key_len;

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
    EVP_EncryptInit_ex(m_ctx_enc,
                       alcpModeKeyLenToCipher(m_mode, m_key_len),
                       NULL,
                       m_key,
                       m_iv);
    if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_enc, 0))
        handleErrors();

    // Create context for decryption and initalized
    if (m_ctx_dec != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx_dec);
    }
    m_ctx_dec = EVP_CIPHER_CTX_new();
    if (m_ctx_dec == NULL) {
        m_ctx_dec = nullptr;
        handleErrors();
        return false;
    }
    EVP_DecryptInit_ex(m_ctx_dec,
                       alcpModeKeyLenToCipher(m_mode, m_key_len),
                       NULL,
                       m_key,
                       m_iv);
    if (1 != EVP_CIPHER_CTX_set_padding(m_ctx_dec, 0))
        handleErrors();
    return true;
}
bool
OpenSSLCipherBase::encrypt(const uint8_t* plaintxt,
                           size_t         len,
                           uint8_t*       ciphertxt)
{
    int len_ct;
    if (1 != EVP_EncryptUpdate(m_ctx_enc, ciphertxt, &len_ct, plaintxt, len))
        handleErrors();
    return true;
}
bool
OpenSSLCipherBase::decrypt(const uint8_t* ciphertxt,
                           size_t         len,
                           uint8_t*       plaintxt)
{
    int len_pt;
    if (1 != EVP_DecryptUpdate(m_ctx_dec, plaintxt, &len_pt, ciphertxt, len))
        handleErrors();
    return true;
}

} // namespace alcp::testing