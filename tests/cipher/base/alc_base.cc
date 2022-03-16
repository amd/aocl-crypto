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

#include "alc_base.hh"
#include "base.hh"

namespace alcp::testing {

// AlcpCipherBase class functions
AlcpCipherBase::AlcpCipherBase(const alc_aes_mode_t mode, const uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

AlcpCipherBase::AlcpCipherBase(const alc_aes_mode_t mode,
                               const uint8_t*       iv,
                               const uint8_t*       key,
                               const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
{
    init(iv, key, key_len);
}

AlcpCipherBase::~AlcpCipherBase()
{
    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        if (m_handle->ch_context != NULL) {
            free(m_handle->ch_context);
        }
        delete m_handle;
    }
}

bool
AlcpCipherBase::init(const uint8_t* iv,
                     const uint8_t* key,
                     const uint32_t key_len)
{
    this->m_iv = reinterpret_cast<const uint8_t*>(iv);
    return init(key, key_len);
}

bool
AlcpCipherBase::init(const uint8_t* key, const uint32_t key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        free(m_handle->ch_context);
        delete m_handle; // Free old handle
    }
    m_handle = new alc_cipher_handle_t;
    if (m_handle == nullptr) {
        std::cout << "alcp_base.c: Memory allocation for handle failure!"
                  << std::endl;
        goto out;
    }
    m_handle->ch_context = malloc(alcp_cipher_context_size(&m_cinfo));
    if (m_handle->ch_context == NULL) {
        std::cout << "alcp_base.c: Memory allocation for context failure!"
                  << std::endl;
        goto out;
    }

    /* Initialize keyinfo */
    m_keyinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    m_keyinfo.fmt  = ALC_KEY_FMT_RAW;
    m_keyinfo.len  = key_len;
    m_keyinfo.key  = key;
    /* Initialize cinfo */
    m_cinfo.ci_mode_data.cm_aes.ai_mode = m_mode;
    m_cinfo.ci_mode_data.cm_aes.ai_iv   = m_iv;
    m_cinfo.ci_type                     = ALC_CIPHER_TYPE_AES;
    m_cinfo.ci_key_info                 = m_keyinfo;

    /* Check support */
    err = alcp_cipher_supported(&m_cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }

    /* Request Handle */
    err = alcp_cipher_request(&m_cinfo, m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }
    return true;
out:
    if (m_handle != nullptr) {
        if (m_handle->ch_context != NULL)
            free(m_handle->ch_context);
        delete m_handle; // Free old handle
    }
    return false;
}

bool
AlcpCipherBase::encrypt(const uint8_t* plaintxt,
                        const int      len,
                        uint8_t*       ciphertxt)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* Encrypt Data */
    err = alcp_cipher_encrypt(m_handle, plaintxt, ciphertxt, len, m_iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    return true;
}

bool
AlcpCipherBase::decrypt(const uint8_t* ciphertxt,
                        const int      len,
                        uint8_t*       plaintxt)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* Decrypt Data */
    err = alcp_cipher_decrypt(m_handle, ciphertxt, plaintxt, len, m_iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    return true;
}

// AlcpCipherTesting class functions
AlcpCipherTesting::AlcpCipherTesting(const alc_aes_mode_t       mode,
                                     const std::vector<uint8_t> iv)
    : AlcpCipherBase(mode, &iv[0])
{}

std::vector<uint8_t>
AlcpCipherTesting::testingEncrypt(const std::vector<uint8_t> plaintext,
                                  const std::vector<uint8_t> key,
                                  const std::vector<uint8_t> iv)
{
    if (init(&iv[0], &key[0], key.size() * 8)) {
        uint8_t* ciphertext = new uint8_t[plaintext.size()];
        encrypt(&plaintext[0], plaintext.size(), ciphertext);
        return std::vector<uint8_t>(ciphertext, ciphertext + plaintext.size());
    }
    return {};
}
std::vector<uint8_t>
AlcpCipherTesting::testingDecrypt(const std::vector<uint8_t> ciphertext,
                                  const std::vector<uint8_t> key,
                                  const std::vector<uint8_t> iv)
{
    if (init(&iv[0], &key[0], key.size() * 8)) {
        uint8_t* plaintext = new uint8_t[ciphertext.size()];
        decrypt(&ciphertext[0], ciphertext.size(), plaintext);
        return std::vector<uint8_t>(plaintext, plaintext + ciphertext.size());
    }
    return {};
}

} // namespace alcp::testing