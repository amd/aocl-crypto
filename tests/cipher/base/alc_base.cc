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

namespace alcp::testing {

// AlcpCipherBase class functions
AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode, const uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode,
                               const uint8_t*       iv,
                               const uint8_t*       key,
                               const uint32_t       key_len)
    : m_mode{ mode }
    , m_iv{ iv }
{
    init(iv, key, key_len);
}

/* xts */
AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode,
                               const uint8_t *iv,
                               const uint8_t *key,
                               const uint32_t key_len,
                               const uint8_t *tkey)
    : m_mode{mode}, m_iv{iv}
{
    init(iv, key, key_len, tkey);
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
                     const uint32_t iv_len,
                     const uint8_t* key,
                     const uint32_t key_len)
{
    this->m_iv = iv;
    return init(key, key_len);
}

/* for XTS */
bool AlcpCipherBase::init(const uint8_t *iv,
                          const uint8_t *key,
                          const uint32_t key_len,
                          const uint8_t *tkey)
{
    this->m_iv = iv;
    this->m_tkey = tkey;
    return init(key, key_len);
}

bool
AlcpCipherBase::init(const uint8_t* iv,
                     const uint8_t* key,
                     const uint32_t key_len)
{
    this->m_iv = iv;
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
    // TODO: Check support before allocating
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

    /* XTS */
    m_keyinfo.tweak_key = m_tkey;

    /* Initialize cinfo */
    m_cinfo.ci_algo_info.ai_mode = m_mode;
    m_cinfo.ci_algo_info.ai_iv   = m_iv;
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
AlcpCipherBase::encrypt(const uint8_t* plaintxt, size_t len, uint8_t* ciphertxt)
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
AlcpCipherBase::encrypt(alcp_data_ex_t data)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buff[err_size];

    if (m_mode == ALC_AES_MODE_GCM) {

        // GCM Init
        err = alcp_cipher_encrypt_update(
            m_handle, nullptr, nullptr, data.ivl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM encrypt init failure! code:11\n");
            alcp_error_str(err, err_buff, err_size);
            return false;
        }
        // Additional Data
        if (data.adl == 0 && data.ad == nullptr) {
            // FIXME: Hack to prevent ad from being null
            uint8_t a;
            data.ad = &a; // Some random value other than NULL
        }
        err = alcp_cipher_encrypt_update(
            m_handle, data.ad, nullptr, data.adl, m_iv);

        if (alcp_is_error(err)) {
            printf("Error: GCM additional data failure! code:12\n");
            alcp_error_str(err, err_buff, err_size);
            return false;
        }
        // GCM Encrypt
        err = alcp_cipher_encrypt_update(
            m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM ecnryption failure! code:13\n");
            alcp_error_str(err, err_buff, err_size);
            return false;
        }
        // Get Tag
        if (data.tagl == 0 && data.tag == nullptr) {
            // FIXME: Hack to prevent ad from being null
            uint8_t a;
            data.tag = &a; // Some random value other than NULL
        }
        err = alcp_cipher_encrypt_update(
            m_handle, nullptr, data.tag, data.tagl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM tag fetch failure! code:14\n");
            alcp_error_str(err, err_buff, err_size);
            return false;
        }
    } else {
        // For non GCM mode
        err = alcp_cipher_encrypt(m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: Encryption failure! code:10\n");
            alcp_error_str(err, err_buff, err_size);
            return false;
        }
    }
    return true;
}

bool
AlcpCipherBase::decrypt(const uint8_t* ciphertxt, size_t len, uint8_t* plaintxt)
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

bool
AlcpCipherBase::decrypt(alcp_data_ex_t data)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];
    uint8_t     tagbuff[data.tagl];

    if (m_mode == ALC_AES_MODE_GCM) {
        // GCM Init
        err = alcp_cipher_decrypt_update(
            m_handle, nullptr, nullptr, data.ivl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM decrypt init failure! code:1\n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
        // Additional Data
        if (data.adl == 0 && data.ad == nullptr) {
            // FIXME: Hack to prevent ad from being null
            uint8_t a;
            data.ad = &a; // Some random value other than NULL
        }
        err = alcp_cipher_decrypt_update(
            m_handle, data.ad, nullptr, data.adl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM additional data failure! code:2\n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
        // GCM Decrypt
        err = alcp_cipher_decrypt_update(
            m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM decryption failure! code:3\n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
        // Get Tag
        if (data.tagl == 0 && data.tag == nullptr) {
            // FIXME: Hack to prevent ad from being null
            uint8_t a;
            data.tag = &a; // Some random value other than NULL
        }
        err = alcp_cipher_decrypt_update(
            m_handle, nullptr, tagbuff, data.tagl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: GCM tag fetch failure! code:4\n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
        // Tag verification
        if (std::memcmp(tagbuff, data.tag, data.tagl) != 0) {
            return false;
        }
    } else {
        // For non GCM mode
        err = alcp_cipher_decrypt(m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Error: Decryption failure! code:0\n");
            alcp_error_str(err, err_buf, err_size);
            return false;
        }
    }
    return true;
}

void
AlcpCipherBase::reset()
{}

} // namespace alcp::testing
