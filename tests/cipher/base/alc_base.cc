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

#include "cipher/alc_base.hh"

namespace alcp::testing {

// AlcpCipherBase class functions
AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode, const Uint8* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode,
                               const Uint8*            iv,
                               const Uint8*            key,
                               const Uint32            key_len)
    : m_mode{ mode }
    , m_iv{ iv }
{
    init(iv, key, key_len);
}

/* xts */
AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode,
                               const Uint8*            iv,
                               const Uint32            iv_len,
                               const Uint8*            key,
                               const Uint32            key_len,
                               const Uint8*            tkey,
                               const Uint64            block_size)
    : m_mode{ mode }
    , m_iv{ iv }
{
    init(iv, iv_len, key, key_len, tkey, block_size);
}

AlcpCipherBase::~AlcpCipherBase()
{
    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        if (m_handle->ch_context != NULL) {
            if (m_cinfo.ci_algo_info.ai_xts.xi_tweak_key != nullptr)
                free(m_cinfo.ci_algo_info.ai_xts.xi_tweak_key);
            free(m_handle->ch_context);
        }
        delete m_handle;
    }
}

bool
AlcpCipherBase::init(const Uint8* iv,
                     const Uint32 iv_len,
                     const Uint8* key,
                     const Uint32 key_len)
{
    this->m_iv = iv;
    return init(key, key_len);
}

/* for XTS */
bool
AlcpCipherBase::init(const Uint8* iv,
                     const Uint32 iv_len,
                     const Uint8* key,
                     const Uint32 key_len,
                     const Uint8* tkey,
                     const Uint64 block_size)
{
    this->m_iv   = iv;
    this->m_tkey = tkey;
    return init(key, key_len);
}

bool
AlcpCipherBase::init(const Uint8* iv, const Uint8* key, const Uint32 key_len)
{
    this->m_iv = iv;
    return init(key, key_len);
}

bool
AlcpCipherBase::init(const Uint8* key, const Uint32 key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        if (m_cinfo.ci_algo_info.ai_xts.xi_tweak_key != nullptr)
            free(m_cinfo.ci_algo_info.ai_xts.xi_tweak_key);
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
    m_cinfo.ci_algo_info.ai_xts.xi_tweak_key = nullptr;

    m_keyinfo.algo = ALC_KEY_ALG_SYMMETRIC;
    m_keyinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    m_keyinfo.fmt  = ALC_KEY_FMT_RAW;
    m_keyinfo.len  = key_len;
    m_keyinfo.key  = key;

    /* Initialize cinfo */
    m_cinfo.ci_algo_info.ai_mode = m_mode;
    m_cinfo.ci_algo_info.ai_iv   = m_iv;

    m_cinfo.ci_type     = ALC_CIPHER_TYPE_AES;
    m_cinfo.ci_key_info = m_keyinfo;
    /* set these only for XTS */
    if (m_mode == ALC_AES_MODE_XTS) {
        m_cinfo.ci_algo_info.ai_xts.xi_tweak_key =
            (alc_key_info_p)malloc(sizeof(alc_key_info_t));
        // m_cinfo.ci_algo_info.ai_xts.xi_tweak_key->tweak_key = m_tkey;
        m_cinfo.ci_algo_info.ai_xts.xi_tweak_key->key  = m_tkey;
        m_cinfo.ci_algo_info.ai_xts.xi_tweak_key->len  = key_len;
        m_cinfo.ci_algo_info.ai_xts.xi_tweak_key->algo = ALC_KEY_ALG_SYMMETRIC;
        m_cinfo.ci_algo_info.ai_xts.xi_tweak_key->fmt  = ALC_KEY_FMT_RAW;
    }

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
        if (m_handle->ch_context != NULL) {
            if (m_cinfo.ci_algo_info.ai_xts.xi_tweak_key != nullptr)
                free(m_cinfo.ci_algo_info.ai_xts.xi_tweak_key);
            free(m_handle->ch_context);
        }
        delete m_handle; // Free old handle
    }
    return false;
}

bool
AlcpCipherBase::encrypt(const Uint8* plaintxt, size_t len, Uint8* ciphertxt)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

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
    Uint8       err_buff[err_size];

    if (m_mode == ALC_AES_MODE_GCM) {

        // GCM Init
        err = alcp_cipher_encrypt_update(
            m_handle, nullptr, nullptr, data.ivl, m_iv);
        if (alcp_is_error(err)) {
            goto enc_out;
        }

        if (data.adl > 0) {
            err = alcp_cipher_encrypt_update(
                m_handle, data.ad, nullptr, data.adl, m_iv);

            if (alcp_is_error(err)) {
                goto enc_out;
            }
        }

        // GCM Encrypt
        err = alcp_cipher_encrypt_update(
            m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            goto enc_out;
        }
        // Get Tag
        if (data.tagl == 0 && data.tag == nullptr) {
            // FIXME: Hack to prevent ad from being null
            Uint8 a;
            data.tag = &a; // Some random value other than NULL
        }
        err = alcp_cipher_encrypt_update(
            m_handle, nullptr, data.tag, data.tagl, m_iv);
        if (alcp_is_error(err)) {
            goto enc_out;
        }
    } else {
        // For non GCM mode
        err = alcp_cipher_encrypt(m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            goto enc_out;
        }
    }
    return true;
enc_out:
    alcp_error_str(err, err_buff, err_size);
    std::cout << "Error:" << err_buff << std::endl;
    return false;
}

bool
AlcpCipherBase::decrypt(const Uint8* ciphertxt, size_t len, Uint8* plaintxt)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

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
    Uint8       err_buff[err_size];
    Uint8*      tagbuff = new Uint8[data.tagl];
    if (tagbuff == nullptr) {
        std::cout << __FILE__ << ":" << __LINE__ - 2
                  << " Memory Allocation error" << std::endl;
        return false;
    }

    if (m_mode == ALC_AES_MODE_GCM) {
        // GCM Init
        Uint8 tagbuff[data.tagl];
        err = alcp_cipher_decrypt_update(
            m_handle, nullptr, nullptr, data.ivl, m_iv);
        if (alcp_is_error(err)) {
            goto dec_out;
        }

        if (data.adl > 0) {
            err = alcp_cipher_decrypt_update(
                m_handle, data.ad, nullptr, data.adl, m_iv);
            if (alcp_is_error(err)) {
                goto dec_out;
            }
        }
        // GCM Decrypt
        err = alcp_cipher_decrypt_update(
            m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            goto dec_out;
        }
        // Get Tag
        if (data.tagl == 0 && data.tag == nullptr) {
            // FIXME: Hack to prevent ad from being null
            Uint8 a;
            data.tag = &a; // Some random value other than NULL
        }
        err = alcp_cipher_decrypt_update(
            m_handle, nullptr, tagbuff, data.tagl, m_iv);
        if (alcp_is_error(err)) {
            goto dec_out;
        }
        // Tag verification
        if (std::memcmp(tagbuff, data.tag, data.tagl) != 0) {
            return false;
        }
    } else {
        // For non GCM mode
        err = alcp_cipher_decrypt(m_handle, data.in, data.out, data.inl, m_iv);
        if (alcp_is_error(err)) {
            goto dec_out;
        }
    }
    delete[] tagbuff;
    return true;
dec_out:
    delete[] tagbuff;
    alcp_error_str(err, err_buff, err_size);
    std::cout << "Error:" << err_buff << std::endl;
    return false;
}

void
AlcpCipherBase::reset()
{}

} // namespace alcp::testing
