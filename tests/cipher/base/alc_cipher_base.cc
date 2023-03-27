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

#include "cipher/alc_cipher_base.hh"

namespace alcp::testing {

// AlcpCipherBase class functions
AlcpCipherBase::AlcpCipherBase(const alc_cipher_mode_t mode, const Uint8* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{
}

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
    } else if (m_mode == ALC_AES_MODE_SIV) {
        alc_key_info_t* p_kinfo =
            (alc_key_info_p)malloc(sizeof(alc_key_info_t));
        p_kinfo->key  = m_tkey; // Using tkey as CTR key for SIV
        p_kinfo->len  = key_len;
        p_kinfo->algo = ALC_KEY_ALG_SYMMETRIC;
        p_kinfo->fmt  = ALC_KEY_FMT_RAW;
        m_cinfo.ci_algo_info.ai_siv.xi_ctr_key = p_kinfo;
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
        m_handle = nullptr;
    }
    return false;
}

bool
AlcpCipherBase::encrypt(alcp_data_ex_t data)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buff[err_size];

    /* for gcm / ccm */
    if ((m_mode == ALC_AES_MODE_GCM) || (m_mode == ALC_AES_MODE_CCM)
        || (m_mode == ALC_AES_MODE_SIV)) {

        // GCM/CCM init
        if (m_mode == ALC_AES_MODE_CCM) {
            err = alcp_cipher_set_tag_length(m_handle, data.m_tagl);

            if (alcp_is_error(err)) {
                printf("Err:setting tagl\n");
                goto enc_out;
            }
        }

        // SIV generates IV synthetically.
        if (m_mode != ALC_AES_MODE_SIV) {
            err = alcp_cipher_set_iv(m_handle, data.m_ivl, m_iv);
            if (alcp_is_error(err)) {
                printf("Err:Setting iv\n");
                goto enc_out;
            }
        }

        if (data.m_adl > 0) {
            err = alcp_cipher_set_aad(m_handle, data.m_ad, data.m_adl);

            if (alcp_is_error(err)) {
                printf("Err:Setadl\n");
                goto enc_out;
            }
        }

        // GCM/CCM Encrypt
        if (data.m_inl) {
            if (m_mode == ALC_AES_MODE_SIV) {
                err = alcp_cipher_encrypt(
                    m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
            } else {
                err = alcp_cipher_encrypt_update(
                    m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
            }
        } else {
            // Call encrypt update with a valid memory if no plaintext
            Uint8 a;
            err = alcp_cipher_encrypt_update(m_handle, &a, &a, 0, m_iv);
        }
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            goto enc_out;
        }

        // Get Tag
        if (data.m_tagl > 0) {
            err = alcp_cipher_get_tag(m_handle, data.m_tag, data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                goto enc_out;
            }
        }

    } else {
        // For non GCM/CCM mode
        err = alcp_cipher_encrypt(
            m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
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
AlcpCipherBase::decrypt(alcp_data_ex_t data)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buff[err_size];

    if ((m_mode == ALC_AES_MODE_GCM) || (m_mode == ALC_AES_MODE_CCM)
        || (m_mode == ALC_AES_MODE_SIV)) {
        /* only for ccm */
        if (m_mode == ALC_AES_MODE_CCM) {
            err = alcp_cipher_set_tag_length(m_handle, data.m_tagl);
            if (alcp_is_error(err)) {
                goto dec_out;
            }
        }

        if (m_mode != ALC_AES_MODE_SIV) {
            err = alcp_cipher_set_iv(m_handle, data.m_ivl, m_iv);
            if (alcp_is_error(err)) {
                goto dec_out;
            }
        }

        if (data.m_adl > 0) {
            err = alcp_cipher_set_aad(m_handle, data.m_ad, data.m_adl);
            if (alcp_is_error(err)) {
                goto dec_out;
            }
        }

        // GCM/CCM Decrypt
        if (data.m_inl) {
            if (m_mode == ALC_AES_MODE_SIV) {
                err = alcp_cipher_decrypt(
                    m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
            } else {
                err = alcp_cipher_decrypt_update(
                    m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
            }
        } else {
            Uint8 a;
            if (m_mode == ALC_AES_MODE_SIV) {
                err = alcp_cipher_decrypt(
                    m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
            } else {
                err = alcp_cipher_decrypt_update(m_handle, &a, &a, 0, m_iv);
            }
        }
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            goto dec_out;
        }

        if (data.m_tagl > 0) {
            err = alcp_cipher_get_tag(m_handle, data.m_tagBuff, data.m_tagl);
            if (alcp_is_error(err)) {
                printf("Tag Error\n");
                goto dec_out;
            }
            // Tag verification
            if (std::memcmp(data.m_tagBuff, data.m_tag, data.m_tagl) != 0) {
                std::cout << "Error: Tag Verification Failed!" << std::endl;
                return false;
            }
        }

    } else {
        // For non GCM/CCM mode
        err = alcp_cipher_decrypt(
            m_handle, data.m_in, data.m_out, data.m_inl, m_iv);
        if (alcp_is_error(err)) {
            goto dec_out;
        }
    }
    return true;
dec_out:
    alcp_error_str(err, err_buff, err_size);
    std::cout << "Error:" << err_buff << std::endl;
    return false;
}

bool
AlcpCipherBase::reset()
{
    return true;
}

} // namespace alcp::testing
