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

#include "cipher/alc_cipher_aead.hh"

namespace alcp::testing {

// AlcpCipherAeadBase class functions
AlcpCipherAeadBase::AlcpCipherAeadBase(const _alc_cipher_type  cipher_type,
                                       const alc_cipher_mode_t mode,
                                       const Uint8*            iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

AlcpCipherAeadBase::AlcpCipherAeadBase(const _alc_cipher_type  cipher_type,
                                       const alc_cipher_mode_t mode,
                                       const Uint8*            iv,
                                       const Uint8*            key,
                                       const Uint32            key_len)
    : m_mode{ mode }
    , m_iv{ iv }
{
    init(iv, key, key_len);
}

/* xts */
AlcpCipherAeadBase::AlcpCipherAeadBase(const _alc_cipher_type  cipher_type,
                                       const alc_cipher_mode_t mode,
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

AlcpCipherAeadBase::~AlcpCipherAeadBase()
{
    if (m_handle != nullptr) {
        alcp_cipher_aead_finish(m_handle);
        if (m_handle->ch_context != NULL) {
            free(m_handle->ch_context);
        }
        delete m_handle;
    }
}

bool
AlcpCipherAeadBase::init(const Uint8* iv,
                         const Uint32 iv_len,
                         const Uint8* key,
                         const Uint32 key_len)
{
    this->m_iv = iv;
    return init(key, key_len);
}

/* for XTS */
bool
AlcpCipherAeadBase::init(const Uint8* iv,
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
AlcpCipherAeadBase::init(const Uint8* iv,
                         const Uint8* key,
                         const Uint32 key_len)
{
    this->m_iv = iv;
    return init(key, key_len);
}

bool
AlcpCipherAeadBase::init(const Uint8* key, const Uint32 key_len)
{
    alc_error_t    err;
    const int      err_size = 256;
    Uint8          err_buf[err_size];
    alc_key_info_t p_kinfo{};

    if (m_handle != nullptr) {
        alcp_cipher_aead_finish(m_handle);
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
    m_handle->ch_context = malloc(alcp_cipher_aead_context_size(&m_cinfo));
    if (m_handle->ch_context == NULL) {
        std::cout << "alcp_base.c: Memory allocation for context failure!"
                  << std::endl;
        goto out;
    }

    /* Initialize keyinfo */

    m_keyinfo.algo = ALC_KEY_ALG_SYMMETRIC;
    m_keyinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    m_keyinfo.fmt  = ALC_KEY_FMT_RAW;
    m_keyinfo.len  = key_len;
    m_keyinfo.key  = key;

    /* Initialize cinfo */
    m_cinfo.ci_algo_info.ai_mode = m_mode;
    m_cinfo.ci_algo_info.ai_iv   = m_iv;

    m_cinfo.ci_type = ALC_CIPHER_TYPE_AES;

#if 1
    if (m_mode == ALC_AES_MODE_SIV) {
        p_kinfo.key  = m_tkey; // Using tkey as CTR key for SIV
        p_kinfo.len  = key_len;
        p_kinfo.algo = ALC_KEY_ALG_SYMMETRIC;
        p_kinfo.fmt  = ALC_KEY_FMT_RAW;
        m_cinfo.ci_algo_info.ai_siv.xi_ctr_key = &p_kinfo;
    }
#endif
    m_cinfo.ci_key_info = m_keyinfo;

    /* Check support */
    err = alcp_cipher_aead_supported(&m_cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }

    /* Request Handle */
    err = alcp_cipher_aead_request(&m_cinfo, m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }
    return true;
out:
    if (m_handle != nullptr) {
        if (m_handle->ch_context != NULL) {
            free(m_handle->ch_context);
        }
        delete m_handle; // Free old handle
        m_handle = nullptr;
    }
    return false;
}

bool
AlcpCipherAeadBase::encrypt(alcp_dc_ex_t& data)
{
    alcp_dca_ex_t  aead_data = *reinterpret_cast<alcp_dca_ex_t*>(&data);
    constexpr bool enc       = true;

    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            return alcpGCMModeToFuncCall<enc>(aead_data);
        case ALC_AES_MODE_CCM:
            return alcpCCMModeToFuncCall<enc>(aead_data);
        case ALC_AES_MODE_SIV:
            return alcpSIVModeToFuncCall<enc>(aead_data);
        default:
            return false; // Should not come here
    }
}

bool
AlcpCipherAeadBase::decrypt(alcp_dc_ex_t& data)
{
    alcp_dca_ex_t  aead_data = *reinterpret_cast<alcp_dca_ex_t*>(&data);
    constexpr bool enc       = false;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            return alcpGCMModeToFuncCall<enc>(aead_data);
        case ALC_AES_MODE_CCM:
            return alcpCCMModeToFuncCall<enc>(aead_data);
        case ALC_AES_MODE_SIV:
            return alcpSIVModeToFuncCall<enc>(aead_data);
        default:
            return false; // Should not come here
    }
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpGCMModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buff[err_size];

    err = alcp_cipher_aead_set_iv(m_handle, aead_data.m_ivl, m_iv);
    if (alcp_is_error(err)) {
        printf("Err:Setting iv\n");
        alcp_error_str(err, err_buff, err_size);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    if (aead_data.m_adl > 0) {
        err =
            alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);
        if (alcp_is_error(err)) {
            printf("Err:Setadl\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }

    if constexpr (enc) {
        err = alcp_cipher_aead_encrypt_update(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tag, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            printf("TAG Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    } else {
        err = alcp_cipher_aead_decrypt_update(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tagBuff, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            printf("TAG Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        // Tag verification
        if (std::memcmp(aead_data.m_tag, aead_data.m_tagBuff, aead_data.m_tagl)
            != 0) {
            std::cout << "Error: Tag Verification Failed!" << std::endl;
            return false;
        }
    }
    return true;
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpCCMModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buff[err_size];
    err = alcp_cipher_aead_set_tag_length(m_handle, aead_data.m_tagl);
    if (alcp_is_error(err)) {
        printf("Err:setting tagl\n");
        alcp_error_str(err, err_buff, err_size);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    err = alcp_cipher_aead_set_iv(m_handle, aead_data.m_ivl, m_iv);
    if (alcp_is_error(err)) {
        printf("Err:Setting iv\n");
        alcp_error_str(err, err_buff, err_size);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }
    if (aead_data.m_adl > 0) {
        err =
            alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);
        if (alcp_is_error(err)) {
            printf("Err:Setadl\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }

    if constexpr (enc) {
        if (aead_data.m_inl) {
            err = alcp_cipher_aead_encrypt_update(m_handle,
                                                  aead_data.m_in,
                                                  aead_data.m_out,
                                                  aead_data.m_inl,
                                                  m_iv);
        } else {
            Uint8 a;
            err = alcp_cipher_aead_encrypt_update(m_handle, &a, &a, 0, m_iv);
        }
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        // Get Tag
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, err_size);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
        }
    } else {
        if (aead_data.m_inl) {
            err = alcp_cipher_aead_decrypt_update(m_handle,
                                                  aead_data.m_in,
                                                  aead_data.m_out,
                                                  aead_data.m_inl,
                                                  m_iv);
        } else {
            Uint8 a;
            err = alcp_cipher_aead_decrypt_update(m_handle, &a, &a, 0, m_iv);
        }
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tagBuff, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            printf("TAG Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        // Tag verification
        if (std::memcmp(aead_data.m_tagBuff, aead_data.m_tag, aead_data.m_tagl)
            != 0) {
            std::cout << "Error: Tag Verification Failed!" << std::endl;
            return false;
        }
    }
    return true;
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpSIVModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buff[err_size];

    err = alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);

    if (alcp_is_error(err)) {
        printf("Err:Setadl\n");
        alcp_error_str(err, err_buff, err_size);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    if constexpr (enc) {
        err = alcp_cipher_aead_encrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, err_size);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
        }
    } else {
        err = alcp_cipher_aead_decrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl, m_iv);
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, err_size);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tagBuff, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("Tag Error\n");
                alcp_error_str(err, err_buff, err_size);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
            // Tag verification
            if (std::memcmp(
                    aead_data.m_tagBuff, aead_data.m_tag, aead_data.m_tagl)
                != 0) {
                std::cout << "Error: Tag Verification Failed!" << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool
AlcpCipherAeadBase::reset()
{
    return true;
}

} // namespace alcp::testing
