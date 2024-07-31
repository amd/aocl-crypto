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

#include "cipher/alc_cipher_aead.hh"

namespace alcp::testing {

// AlcpCipherAeadBase class functions
AlcpCipherAeadBase::AlcpCipherAeadBase(const alc_cipher_mode_t cMode,
                                       const Uint8*            iv)
    : m_mode{ cMode }
    , m_iv{ iv }
{
}

AlcpCipherAeadBase::AlcpCipherAeadBase(const alc_cipher_mode_t cMode,
                                       const Uint8*            iv,
                                       const Uint8*            key,
                                       const Uint32            cKeyLen)
    : m_mode{ cMode }
    , m_iv{ iv }
{
    init(iv, key, cKeyLen);
}

/* xts */
AlcpCipherAeadBase::AlcpCipherAeadBase(const alc_cipher_mode_t cMode,
                                       const Uint8*            iv,
                                       const Uint32            cIvLen,
                                       const Uint8*            key,
                                       const Uint32            cKeyLen,
                                       const Uint8*            tkey,
                                       const Uint64            cBlockSize)
    : m_mode{ cMode }
    , m_iv{ iv }
{
    init(iv, cIvLen, key, cKeyLen, tkey, cBlockSize);
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
                         const Uint32 cIvLen,
                         const Uint8* key,
                         const Uint32 cKeyLen)
{
    this->m_iv  = iv;
    this->m_key = key;
    return init(key, cKeyLen);
    UNREF(cIvLen);
}

/* for XTS */
bool
AlcpCipherAeadBase::init(const Uint8* iv,
                         const Uint32 cIvLen,
                         const Uint8* key,
                         const Uint32 cKeyLen,
                         const Uint8* tkey,
                         const Uint64 cBlockSize)
{
    this->m_iv     = iv;
    this->m_tkey   = tkey;
    this->m_key    = key;
    this->m_keyLen = cKeyLen;
    return init(key, cKeyLen);
}

bool
AlcpCipherAeadBase::init(const Uint8* iv,
                         const Uint8* key,
                         const Uint32 cKeyLen)
{
    this->m_iv = iv;
    return init(key, cKeyLen);
}

bool
AlcpCipherAeadBase::init(const Uint8* key, const Uint32 cKeyLen)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];

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
    m_handle->ch_context = malloc(alcp_cipher_aead_context_size());
    if (m_handle->ch_context == NULL) {
        std::cout << "alcp_base.c: Memory allocation for context failure!"
                  << std::endl;
        goto out;
    }

#if 1
    if (m_mode == ALC_AES_MODE_SIV) {
        // m_cinfo.ci_key    = m_tkey; // Using tkey as CTR key for SIV
        // m_cinfo.ci_keyLen = cKeyLen;
        std::copy(key, key + (m_keyLen / 8), m_combined_key);
        std::copy(
            m_tkey, m_tkey + (m_keyLen / 8), m_combined_key + (m_keyLen / 8));

        // FIXME: Need to be removed from the library
        // m_cinfo.ci_key = key;
    }
#endif

    /* Request Handle */
    // FIXME:  m_cinfo.ci_mode getting corrupt
    err = alcp_cipher_aead_request(m_mode, cKeyLen, m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, cErrSize);
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
    constexpr bool cEnc      = true;

    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            return alcpGCMModeToFuncCall<cEnc>(aead_data);
        case ALC_AES_MODE_CCM:
            return alcpCCMModeToFuncCall<cEnc>(aead_data);
        case ALC_AES_MODE_SIV:
            return alcpSIVModeToFuncCall<cEnc>(aead_data);
        case ALC_CHACHA20_POLY1305:
            return alcpChachaPolyModeToFuncCall<cEnc>(aead_data);
        default:
            return false; // Should not come here
    }
}

bool
AlcpCipherAeadBase::decrypt(alcp_dc_ex_t& data)
{
    alcp_dca_ex_t  aead_data = *reinterpret_cast<alcp_dca_ex_t*>(&data);
    constexpr bool cEnc      = false;
    switch (m_mode) {
        case ALC_AES_MODE_GCM:
            return alcpGCMModeToFuncCall<cEnc>(aead_data);
        case ALC_AES_MODE_CCM:
            return alcpCCMModeToFuncCall<cEnc>(aead_data);
        case ALC_AES_MODE_SIV:
            return alcpSIVModeToFuncCall<cEnc>(aead_data);
        case ALC_CHACHA20_POLY1305:
            return alcpChachaPolyModeToFuncCall<cEnc>(aead_data);
        default:
            return false; // Should not come here
    }
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpChachaPolyModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];

    err =
        alcp_cipher_aead_init(m_handle, m_key, m_keyLen, m_iv, aead_data.m_ivl);
    if (alcp_is_error(err)) {
        std::cout << __func__ << ":Err:alcp_cipher_aead_init" << std::endl;
        alcp_error_str(err, err_buff, cErrSize);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    if (aead_data.m_adl > 0) {
        err =
            alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);
        if (alcp_is_error(err)) {
            std::cout << __func__ << ":Err:alcp_cipher_aead_set_aad"
                      << std::endl;
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }

    if constexpr (enc) {
        err = alcp_cipher_aead_encrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            std::cout << __func__ << ":Err:alcp_cipher_aead_encrypt"
                      << std::endl;
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tag, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            std::cout << __func__ << ":Err:alcp_cipher_aead_get_tag"
                      << std::endl;
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    } else {
        err = alcp_cipher_aead_decrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            std::cout << __func__ << ":Err:alcp_cipher_aead_decrypt"
                      << std::endl;
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }

        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tag, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            std::cout << __func__ << ":Err:alcp_cipher_aead_get_tag"
                      << std::endl;
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }
    return true;
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpGCMModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];

    err =
        alcp_cipher_aead_init(m_handle, m_key, m_keyLen, m_iv, aead_data.m_ivl);
    if (alcp_is_error(err)) {
        printf("Err:aead init\n");
        alcp_error_str(err, err_buff, cErrSize);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    if (aead_data.m_adl > 0) {
        err =
            alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);
        if (alcp_is_error(err)) {
            printf("Err:Setadl\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }

    if constexpr (enc) {
        err = alcp_cipher_aead_encrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tag, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            printf("TAG Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    } else {
        err = alcp_cipher_aead_decrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }

        if (m_mode == ALC_AES_MODE_GCM) {

            // Tag verification done in getTag api for gcm, other aead modes to
            // be made similar to gcm. Encrypt tag is shared has input to
            // decrypt
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, cErrSize);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }

        } else {
            // pass expected for gcm decrypt, get_tag api return error if tag is
            // not matched
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, cErrSize);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
        }
    }
    return true;
}

template<bool enc>
bool
AlcpCipherAeadBase::alcpCCMModeToFuncCall(alcp_dca_ex_t& aead_data)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];
    err = alcp_cipher_aead_set_tag_length(m_handle, aead_data.m_tagl);
    if (alcp_is_error(err)) {
        printf("Err:setting tagl\n");
        alcp_error_str(err, err_buff, cErrSize);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

#ifdef CCM_MULTI_UPDATE
    // set plaintext length
    err = alcp_cipher_aead_set_ccm_plaintext_length(m_handle, aead_data.m_inl);
    if (err != ALC_ERROR_NONE) {
        printf("Error: Setting the plaintext Length\n");
        alcp_error_str(err, err_buff, cErrSize);
        return -1;
    }
#endif

    err =
        alcp_cipher_aead_init(m_handle, m_key, m_keyLen, m_iv, aead_data.m_ivl);
    if (alcp_is_error(err)) {
        printf("Error: init failure! code\n");
        alcp_error_str(err, err_buff, cErrSize);
        return false;
    }

    if (aead_data.m_adl > 0) {
        err =
            alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);
        if (alcp_is_error(err)) {
            printf("Err:Setadl\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
    }

    if constexpr (enc) {
        if (aead_data.m_inl) {
            err = alcp_cipher_aead_encrypt(
                m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        } else {
            Uint8 a;
            err = alcp_cipher_aead_encrypt(m_handle, &a, &a, 0);
        }
        if (alcp_is_error(err)) {
            printf("Encrypt Update Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        // Get Tag
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, cErrSize);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
        }
    } else {
        if (aead_data.m_inl) {
            err = alcp_cipher_aead_decrypt(
                m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        } else {
            Uint8 a;
            err = alcp_cipher_aead_decrypt(m_handle, &a, &a, 0);
        }
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        err = alcp_cipher_aead_get_tag(
            m_handle, aead_data.m_tagBuff, aead_data.m_tagl);
        if (alcp_is_error(err)) {
            printf("TAG Error\n");
            alcp_error_str(err, err_buff, cErrSize);
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
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];

    err = alcp_cipher_aead_init(
        m_handle, m_combined_key, m_keyLen, m_iv, aead_data.m_ivl);

    err = alcp_cipher_aead_set_aad(m_handle, aead_data.m_ad, aead_data.m_adl);

    if (alcp_is_error(err)) {
        printf("Err:Setadd\n");
        alcp_error_str(err, err_buff, cErrSize);
        std::cout << "Error:" << err_buff << std::endl;
        return false;
    }

    if constexpr (enc) {
        err = alcp_cipher_aead_encrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            printf("Encrypt Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tag, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("TAG Error\n");
                alcp_error_str(err, err_buff, cErrSize);
                std::cout << "Error:" << err_buff << std::endl;
                return false;
            }
        }
    } else {
        err = alcp_cipher_aead_decrypt(
            m_handle, aead_data.m_in, aead_data.m_out, aead_data.m_inl);
        if (alcp_is_error(err)) {
            printf("Decrypt Error\n");
            alcp_error_str(err, err_buff, cErrSize);
            std::cout << "Error:" << err_buff << std::endl;
            return false;
        }
        if (aead_data.m_tagl > 0) {
            err = alcp_cipher_aead_get_tag(
                m_handle, aead_data.m_tagBuff, aead_data.m_tagl);
            if (alcp_is_error(err)) {
                printf("Tag Error\n");
                alcp_error_str(err, err_buff, cErrSize);
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
