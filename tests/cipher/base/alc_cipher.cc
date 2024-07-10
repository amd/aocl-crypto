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

#include "cipher/alc_cipher.hh"

namespace alcp::testing {

AlcpCipherBase::AlcpCipherBase(const _alc_cipher_type  cIpherType,
                               const alc_cipher_mode_t cMode,
                               const Uint8*            iv)
    : m_mode{ cMode }
    , m_cipher_type{ cIpherType }
    , m_iv{ iv }
{}

/* xts */
AlcpCipherBase::AlcpCipherBase(const _alc_cipher_type  cIpherType,
                               const alc_cipher_mode_t cMode,
                               const Uint8*            iv,
                               const Uint32            cIvLen,
                               const Uint8*            key,
                               const Uint32            cKeyLen,
                               const Uint8*            tkey,
                               const Uint64            cBlockSize)
    : m_mode{ cMode }
    , m_cipher_type{ cIpherType }
    , m_iv{ iv }
    , m_tkey{ tkey }
{
    init(iv, cIvLen, key, cKeyLen, tkey, cBlockSize);
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

/* for XTS */
bool
AlcpCipherBase::init(const Uint8* iv,
                     const Uint32 cIvLen,
                     const Uint8* key,
                     const Uint32 cKeyLen,
                     const Uint8* tkey,
                     const Uint64 cBlockSize) // Usefull
{
    this->m_iv   = iv;
    this->m_tkey = tkey;
    return init(key, cKeyLen);
}

bool
AlcpCipherBase::init(const Uint8* key, const Uint32 cKeyLen)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buf[cErrSize];

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
    m_handle->ch_context = malloc(alcp_cipher_context_size());
    if (m_handle->ch_context == NULL) {
        std::cout << "alcp_base.c: Memory allocation for context failure!"
                  << std::endl;
        goto out;
    }

    m_cinfo.ci_type = m_cipher_type;
    if (m_cinfo.ci_type == ALC_CIPHER_TYPE_CHACHA20) {
        // m_cinfo.ci_mode   = ALC_AES_MODE_NONE;
        m_cinfo.ci_mode   = m_mode;
        m_cinfo.ci_keyLen = cKeyLen;

        m_cinfo.ci_key   = key;
        m_cinfo.ci_iv    = m_iv;
        m_cinfo.ci_ivLen = 16 * 8; /* FIXME is it always 16 bytes ?*/

    } else {

        // request params
        m_cinfo.ci_mode   = m_mode;
        m_cinfo.ci_keyLen = cKeyLen;

        // init params
        m_cinfo.ci_key = key;
        m_cinfo.ci_iv  = m_iv;

        /* set these only for XTS */
        if (m_mode == ALC_AES_MODE_XTS) {
            memcpy(m_key, key, cKeyLen / 8);
            memcpy(m_key + (cKeyLen / 8), m_tkey, cKeyLen / 8);
            m_cinfo.ci_key = m_key;
        }
    }
#if 0
    else if (m_mode == ALC_AES_MODE_SIV) {
        alc_key_info_t* p_kinfo =
            (alc_key_info_p)malloc(sizeof(alc_key_info_t));
        p_kinfo->key  = m_tkey; // Using tkey as CTR key for SIV
        p_kinfo->len  = key_len;
        p_kinfo->algo = ALC_KEY_ALG_SYMMETRIC;
        p_kinfo->fmt  = ALC_KEY_FMT_RAW;
        m_cinfo.ci_algo_info.ai_siv.xi_ctr_key = p_kinfo;
    }
#endif

    /* Request Handle */
    err = alcp_cipher_request(m_cinfo.ci_mode, m_cinfo.ci_keyLen, m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, cErrSize);
        goto out;
    }

    // encrypt init:
    err = alcp_cipher_init(m_handle,
                           m_cinfo.ci_key,
                           m_cinfo.ci_keyLen,
                           m_cinfo.ci_iv,
                           16); // FIXME: set iv length
    if (alcp_is_error(err)) {
        printf("Error in cipher init\n");
        return 0;
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
AlcpCipherBase::encrypt(alcp_dc_ex_t& data)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];

    err = alcp_cipher_encrypt(m_handle, data.m_in, data.m_out, data.m_inl);
    if (alcp_is_error(err)) {
        goto enc_out;
    }

    return true;
enc_out:
    alcp_error_str(err, err_buff, cErrSize);
    std::cout << "Error:" << err_buff << std::endl;
    return false;
}

bool
AlcpCipherBase::decrypt(alcp_dc_ex_t& data)
{
    alc_error_t err;
    const int   cErrSize = 256;
    Uint8       err_buff[cErrSize];

    err = alcp_cipher_decrypt(m_handle, data.m_in, data.m_out, data.m_inl);
    if (alcp_is_error(err)) {
        goto dec_out;
    }

    return true;
dec_out:
    alcp_error_str(err, err_buff, cErrSize);
    std::cout << "Error:" << err_buff << std::endl;
    return false;
}

bool
AlcpCipherBase::reset()
{
    return true;
}

} // namespace alcp::testing
