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

#include "digest/openssl_digest.hh"

namespace alcp::testing {

OpenSSLDigestBase::OpenSSLDigestBase(const alc_digest_info_t& info)
{
    init(info, m_digest_len);
}

OpenSSLDigestBase::~OpenSSLDigestBase()
{
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
    }
}

bool
OpenSSLDigestBase::init(const alc_digest_info_t& info, Int64 digest_len)
{
    m_info       = info;
    m_digest_len = digest_len;
    return init();
}

bool
OpenSSLDigestBase::init()
{
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
        m_handle = nullptr;
    }

    m_handle = EVP_MD_CTX_new();

    switch (m_info.dt_mode) {
        case ALC_SHA2_224:
            m_md_type = EVP_sha224();
            break;
        case ALC_SHA2_256:
            m_md_type = EVP_sha256();
            break;
        case ALC_SHA2_384:
            m_md_type = EVP_sha384();
            break;
        case ALC_SHA2_512:
            m_md_type = EVP_sha512();
            break;
        case ALC_SHA2_512_256:
            m_md_type = EVP_sha512_256();
            break;
        case ALC_SHA2_512_224:
            m_md_type = EVP_sha512_224();
            break;
        case ALC_SHA3_224:
            m_md_type = EVP_sha3_224();
            break;
        case ALC_SHA3_256:
            m_md_type = EVP_sha3_256();
            break;
        case ALC_SHA3_384:
            m_md_type = EVP_sha3_384();
            break;
        case ALC_SHA3_512:
            m_md_type = EVP_sha3_512();
            break;
        case ALC_SHAKE_128:
            m_md_type = EVP_shake128();
            break;
        case ALC_SHAKE_256:
            m_md_type = EVP_shake256();
            break;
        default:
            return false;
    }
    if (EVP_DigestInit(m_handle, m_md_type) != 1) {
        std::cout << "Error code in EVP_DigestInit: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLDigestBase::context_copy()
{
    /* skip ctx copy if handle is null, and there is no ctx to copy */
    if (m_handle == nullptr) {
        std::cout << "Context is null, skipping context copy" << std::endl;
        return true;
    }
    /* create dup ctx and copy context */
    m_handle_dup = EVP_MD_CTX_new();
    if (EVP_MD_CTX_copy_ex(m_handle_dup, m_handle) != 1) {
        std::cout << "Error code in EVP_MD_CTX_copy_ex: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    /* swap it so that m_handle is the one propagated in the next steps */
    std::swap(m_handle, m_handle_dup);
    /* now free the dup handle*/
    if (m_handle_dup != nullptr) {
        EVP_MD_CTX_free(m_handle_dup);
    }
    return true;
}

bool
OpenSSLDigestBase::digest_function(const alcp_digest_data_t& data)
{
    unsigned int outsize = 0;

    if (EVP_DigestUpdate(m_handle, data.m_msg, data.m_msg_len) != 1) {
        std::cout << "Error code in EVP_DigestUpdate: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    /* for extendable output functions */
    if (m_info.dt_len == ALC_DIGEST_LEN_CUSTOM_SHAKE_128
        || m_info.dt_len == ALC_DIGEST_LEN_CUSTOM_SHAKE_256) {
        if (EVP_DigestFinalXOF(m_handle, data.m_digest, data.m_digest_len)
            != 1) {
            std::cout << "Error code in EVP_DigestFinalXOF: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }

    } else {
        if (EVP_DigestFinal_ex(m_handle, data.m_digest, &outsize) != 1) {
            std::cout << "Error code in EVP_DigestFinal_ex: "
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            return false;
        }
    }
    outsize = outsize;
    return true;
}

bool
OpenSSLDigestBase::digest_squeeze(const alcp_digest_data_t& data)
{
    unsigned int outsize = 0;

    return true;
}

void
OpenSSLDigestBase::reset()
{
    if (EVP_MD_CTX_reset(m_handle) != 1) {
        std::cout << "Error code in EVP_MD_CTX_reset"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return;
    }
    if (EVP_DigestInit(m_handle, m_md_type) != 1) {
        std::cout << "Error code in EVP_DigestInit after reset: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return;
    }
}

} // namespace alcp::testing