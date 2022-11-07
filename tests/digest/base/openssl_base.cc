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

#include "digest/openssl_base.hh"

namespace alcp::testing {

OpenSSLDigestBase::OpenSSLDigestBase(_alc_digest_type type,
                                     _alc_digest_len  sha_len)
    : m_type{ type }
    , m_sha_len{ sha_len }
{
    init();
}


OpenSSLDigestBase::~OpenSSLDigestBase()
{
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
    }
}


bool
OpenSSLDigestBase::init()
{
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
        m_handle = nullptr;
    }

    m_handle = EVP_MD_CTX_new();

    if (m_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_sha_len) {
            case ALC_DIGEST_LEN_224:
                EVP_DigestInit(m_handle, EVP_sha224());
                break;
            case ALC_DIGEST_LEN_256:
                EVP_DigestInit(m_handle, EVP_sha256());
                break;
            case ALC_DIGEST_LEN_384:
                EVP_DigestInit(m_handle, EVP_sha384());
                break;
            case ALC_DIGEST_LEN_512:
                EVP_DigestInit(m_handle, EVP_sha512());
                break;
            default:
                return false;
        }
    } else if (m_type == ALC_DIGEST_TYPE_SHA3) {
        switch (m_sha_len) {
            case ALC_DIGEST_LEN_224:
                EVP_DigestInit(m_handle, EVP_sha3_224());
                break;
            case ALC_DIGEST_LEN_256:
                EVP_DigestInit(m_handle, EVP_sha3_256());
                break;
            case ALC_DIGEST_LEN_384:
                EVP_DigestInit(m_handle, EVP_sha3_384());
                break;
            case ALC_DIGEST_LEN_512:
                EVP_DigestInit(m_handle, EVP_sha3_512());
                break;
            default:
                return false;
        }
    }
    return true;
}

bool
OpenSSLDigestBase::init(_alc_digest_type type,
                        _alc_digest_len  sha_len)
{
    this->m_type    = type;
    this->m_sha_len = sha_len;
    return init();
}


alc_error_t
OpenSSLDigestBase::digest_function(const Uint8* in,
                                   Uint64       in_size,
                                   Uint8*       out,
                                   Uint64       out_size)
{
    unsigned int outsize = 0;
    EVP_DigestUpdate(m_handle, in, in_size);
    EVP_DigestFinal_ex(m_handle, out, &outsize);
    out_size = outsize;

    return ALC_ERROR_NONE;
}


void
OpenSSLDigestBase::reset()
{
    EVP_MD_CTX_reset(m_handle);
    if (m_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_mode) {
            case ALC_SHA2_224:
                EVP_DigestInit(m_handle, EVP_sha224());
                break;
            case ALC_SHA2_256:
                EVP_DigestInit(m_handle, EVP_sha256());
                break;
            case ALC_SHA2_384:
                EVP_DigestInit(m_handle, EVP_sha384());
                break;
            case ALC_SHA2_512:
                EVP_DigestInit(m_handle, EVP_sha512());
                break;
        }
    } else if (m_type == ALC_DIGEST_TYPE_SHA3) {
        switch (m_mode) {
            case ALC_SHA3_224:
                EVP_DigestInit(m_handle, EVP_sha3_224());
                break;
            case ALC_SHA3_256:
                EVP_DigestInit(m_handle, EVP_sha3_256());
                break;
            case ALC_SHA3_384:
                EVP_DigestInit(m_handle, EVP_sha3_384());
                break;
            case ALC_SHA3_512:
                EVP_DigestInit(m_handle, EVP_sha3_512());
                break;
        }
    }
}

} // namespace alcp::testing
