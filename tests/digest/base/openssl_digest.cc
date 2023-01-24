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

    if (m_info.dt_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_info.dt_len) {
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
                /* for truncated variants of sha512 */
                if (m_info.dt_len == ALC_DIGEST_LEN_224) {
                    EVP_DigestInit(m_handle, EVP_sha512_224());
                } else if (m_info.dt_len == ALC_DIGEST_LEN_256) {
                    EVP_DigestInit(m_handle, EVP_sha512_256());
                } else {
                    /* default, when len is 512 */
                    EVP_DigestInit(m_handle, EVP_sha512());
                }
                break;
            default:
                return false;
        }
    } else if (m_info.dt_type == ALC_DIGEST_TYPE_SHA3) {
        switch (m_info.dt_len) {
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
            /*SHAKE*/
            case ALC_DIGEST_LEN_CUSTOM:
                if (m_info.dt_mode.dm_sha3 == ALC_SHAKE_128) {
                    EVP_DigestInit(m_handle, EVP_shake128());
                }
                if (m_info.dt_mode.dm_sha3 == ALC_SHAKE_256) {
                    EVP_DigestInit(m_handle, EVP_shake256());
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

alc_error_t
OpenSSLDigestBase::digest_function(const alcp_digest_data_t& data)
{
    unsigned int outsize = 0;
    int          retval  = 0;

    retval = EVP_DigestUpdate(m_handle, data.m_msg, data.m_msg_len);

    /* for extendable output functions */
    if (m_info.dt_len == ALC_DIGEST_LEN_CUSTOM)
        retval = EVP_DigestFinalXOF(m_handle, data.m_digest, data.m_digest_len);
    else
        retval = EVP_DigestFinal_ex(m_handle, data.m_digest, &outsize);
    outsize = outsize;

    return ALC_ERROR_NONE;
}

void
OpenSSLDigestBase::reset()
{
    EVP_MD_CTX_reset(m_handle);
    if (m_info.dt_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_info.dt_mode.dm_sha2) {
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
                /* for truncated variants of sha512 */
                if (m_info.dt_len == ALC_DIGEST_LEN_224) {
                    EVP_DigestInit(m_handle, EVP_sha512_224());
                } else if (m_info.dt_len == ALC_DIGEST_LEN_256) {
                    EVP_DigestInit(m_handle, EVP_sha512_256());
                } else {
                    /* default, when len is 512 */
                    EVP_DigestInit(m_handle, EVP_sha512());
                }
                break;
            default:
                std::cout << "Error: " << __FILE__ << ":" << __LINE__
                          << std::endl;
                break;
        }
    } else if (m_info.dt_type == ALC_DIGEST_TYPE_SHA3) {
        switch (m_info.dt_len) {
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
            case ALC_DIGEST_LEN_CUSTOM:
                if (m_info.dt_mode.dm_sha3 == ALC_SHAKE_128) {
                    EVP_DigestInit(m_handle, EVP_shake128());
                } else if (m_info.dt_mode.dm_sha3 == ALC_SHAKE_256) {
                    EVP_DigestInit(m_handle, EVP_shake256());
                }
                break;
            default:
                std::cout << "Error: " << __FILE__ << ":" << __LINE__
                          << std::endl;
                break;
        }
    }
}

} // namespace alcp::testing
