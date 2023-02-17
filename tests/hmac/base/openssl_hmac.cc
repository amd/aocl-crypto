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

#include "hmac/openssl_hmac.hh"

namespace alcp::testing {

OpenSSLHmacBase::OpenSSLHmacBase(const alc_mac_info_t& info) {}

OpenSSLHmacBase::~OpenSSLHmacBase()
{
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
    }
}

bool
OpenSSLHmacBase::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();
    return init();
}

bool
OpenSSLHmacBase::init()
{
    int       ret_val = 0;
    EVP_PKEY* evp_key =
        EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, &(m_key[0]), m_key_len);
    if (m_handle != nullptr) {
        EVP_MD_CTX_free(m_handle);
        m_handle = nullptr;
    }

    m_handle = EVP_MD_CTX_new();
    if (m_handle == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
    }

    if (m_info.mi_algoinfo.hmac.hmac_digest.dt_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_info.mi_algoinfo.hmac.hmac_digest.dt_len) {
            case ALC_DIGEST_LEN_224:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha224(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_256:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha256(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_384:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha384(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_512:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha512(), NULL, evp_key);
                break;
            default:
                return false;
        }
    } else if (m_info.mi_algoinfo.hmac.hmac_digest.dt_type
               == ALC_DIGEST_TYPE_SHA3) {
        switch (m_info.mi_algoinfo.hmac.hmac_digest.dt_len) {
            case ALC_DIGEST_LEN_224:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha3_224(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_256:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha3_256(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_384:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha3_384(), NULL, evp_key);
                break;
            case ALC_DIGEST_LEN_512:
                ret_val = EVP_DigestSignInit(
                    m_handle, NULL, EVP_sha3_512(), NULL, evp_key);
                break;
            default:
                return false;
        }
    }
    if (ret_val != 1) {
        printf("EVP_DigestSignInit failed with err code: %d\n", ret_val);
        return false;
    }
    return true;
}

bool
OpenSSLHmacBase::Hmac_function(const alcp_hmac_data_t& data)
{
    size_t outsize = data.out.m_hmac_len;

    if (1 != EVP_DigestSignUpdate(m_handle, data.in.m_msg, data.in.m_msg_len)) {
        std::cout << "EVP_DigestSignUpdate failed, error 0x" << ERR_get_error()
                  << std::endl;
        return false;
    }
    if (1 != EVP_DigestSignFinal(m_handle, data.out.m_hmac, &outsize)) {
        std::cout << "EVP_DigestSignFinal failed, error 0x" << ERR_get_error()
                  << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLHmacBase::reset()
{
    return true;
}

} // namespace alcp::testing
