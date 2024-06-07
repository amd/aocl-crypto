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

#include "hmac/openssl_hmac.hh"

/* get Mac digest len from SHA type*/
std::map<alc_digest_mode_t, const char*> OpenSSLDigestStringMap = {
    { ALC_SHA2_224, "sha224" },         { ALC_SHA2_256, "sha256" },
    { ALC_SHA2_384, "sha384" },         { ALC_SHA2_512, "sha512" },
    { ALC_SHA3_224, "sha3-224" },       { ALC_SHA3_256, "sha3-256" },
    { ALC_SHA3_384, "sha3-384" },       { ALC_SHA3_512, "sha3-512" },
    { ALC_SHA2_512_224, "sha512-224" }, { ALC_SHA2_512_256, "sha512-256" }
};

namespace alcp::testing {

OpenSSLHmacBase::~OpenSSLHmacBase()
{
    EVP_MAC_CTX_free(m_handle);
    EVP_MAC_free(m_mac);
}

bool
OpenSSLHmacBase::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info               = info;
    m_key                = &Key[0];
    m_key_len            = Key.size();
    size_t      params_n = 0;
    const char* digest   = NULL;

    digest = OpenSSLDigestStringMap[m_info.hmac.digest_mode];

    if (m_mac != nullptr) {
        EVP_MAC_free(m_mac);
    }
    m_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (m_mac == nullptr) {
        std::cout << "EVP_MAC_fetch failed, error: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    if (digest != NULL) {
        m_ossl_params[params_n++] =
            OSSL_PARAM_construct_utf8_string("digest", (char*)digest, 0);
        m_ossl_params[params_n] = OSSL_PARAM_construct_end();
    }

    if (m_handle != nullptr) {
        EVP_MAC_CTX_free(m_handle);
    }
    m_handle = EVP_MAC_CTX_new(m_mac);
    if (m_handle == NULL) {
        std::cout << "EVP_MAC_CTX_new failed, error: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    if (EVP_MAC_init(m_handle, m_key, m_key_len, m_ossl_params) != 1) {
        std::cout << "EVP_MAC_init failed, error : "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLHmacBase::mac_update(const alcp_hmac_data_t& data)
{
    if (EVP_MAC_update(m_handle, data.in.m_msg, data.in.m_msg_len) != 1) {
        std::cout << "EVP_MAC_update failed, error : "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLHmacBase::mac_finalize(const alcp_hmac_data_t& data)
{
    size_t outsize = data.out.m_hmac_len;
    if (EVP_MAC_final(m_handle, data.out.m_hmac, &outsize, data.out.m_hmac_len)
        != 1) {
        std::cout << "EVP_MAC_final failed, error : "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLHmacBase::mac_reset()
{
    if (EVP_MAC_init(m_handle, m_key, m_key_len, m_ossl_params) != 1) {
        std::cout << "EVP_MAC_init failed, error : "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

} // namespace alcp::testing