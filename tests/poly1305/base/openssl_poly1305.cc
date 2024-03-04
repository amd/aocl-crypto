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

#include "poly1305/openssl_poly1305.hh"

namespace alcp::testing {

OpenSSLPoly1305Base::OpenSSLPoly1305Base(const alc_mac_info_t& info) {}

OpenSSLPoly1305Base::~OpenSSLPoly1305Base()
{
    EVP_MAC_CTX_free(m_handle);
    EVP_MAC_free(m_mac);
}

bool
OpenSSLPoly1305Base::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();
    return init();
}

bool
OpenSSLPoly1305Base::init()
{
    if (m_mac != nullptr)
        EVP_MAC_free(m_mac);
    m_mac = EVP_MAC_fetch(NULL, "POLY1305", "provider=default");
    if (m_mac == nullptr) {
        std::cout << "EVP_MAC_fetch returned nullptr: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_handle != nullptr)
        EVP_MAC_CTX_free(m_handle);
    m_handle = EVP_MAC_CTX_new(m_mac);
    if (m_handle == nullptr) {
        std::cout << "EVP_MAC_CTX_new returned nullptr: "
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1 != EVP_MAC_init(m_handle, m_key, m_key_len, nullptr)) {
        std::cout << "EVP_MAC_init failed, error : " << ERR_get_error()
                  << std::endl;
        return false;
    }
    return true;
}

bool
OpenSSLPoly1305Base::mac(const alcp_poly1305_data_t& data)
{
    size_t outsize;
    if (1 != EVP_MAC_update(m_handle, data.m_msg, data.m_msg_len)) {
        std::cout << "EVP_MAC_update failed, error : " << ERR_get_error()
                  << std::endl;
        return false;
    }
    if (1 != EVP_MAC_final(m_handle, data.m_mac, &outsize, data.m_mac_len)) {
        std::cout << "EVP_MAC_final failed, error : " << ERR_get_error()
                  << std::endl;
        return false;
    }
    reset();
    return true;
}

bool
OpenSSLPoly1305Base::reset()
{
    if (1 != EVP_MAC_init(m_handle, m_key, m_key_len, nullptr)) {
        std::cout << "EVP_MAC_init failed, error : " << ERR_get_error()
                  << std::endl;
        return false;
    }
    return true;
}

} // namespace alcp::testing
