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

#include "alcp/rsa.h"
#include "rsa/alc_rsa.hh"
#include "rsa/rsa.hh"
#include <cstring>

namespace alcp::testing {

AlcpRsaBase::AlcpRsaBase() {}

bool
AlcpRsaBase::init()
{
    alc_error_t err;
    Uint64      size = alcp_rsa_context_size();

    if (m_rsa_handle == nullptr) {
        m_rsa_handle          = new alc_rsa_handle_t;
        m_rsa_handle->context = malloc(size);
    } else if (m_rsa_handle->context == nullptr) {
        m_rsa_handle->context = malloc(size);
    } else {
        alcp_rsa_finish(m_rsa_handle);
    }

    err = alcp_rsa_request(m_rsa_handle);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_request " << err << std::endl;
        return false;
    }
    return true;
}

AlcpRsaBase::~AlcpRsaBase()
{
    if (m_rsa_handle != nullptr) {
        alcp_rsa_finish(m_rsa_handle);
        if (m_rsa_handle->context != nullptr) {
            free(m_rsa_handle->context);
            m_rsa_handle->context = nullptr;
        }
        delete m_rsa_handle;
    }
}

bool
AlcpRsaBase::GetPublicKey(const alcp_rsa_data_t& data)
{
    alc_error_t err;
    Uint64      size_key = alcp_rsa_get_key_size(m_rsa_handle);
    if (size_key == 0) {
        std::cout << "alcp_rsa_get_key_size returned 0" << std::endl;
        return false;
    }

    m_keysize = size_key;
    err       = alcp_rsa_get_publickey(
        m_rsa_handle, &m_pub_key_exp, data.m_pub_key_mod, m_keysize);

    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_get_publickey " << err << std::endl;
        return false;
    }
    return true;
}

int
AlcpRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    alc_error_t err;
    err = alcp_rsa_publickey_encrypt(m_rsa_handle,
                                     ALCP_RSA_PADDING_NONE,
                                     data.m_pub_key_mod,
                                     m_keysize,
                                     m_pub_key_exp,
                                     data.m_msg,
                                     m_keysize,
                                     data.m_encrypted_data);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_publickey_encrypt " << err << std::endl;
        return err;
    }
    return 0;
}

int
AlcpRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    alc_error_t err;
    err = alcp_rsa_privatekey_decrypt(m_rsa_handle,
                                      ALCP_RSA_PADDING_NONE,
                                      data.m_encrypted_data,
                                      m_keysize,
                                      data.m_decrypted_data);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_rsa_privatekey_decrypt " << err
                  << std::endl;
        return err;
    }
    return 0;
}

bool
AlcpRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
