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

#include "cmac/alc_cmac.hh"
#include "cmac/cmac.hh"

namespace alcp::testing {

bool
AlcpCmacBase::Init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();

    if (m_handle == nullptr) {
        m_handle             = new alc_mac_handle_t;
        m_handle->ch_context = malloc(alcp_mac_context_size());
    } else if (m_handle->ch_context == nullptr) {
        m_handle->ch_context = malloc(alcp_mac_context_size());
    } else {
        alcp_mac_finish(m_handle);
    }

    alc_error_t err = alcp_mac_request(m_handle, ALC_MAC_CMAC);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_mac_request:" << err << std::endl;
        return false;
    }

    err = alcp_mac_init(m_handle, m_key, m_key_len, &m_info);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_mac_request:" << err << std::endl;
        return false;
    }
    return true;
}

AlcpCmacBase::~AlcpCmacBase()
{
    if (m_handle != nullptr) {
        alcp_mac_finish(m_handle);
        if (m_handle->ch_context != nullptr) {
            free(m_handle->ch_context);
            m_handle->ch_context = nullptr;
        }
        delete m_handle;
        m_handle = nullptr;
    }
}

bool
AlcpCmacBase::MacUpdate(const alcp_cmac_data_t& data)
{
    alc_error_t err;
    err = alcp_mac_update(m_handle, data.m_msg, data.m_msg_len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_mac_update failed: Err code: " << err << std::endl;
        return false;
    }
    return true;
}

bool
AlcpCmacBase::MacFinalize(const alcp_cmac_data_t& data)
{
    alc_error_t err;
    err = alcp_mac_finalize(m_handle, data.m_cmac, data.m_cmac_len);
    if (alcp_is_error(err)) {
        std::cout << "alcp_mac_finalize failed: Err code: " << err << std::endl;
        return false;
    }
    return true;
}

bool
AlcpCmacBase::MacReset()
{
    alc_error_t err;
    err = alcp_mac_reset(m_handle);
    if (alcp_is_error(err)) {
        std::cout << "alcp_mac_reset failed: Err code: " << err << std::endl;
        return false;
    }
    return true;
}

} // namespace alcp::testing
