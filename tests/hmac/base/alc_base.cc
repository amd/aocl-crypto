/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "hmac/alc_base.hh"
#include "hmac/base.hh"

namespace alcp::testing {

static Uint8 size_[4096] = { 0 };

AlcpHmacBase::AlcpHmacBase(const alc_mac_info_t& info) {}

bool
AlcpHmacBase::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();
    return init();
}

bool
AlcpHmacBase::init()
{
    alc_error_t    err;
    alc_mac_info_t dinfo = m_info;

    const alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = m_key_len,
                                   .key  = m_key };

    dinfo.mi_keyinfo = kinfo;
    if (m_handle == nullptr) {
        m_handle             = new alc_mac_handle_t;
        m_handle->ch_context = malloc(alcp_mac_context_size(&dinfo));
    } else if (m_handle->ch_context == nullptr) {
        m_handle->ch_context = malloc(alcp_mac_context_size(&dinfo));
    }

    err = alcp_mac_request(m_handle, &dinfo);
    if (alcp_is_error(err)) {
        printf("Error code in alcp_mac_request: %ld\n", err);
        return false;
    }
    return true;
}

AlcpHmacBase::~AlcpHmacBase()
{
    if (m_handle != nullptr) {
        alcp_mac_finish(m_handle);
        delete m_handle;
        m_handle = nullptr;
    }
}

alc_error_t
AlcpHmacBase::Hmac_function(const alcp_hmac_data_t& data)
{
    alc_error_t err;

    err = alcp_mac_update(m_handle, data.m_msg, data.m_msg_len);
    if (alcp_is_error(err)) {
        printf("HMAC update failed: Err code: %ld\n", err);
    }

    alcp_mac_finalize(m_handle, NULL, 0);
    if (alcp_is_error(err)) {
        printf("HMAC finalize failed: Error code: %ld\n", err);
    }

    err = alcp_mac_copy(m_handle, data.m_hmac, data.m_hmac_len);
    if (alcp_is_error(err)) {
        printf("HMAC copy failed: Error code: %ld\n", err);
    }

    err = alcp_mac_finish(m_handle);
    if (alcp_is_error(err)) {
        printf("HMAC Finish failed: Error code: %ld\n", err);
    }
    free(m_handle->ch_context);
    m_handle->ch_context = nullptr;
    return err;
}

void
AlcpHmacBase::reset()
{
    free(m_handle->ch_context);
}

} // namespace alcp::testing