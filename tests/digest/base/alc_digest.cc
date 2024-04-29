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

#include "digest/alc_digest.hh"
#include "digest/digest.hh"

namespace alcp::testing {

/* Mapping between ALC sha mode and digest len. Update for upcoming ALC digest
 * types here*/
std::map<alc_digest_len_t, alc_digest_mode_t> sha2_mode_len_map = {
    { ALC_DIGEST_LEN_224, ALC_SHA2_224 },
    { ALC_DIGEST_LEN_256, ALC_SHA2_256 },
    { ALC_DIGEST_LEN_384, ALC_SHA2_384 },
    { ALC_DIGEST_LEN_512, ALC_SHA2_512 },
};

std::map<alc_digest_len_t, alc_digest_mode_t> sha3_mode_len_map = {
    { ALC_DIGEST_LEN_224, ALC_SHA3_224 },
    { ALC_DIGEST_LEN_256, ALC_SHA3_256 },
    { ALC_DIGEST_LEN_384, ALC_SHA3_384 },
    { ALC_DIGEST_LEN_512, ALC_SHA3_512 },
};

AlcpDigestBase::AlcpDigestBase(const alc_digest_info_t& info)
{
    init(info, m_digest_len);
}

bool
AlcpDigestBase::init(const alc_digest_info_t& info, Int64 digest_len)
{
    m_info       = info;
    m_digest_len = digest_len;
    return init();
}

bool
AlcpDigestBase::init()
{
    alc_error_t       err;
    alc_digest_info_t dinfo = m_info;

    if (m_handle == nullptr) {
        m_handle          = new alc_digest_handle_t;
        m_handle->context = malloc(alcp_digest_context_size());
    } else if (m_handle->context == nullptr) {
        m_handle->context = malloc(alcp_digest_context_size());
    } else {
        alcp_digest_finish(m_handle);
    }

    err = alcp_digest_request(dinfo.dt_mode, m_handle);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_request:" << err << std::endl;
        return false;
    }

    err = alcp_digest_init(m_handle);

    if (alcp_is_error(err)) {
        return false;
    }

    return true;
}

AlcpDigestBase::~AlcpDigestBase()
{
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        if (m_handle->context != nullptr) {
            free(m_handle->context);
            m_handle->context = nullptr;
        }
        delete m_handle;
        m_handle = nullptr;
    }
}

bool
AlcpDigestBase::context_copy()
{
    alc_error_t err;
    /* skip ctx copy if handle is null, and there is no ctx to copy */
    if (m_handle == nullptr || m_handle->context == nullptr) {
        std::cout << "Context is null, skipping context copy" << std::endl;
        return true;
    }
    m_handle_dup          = new alc_digest_handle_t;
    m_handle_dup->context = malloc(alcp_digest_context_size());
    err                   = alcp_digest_context_copy(m_handle, m_handle_dup);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_context_copy:" << err
                  << std::endl;
        return false;
    }
    std::swap(m_handle, m_handle_dup);
    /* now free dup handle */
    if (m_handle_dup != nullptr) {
        alcp_digest_finish(m_handle_dup);
        if (m_handle_dup->context != nullptr) {
            free(m_handle_dup->context);
            m_handle_dup->context = nullptr;
        }
        delete m_handle_dup;
        m_handle_dup = nullptr;
    }
    return true;
}

bool
AlcpDigestBase::digest_function(const alcp_digest_data_t& data)
{
    alc_error_t err;
    if (data.m_msg != nullptr && data.m_msg_len > 0) {
        err = alcp_digest_update(m_handle, data.m_msg, data.m_msg_len);
        if (alcp_is_error(err)) {
            std::cout << "Error code in alcp_digest_update:" << err
                      << std::endl;
            return false;
        }
    }
    err = alcp_digest_finalize(m_handle, data.m_digest, data.m_digest_len);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_finalize:" << err << std::endl;
        return false;
    }
    return true;
}

void
AlcpDigestBase::reset()
{
    alcp_digest_init(m_handle);
}

} // namespace alcp::testing
