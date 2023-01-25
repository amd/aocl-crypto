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

#include "digest/alc_digest.hh"
#include "digest/digest.hh"

namespace alcp::testing {

static Uint8 size_[4096] = { 0 };

/* Mapping between ALC sha mode and digest len. Update for upcoming ALC digest
 * types here*/
std::map<alc_digest_len_t, alc_sha2_mode_t> sha2_mode_len_map = {
    { ALC_DIGEST_LEN_224, ALC_SHA2_224 },
    { ALC_DIGEST_LEN_256, ALC_SHA2_256 },
    { ALC_DIGEST_LEN_384, ALC_SHA2_384 },
    { ALC_DIGEST_LEN_512, ALC_SHA2_512 },
};

std::map<alc_digest_len_t, alc_sha3_mode_t> sha3_mode_len_map = {
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

    if (m_info.dt_type == ALC_DIGEST_TYPE_SHA2) {
        /* for sha512-224/256 */
        if (m_info.dt_mode.dm_sha2 == ALC_SHA2_512
            && m_info.dt_len != ALC_DIGEST_LEN_512) {
            dinfo.dt_mode.dm_sha2 = ALC_SHA2_512;
            dinfo.dt_len          = m_info.dt_len;
        }
        /* for normal sha2 cases */
        else
            dinfo.dt_mode.dm_sha2 = sha2_mode_len_map[m_info.dt_len];
    } else if (m_info.dt_type == ALC_DIGEST_TYPE_SHA3) {
        if (m_info.dt_len == ALC_DIGEST_LEN_CUSTOM)
            dinfo.dt_custom_len = m_digest_len;
        else
            dinfo.dt_mode.dm_sha3 = sha3_mode_len_map[m_info.dt_len];
    }

    m_handle          = new alc_digest_handle_t;
    m_handle->context = &size_[0];

    err = alcp_digest_request(&dinfo, m_handle);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_request:" << err << std::endl;
        return false;
    }
    return true;
}

AlcpDigestBase::~AlcpDigestBase()
{
    if (m_handle != nullptr) {
        alcp_digest_finish(m_handle);
        delete m_handle;
    }
}

bool
AlcpDigestBase::digest_function(const alcp_digest_data_t& data)
{
    alc_error_t err;
    err = alcp_digest_update(m_handle, data.m_msg, data.m_msg_len);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_update:" << err << std::endl;
        return false;
    }

    err = alcp_digest_finalize(m_handle, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_finalize:" << err << std::endl;
        return false;
    }

    err = alcp_digest_copy(m_handle, data.m_digest, data.m_digest_len);
    if (alcp_is_error(err)) {
        std::cout << "Error code in alcp_digest_copy:" << err << std::endl;
        return false;
    }
    return true;
}

void
AlcpDigestBase::reset()
{
    alcp_digest_reset(m_handle);
}

} // namespace alcp::testing
