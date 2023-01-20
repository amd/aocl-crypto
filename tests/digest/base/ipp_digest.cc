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

#include "digest/ipp_digest.hh"

namespace alcp::testing {

IPPDigestBase::IPPDigestBase(const alc_digest_info_t& info)
{
    init(info, m_digest_len);
}

IPPDigestBase::~IPPDigestBase()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
    }
}

bool
IPPDigestBase::init(const alc_digest_info_t& info, Int64 digest_len)
{
    m_info = info;
    return init();
}

bool
IPPDigestBase::init()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
        m_handle = nullptr;
    }
    int ctx_size;
    ippsHashGetSize_rmf(&ctx_size);
    m_handle = reinterpret_cast<IppsHashState_rmf*>(new Uint8[ctx_size]);
    if (m_info.dt_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_info.dt_mode.dm_sha2) {
            case ALC_SHA2_224:
                ippsHashInit_rmf(m_handle, ippsHashMethod_SHA224());
                break;
            case ALC_SHA2_256:
                ippsHashInit_rmf(m_handle, ippsHashMethod_SHA256());
                break;
            case ALC_SHA2_384:
                ippsHashInit_rmf(m_handle, ippsHashMethod_SHA384());
                break;
            case ALC_SHA2_512:
                ippsHashInit_rmf(m_handle, ippsHashMethod_SHA512());
                break;
            default:
                return false;
        }
    } else {
        return false;
    }
    return true;
}

alc_error_t
IPPDigestBase::digest_function(const alcp_digest_data_t& data)
{
    ippsHashUpdate_rmf(data.m_msg, data.m_msg_len, m_handle);
    ippsHashFinal_rmf(data.m_digest, m_handle);
    return ALC_ERROR_NONE;
}

void
IPPDigestBase::reset()
{}

} // namespace alcp::testing