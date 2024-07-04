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

#include "digest/ipp_digest.hh"

namespace alcp::testing {

IPPDigestBase::IPPDigestBase(alc_digest_mode_t mode)
{
    m_mode = mode;
    init();
}

IPPDigestBase::~IPPDigestBase()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
    }
    if (m_handle_dup != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle_dup);
    }
}

bool
IPPDigestBase::init()
{
    IppStatus status = ippStsNoErr;
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
        m_handle = nullptr;
    }
    int ctx_size;
    ippsHashGetSize_rmf(&ctx_size);
    m_handle = reinterpret_cast<IppsHashState_rmf*>(new Uint8[ctx_size]);
    switch (m_mode) {
        case ALC_SHA1:
            status = ippsHashInit_rmf(m_handle, ippsHashMethod_SHA1_TT());
        case ALC_MD5:
            status = ippsHashInit_rmf(m_handle, ippsHashMethod_MD5());
        case ALC_SHA2_224:
            status = ippsHashInit_rmf(m_handle, ippsHashMethod_SHA224_TT());
            break;
        case ALC_SHA2_256:
            status = ippsHashInit_rmf(m_handle, ippsHashMethod_SHA256_TT());
            break;
        case ALC_SHA2_384:
            status = ippsHashInit_rmf(m_handle, ippsHashMethod_SHA384());
            break;
        case ALC_SHA2_512_224:
            /* for truncated variants of sha512*/
            ippsHashInit_rmf(m_handle, ippsHashMethod_SHA512_224());
            break;
        case ALC_SHA2_512_256:
            /* for truncated variants of sha512*/
            ippsHashInit_rmf(m_handle, ippsHashMethod_SHA512_256());
            break;
        case ALC_SHA2_512:
            ippsHashInit_rmf(m_handle, ippsHashMethod_SHA512());
            break;
        default:
            return false;
    }

    /* check error code */
    if (status != ippStsNoErr) {
        std::cout << "Error code in ippsHashInit_rmf: " << status << std::endl;
        return false;
    }
    return true;
}

bool
IPPDigestBase::context_copy()
{
    IppStatus status = ippStsNoErr;
    /* skip ctx copy if handle is null, and there is no ctx to copy */
    if (m_handle == nullptr) {
        std::cout << "Context is null, skipping context copy" << std::endl;
        return true;
    }
    status = ippsHashDuplicate_rmf(m_handle, m_handle_dup);
    if (status != ippStsNoErr) {
        std::cout << "Error code in ippsHashUpdate_rmf: " << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPDigestBase::digest_update(const alcp_digest_data_t& data)
{
    IppStatus status = ippStsNoErr;

    status = ippsHashUpdate_rmf(data.m_msg, data.m_msg_len, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "Error code in ippsHashUpdate_rmf: " << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPDigestBase::digest_finalize(const alcp_digest_data_t& data)
{
    IppStatus status = ippStsNoErr;
    status           = ippsHashFinal_rmf(data.m_digest, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "Error code in ippsHashFinal_rmf: " << status << std::endl;
        return false;
    }
    return true;
}

bool
IPPDigestBase::digest_squeeze(const alcp_digest_data_t& data)
{
    return true;
}

void
IPPDigestBase::reset()
{}

} // namespace alcp::testing