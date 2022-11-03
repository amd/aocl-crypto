/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "digest/ipp_base.hh"

namespace alcp::testing {

IPPDigestBase::IPPDigestBase(
                            //_alc_sha2_mode   mode,
                             _alc_digest_type type,
                             _alc_digest_len  sha_len)
    //: m_mode{ mode }
    : m_type{ type }
    , m_sha_len{ sha_len }
{
    init();
}


IPPDigestBase::~IPPDigestBase()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
    }
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
    if (m_type == ALC_DIGEST_TYPE_SHA2) {
        switch (m_mode) {
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


bool
IPPDigestBase::init(
                    //_alc_sha2_mode   mode,
                    _alc_digest_type type,
                    _alc_digest_len  sha_len)
{
    //this->m_mode    = mode;
    this->m_type    = type;
    this->m_sha_len = sha_len;
    return init();
}


alc_error_t
IPPDigestBase::digest_function(const Uint8* in,
                               Uint64       in_size,
                               Uint8*       out,
                               Uint64       out_size)
{
    ippsHashUpdate_rmf(in, in_size, m_handle);
    ippsHashFinal_rmf(out, m_handle);
    return ALC_ERROR_NONE;
}

void
IPPDigestBase::reset()
{}

void
IPPDigestBase::hash_to_string(char*        output_string,
                              const Uint8* hash,
                              int          sha_len)
{
    for (int i = 0; i < sha_len / 8; i++) {
        output_string += sprintf(output_string, "%02x", hash[i]);
    }
    output_string[(sha_len / 8) * 2 + 1] = '\0';
}


} // namespace alcp::testing