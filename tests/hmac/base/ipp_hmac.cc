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

#include "hmac/ipp_hmac.hh"

/* get digest from SHA type*/
std::map<alc_digest_mode_t, const IppsHashMethod*> IPPDigestMap = {
    { ALC_SHA2_224, ippsHashMethod_SHA224_TT() },
    { ALC_SHA2_256, ippsHashMethod_SHA256_TT() },
    { ALC_SHA2_384, ippsHashMethod_SHA384() },
    { ALC_SHA2_512, ippsHashMethod_SHA512() },
    { ALC_SHA2_512_224, ippsHashMethod_SHA512_224() },
    { ALC_SHA2_512_256, ippsHashMethod_SHA512_256() }
};

namespace alcp::testing {

IPPHmacBase::IPPHmacBase(const alc_mac_info_t& info) {}

IPPHmacBase::~IPPHmacBase()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
    }
}

bool
IPPHmacBase::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();
    return init();
}

// A helper function to convert ALCP digestinfo to IPPHashMethod
const IppsHashMethod*
getIppHashMethod(alc_digest_mode_t pDigestMode)
{
    return IPPDigestMap[pDigestMode];
}

bool
IPPHmacBase::init()
{
    IppStatus status = ippStsNoErr;
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
        m_handle = nullptr;
    }

    int ctx_size;
    ippsHMACGetSize_rmf(&ctx_size);
    m_handle = reinterpret_cast<IppsHMACState_rmf*>(new Uint8[ctx_size]);

    /* IPPCP Doesnt have HMAC SHA3 supported */
    switch (m_info.mi_algoinfo.hmac.digest_mode) {
        case ALC_SHA3_224:
        case ALC_SHA3_256:
        case ALC_SHA3_384:
        case ALC_SHA3_512:
            std::cout
                << "IPPCP doesnt have HMAC-SHA3 support yet,skipping the test"
                << std::endl;
            return true;
        default:
            break;
    }
    const IppsHashMethod* p_hash_method =
        getIppHashMethod(m_info.mi_algoinfo.hmac.digest_mode);
    if (p_hash_method == nullptr) {
        std::cout << "IPPCP: Provided Digest Not Supported" << std::endl;
        return false;
    }
    status = ippsHMACInit_rmf(m_key, m_key_len, m_handle, p_hash_method);
    if (status != ippStsNoErr) {
        std::cout << "ippsHMACInit_rmf failed with err code: " << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPHmacBase::Hmac_function(const alcp_hmac_data_t& data)
{
    IppStatus status = ippStsNoErr;

    status = ippsHMACUpdate_rmf(data.in.m_msg, data.in.m_msg_len, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "ippsHMACUpdate_rmf failed, err code: " << status
                  << std::endl;
        return false;
    }
    status = ippsHMACFinal_rmf(data.out.m_hmac, data.out.m_hmac_len, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "ippsHMACFinal_rmf failed, err code: " << status
                  << std::endl;
        return false;
    }
    return true;

    // clang-format off
    // FIXME: Add the below code to provider testing when implemented
    /* 
    // code to calculate HMAC in a single run 
    status = ippsHMACMessage_rmf(data.in.m_msg,
                                    data.in.m_msg_len,
                                    data.in.m_key,
                                    data.in.m_key_len,
                                    data.out.m_hmac,
                                    data.out.m_hmac_len,
                                    getIppHashMethod(&m_info.mi_algoinfo.hmac.digest_mode)); */
    // clang-format on
}

bool
IPPHmacBase::reset()
{
    return true;
}

} // namespace alcp::testing