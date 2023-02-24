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

#include "cmac/ipp_cmac_base.hh"

namespace alcp::testing {

IPPCmacBase::IPPCmacBase(const alc_mac_info_t& info) {}

IPPCmacBase::~IPPCmacBase()
{
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
        m_handle = nullptr;
    }
}

bool
IPPCmacBase::init(const alc_mac_info_t& info, std::vector<Uint8>& Key)
{
    m_info    = info;
    m_key     = &Key[0];
    m_key_len = Key.size();
    return init();
}

bool
IPPCmacBase::init()
{
    IppStatus status = ippStsNoErr;
    if (m_handle != nullptr) {
        delete[] reinterpret_cast<Uint8*>(m_handle);
        m_handle = nullptr;
    }

    int ctx_size;
    status = ippsAES_CMACGetSize(&ctx_size);
    if (status != ippStsNoErr) {
        std::cout << "ippsAES_CMACGetSize failed with err code" << status
                  << std::endl;
        return false;
    }
    m_handle = reinterpret_cast<IppsAES_CMACState*>(new Uint8[ctx_size]);

    status = ippsAES_CMACInit(m_key, m_key_len, m_handle, ctx_size);
    if (status != ippStsNoErr) {
        std::cout << "ippsAES_CMACInit failed with err code" << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPCmacBase::Cmac_function(const alcp_cmac_data_t& data)
{
    IppStatus status = ippStsNoErr;
    status           = ippsAES_CMACUpdate(data.m_msg, data.m_msg_len, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "ippsAES_CMACUpdate failed with err code" << status
                  << std::endl;
        return false;
    }
    status = ippsAES_CMACFinal(data.m_cmac, data.m_cmac_len, m_handle);
    if (status != ippStsNoErr) {
        std::cout << "ippsAES_CMACFinal failed with err code" << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPCmacBase::reset()
{
    /* IPPCP doesnt have an explicit reset call for cmac */
    return true;
}
} // namespace alcp::testing