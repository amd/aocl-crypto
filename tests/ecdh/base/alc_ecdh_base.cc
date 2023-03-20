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

#include "alcp/ec.h"
#include "alcp/ecdh.h"
#include "ecdh/alc_ecdh_base.hh"
#include "ecdh/ecdh_base.hh"
#include <cstring>

namespace alcp::testing {

AlcpEcdhBase::AlcpEcdhBase(const alc_ec_info_t& info) {}

bool
AlcpEcdhBase::init(const alc_ec_info_t& info, const alcp_ecdh_data_t& data)
{
    alc_error_t err;
    m_info              = info;
    alc_ec_info_t dinfo = m_info;
    Uint64        size  = alcp_ec_context_size(&dinfo);
    /* for peer1 */
    if (m_ec_handle1 == nullptr) {
        m_ec_handle1          = new alc_ec_handle_t;
        m_ec_handle1->context = malloc(size);
    } else if (m_ec_handle1->context == nullptr) {
        m_ec_handle1->context = malloc(size);
    }

    err = alcp_ec_request(&dinfo, m_ec_handle1);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_request:Peer1 " << err << std::endl;
        return false;
    }

    /* for peer2 */
    if (m_ec_handle2 == nullptr) {
        m_ec_handle2          = new alc_ec_handle_t;
        m_ec_handle2->context = malloc(size);
    } else if (m_ec_handle2->context == nullptr) {
        m_ec_handle2->context = malloc(size);
    }

    err = alcp_ec_request(&dinfo, m_ec_handle2);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_request:Peer2: " << err << std::endl;
        return false;
    }
    return true;
}

AlcpEcdhBase::~AlcpEcdhBase()
{
    if (m_ec_handle1 != nullptr) {
        alcp_ec_finish(m_ec_handle1);
        if (m_ec_handle1->context != nullptr) {
            free(m_ec_handle1->context);
            m_ec_handle1->context = nullptr;
        }
        delete m_ec_handle1;
        m_ec_handle1 = nullptr;
    }
    if (m_ec_handle2 != nullptr) {
        alcp_ec_finish(m_ec_handle2);
        if (m_ec_handle2->context != nullptr) {
            free(m_ec_handle2->context);
            m_ec_handle2->context = nullptr;
        }
        delete m_ec_handle2;
        m_ec_handle2 = nullptr;
    }
}

bool
AlcpEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    alc_error_t err;

    err = alcp_ec_get_publickey(
        m_ec_handle1, data.m_Peer1_PubKey, data.m_Peer1_PvtKey);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_publickey peer1: " << err
                  << std::endl;
        return false;
    }
    err = alcp_ec_get_publickey(
        m_ec_handle2, data.m_Peer2_PubKey, data.m_Peer2_PvtKey);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_publickey peer2: " << err
                  << std::endl;
        return false;
    }
    return true;
}

bool
AlcpEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data)
{
    alc_error_t err;
    Uint64      keyLength1, keyLength2;
    err = alcp_ec_get_secretkey(
        m_ec_handle1, data.m_Peer1_SecretKey, data.m_Peer2_PubKey, &keyLength1);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_secretkey peer1: " << err
                  << std::endl;
        return false;
    }
    err = alcp_ec_get_secretkey(
        m_ec_handle2, data.m_Peer2_SecretKey, data.m_Peer1_PubKey, &keyLength2);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_secretkey peer2: " << err
                  << std::endl;
        return false;
    }
    return true;
}

bool
AlcpEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
