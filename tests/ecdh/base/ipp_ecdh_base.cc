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

#include "ecdh/ipp_ecdh_base.hh"
#include <cstddef>
#include <cstring>
#include <iostream>
#include <ostream>

namespace alcp::testing {

IPPEcdhBase::IPPEcdhBase(const alc_ec_info_t& info) {}

IPPEcdhBase::~IPPEcdhBase() {}

bool
IPPEcdhBase::init(const alc_ec_info_t& info, const alcp_ecdh_data_t& data)
{
    return true;
}

bool
IPPEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    mbx_status status = 0;
    /* FIXME: this is because we are calling 8 elem buffer variant of ipp */
    int elem = 8;
    if (data.m_Peer1_PvtKey == NULL || data.m_Peer2_PvtKey == NULL) {
        std::cout << "Pvt key data is null" << std::endl;
        return false;
    }

    /* load keys */
    for (int i = 0; i < elem; i++) {
        m_pPublicKeyData1_mb[i] = data.m_Peer1_PubKey;
        m_pPrivKey1_mb[i]       = data.m_Peer1_PvtKey;
    }
    for (int i = 0; i < elem; i++) {
        m_pPublicKeyData2_mb[i] = data.m_Peer2_PubKey;
        m_pPrivKey2_mb[i]       = data.m_Peer2_PvtKey;
    }
    /* generate public key */
    /*TODO : get error status using MBX_GET_STS() call */
    status = mbx_x25519_public_key_mb8(m_pPublicKeyData1_mb, m_pPrivKey1_mb);
    if (status != 0) {
        std::cout << "mbx_x25519_public_key_mb8 failed with err code: "
                  << status << std::endl;
        return false;
    }
    status = mbx_x25519_public_key_mb8(m_pPublicKeyData2_mb, m_pPrivKey2_mb);
    if (status != 0) {
        std::cout << "mbx_x25519_public_key_mb8 failed with err code: "
                  << status << std::endl;
        return false;
    }
    return true;
}

bool
IPPEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data)
{
    mbx_status status = 0;
    /* FIXME: this is because we are calling 8 elem buffer variant of ipp */
    int elem = 8;
    if (data.m_Peer1_PubKey == NULL || data.m_Peer2_PubKey == NULL) {
        std::cout << "Pub key data is null" << std::endl;
        return false;
    }
    /* load keys */
    for (int i = 0; i < elem; i++) {
        m_pSecretKey1_mb[i] = data.m_Peer1_SecretKey;
    }
    for (int i = 0; i < elem; i++) {
        m_pSecretKey2_mb[i] = data.m_Peer2_SecretKey;
    }

    /* compute secret key */
    status =
        mbx_x25519_mb8(m_pSecretKey1_mb, m_pPrivKey1_mb, m_pPublicKeyData1_mb);
    status =
        mbx_x25519_mb8(m_pSecretKey2_mb, m_pPrivKey2_mb, m_pPublicKeyData2_mb);

    return true;
}

bool
IPPEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
