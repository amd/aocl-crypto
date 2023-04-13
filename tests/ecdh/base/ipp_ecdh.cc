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

#include "ecdh/ipp_ecdh.hh"
#include <cstddef>
#include <cstring>
#include <iostream>
#include <ostream>

namespace alcp::testing {

IPPEcdhBase::IPPEcdhBase(const alc_ec_info_t& info) {}

IPPEcdhBase::~IPPEcdhBase() {}

bool
IPPEcdhBase::init(const alc_ec_info_t& info)
{
    m_info = info;
    return true;
}

bool
IPPEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    mbx_status status = 0;
    /* FIXME: this is because we are calling 8 elem buffer variant of ipp */
    int elem = 8;
    if (data.m_Peer_PvtKey == NULL) {
        std::cout << "Pvt key data is null" << std::endl;
        return false;
    }

    /* load keys */
    /* TODO: when there is alcp multi-buffer implementation available, modify
     * this*/
    Uint8 m_pPublicKeyData_mb_temp_buff[7][ECDH_KEYSIZE];
    m_pPublicKeyData_mb[0] = data.m_Peer_PubKey;
    m_pPrivKey_mb[0]       = data.m_Peer_PvtKey;
    for (int i = 1; i < elem; i++) {
        m_pPrivKey_mb[i]       = data.m_Peer_PvtKey;
        m_pPublicKeyData_mb[i] = m_pPublicKeyData_mb_temp_buff[i - 1];
    }

    /* generate public key */
    status = mbx_x25519_public_key_mb8(m_pPublicKeyData_mb, m_pPrivKey_mb);
    if (MBX_STATUS_OK != MBX_GET_STS(status, 0)) {
        std::cout << "mbx_x25519_public_key_mb8 failed with err code: "
                  << status << std::endl;
        return false;
    }
    return true;
}

bool
IPPEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data_peer1,
                              const alcp_ecdh_data_t& data_peer2)
{
    mbx_status status = 0;
    /* FIXME: this is because we are calling 8 elem buffer variant of ipp */
    int elem = 8;
    if (data_peer1.m_Peer_PubKey == NULL || data_peer2.m_Peer_PubKey == NULL) {
        std::cout << "Pub key data is null" << std::endl;
        return false;
    }
    /* load keys */
    for (int i = 0; i < elem; i++) {
        m_pSecretKey_mb[i]     = data_peer1.m_Peer_SecretKey;
        m_pPublicKeyData_mb[i] = data_peer2.m_Peer_PubKey;
        // same public key is set for all 8 paths.
    }

    /* compute secret key using pub key of the other peer */
    status =
        mbx_x25519_mb8(m_pSecretKey_mb, m_pPrivKey_mb, m_pPublicKeyData_mb);
    if (MBX_STATUS_OK != MBX_GET_STS(status, 0)) {
        std::cout << "mbx_x25519_mb8 failed with err code: " << status
                  << std::endl;
        return false;
    }
    return true;
}

bool
IPPEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing