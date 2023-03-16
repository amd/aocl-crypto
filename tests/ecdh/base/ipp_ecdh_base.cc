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
    int        elem   = 8;
    if (data.m_Peer1_PvtKey == NULL || data.m_Peer2_PvtKey == NULL) {
        return false;
    }

    int    Test[elem];
    int8u* pPublicKeyData1_mb[elem];
    int8u* pPublicKeyData2_mb[elem];

    const int8u* pPrivKey1_mb[elem];
    const int8u* pPrivKey2_mb[elem];

    Uint8 publicKeyData1[8][32];
    Uint8 publicKeyData2[8][32];

    pPublicKeyData1_mb[0] = data.m_Peer1_PubKey;
    pPublicKeyData2_mb[0] = data.m_Peer2_PubKey;

    /* load keys */
    for (int i = 0; i < elem; i++) {
        pPublicKeyData1_mb[i] = publicKeyData1[i];
        pPrivKey1_mb[i]       = data.m_Peer1_PvtKey;
    }
    pPrivKey1_mb[0] = data.m_Peer1_PubKey;

    for (int i = 0; i < elem; i++) {
        pPublicKeyData2_mb[i] = publicKeyData2[i];
        pPrivKey2_mb[i]       = data.m_Peer2_PvtKey;
    }
    pPrivKey2_mb[0] = data.m_Peer2_PubKey;
    /* generate public key */
    /*TODO : get error status using MBX_GET_STS() call */
    status = mbx_x25519_public_key_mb8(pPublicKeyData1_mb, pPrivKey1_mb);
    status = mbx_x25519_public_key_mb8(pPublicKeyData2_mb, pPrivKey2_mb);

    return true;
}

bool
IPPEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data)
{
    return true;
}

bool
IPPEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
