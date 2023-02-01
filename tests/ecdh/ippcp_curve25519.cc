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

#include <cstring>

#include "ecdh/ecdh.hh"
#include "ecdh/ippcp_ecdh.hh"

#include <crypto_mb/x25519.h>
#include <ippcp.h>

namespace alcp::testing {

using namespace std;

ippcpEcdh::ippcpEcdh(const char* pKeytype, alc_peer_id_t peerId)
{

    string st  = "peer" + to_string((int)peerId);
    m_name     = st.c_str();
    m_pkeytype = pKeytype;
    m_peerId   = peerId;
}

ippcpEcdh::~ippcpEcdh() {}

Uint8 publicKeyData1[7][32];

alc_error_t
ippcpEcdh::generate_public_key(Uint8* pPublicKeyData, const Uint8* pPrivKey)
{

    if (pPrivKey == NULL) {
        return ALC_ERROR_INVALID_DATA;
    }

    int8u*       pPublicKeyData_mb[8];
    const int8u* pPrivKey_mb[8];

    pPublicKeyData_mb[0] = pPublicKeyData;

    for (int i = 1; i < 8; i++) {
        pPublicKeyData_mb[i] = publicKeyData1[i];
        pPrivKey_mb[i] = pPrivKey; // same private key is set for all 8 paths.
    }

    m_pPrivateKeyData = pPrivKey_mb[0] = pPrivKey;

    mbx_x25519_public_key_mb8(pPublicKeyData_mb, pPrivKey_mb);

    return ALC_ERROR_NONE;
}

Uint8 secretKey[7][32];

alc_error_t
ippcpEcdh::compute_secret_key(Uint8*       pSecret_key,
                              const Uint8* pPublicKeyDataRemote,
                              Uint64*      pKeyLength)
{

    int8u*       pSecret_key_mb[8];
    const int8u* pPublicKeyDataRemote_mb[8];
    const int8u* pa_private_key[8];

    pSecret_key_mb[0]          = pSecret_key;
    pPublicKeyDataRemote_mb[0] = pPublicKeyDataRemote;
    pa_private_key[0]          = m_pPrivateKeyData;

    for (int i = 1; i < 8; i++) {
        pSecret_key_mb[i] = secretKey[i];
        pPublicKeyDataRemote_mb[i] =
            pPublicKeyDataRemote; // same public key is set for all 8 paths.
        pa_private_key[i] = m_pPrivateKeyData;
    }

    mbx_x25519_mb8(pSecret_key_mb, pa_private_key, pPublicKeyDataRemote_mb);

    *pKeyLength = 32;

    return ALC_ERROR_NONE;
}

void
ippcpEcdh::reset()
{}

} // namespace alcp::testing
