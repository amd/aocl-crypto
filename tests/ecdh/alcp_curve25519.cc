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

#include "ecdh/alcp_ecdh.hh"
#include "ecdh/ecdh.hh"

#include "alcp/ec.h"
#include "alcp/ecdh.h"

namespace alcp::testing {

using namespace std;

alcpEcdh::alcpEcdh(const char* pKeytype, alc_peer_id_t peerId)
{

    string st  = "peer" + to_string((int)peerId);
    m_name     = st.c_str();
    m_pkeytype = pKeytype;
    m_peerId   = peerId;
}

alcpEcdh::~alcpEcdh() {}

alc_error_t
alcpEcdh::generate_public_key(Uint8* pPublicKeyData, const Uint8* pPrivKey)
{

    if (pPrivKey == NULL) {
        return ALC_ERROR_INVALID_DATA;
    }

    // GeneratePublicKey(pPublicKeyData, pPrivKey);
    memcpy(m_publicKeyData, pPublicKeyData, 32);

    return ALC_ERROR_NONE;
}

alc_error_t
alcpEcdh::compute_secret_key(Uint8*       pSecret_key,
                             const Uint8* pPublicKeyDataRemote,
                             Uint64*      pKeyLength)
{

    // ComputeSecretKey(pSecret_key, pPublicKeyDataRemote, pKeyLength);

    return ALC_ERROR_NONE;
}

void
alcpEcdh::reset()
{}

} // namespace alcp::testing
