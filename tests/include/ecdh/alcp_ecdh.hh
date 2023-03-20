/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#pragma once

/* C/C++ Headers */
#include <iostream>
#include <stdio.h>
#include <string.h>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "alcp/ec.h"
#include "alcp/ecdh.h"
#include "ecdh.hh"

namespace alcp::testing {
class AlcpEcdh : public ecdh
{
    void*       m_handle = nullptr;
    const char* m_name;
    const char* m_pkeytype;

    const Uint8* m_pPrivateKeyData;
    Uint8*       m_pSecret = NULL;
    Uint64       m_secretLength;

  public:
    Uint8  m_publicKeyData[MAX_SIZE_KEY_DATA];
    Uint64 m_publicKey_len;

    bool          m_isKAT;
    alc_peer_id_t m_peerId;
    std::string   m_peerName;

  public:
    // Create ecdh with EC type.
    AlcpEcdh(const char* pKeytype, alc_peer_id_t peerId);
    ~AlcpEcdh();

    /**
     * @brief Function generates public key using input privateKey generated
     * public key is shared with the peer.
     * @param pPublicKey - pointer to Output Publickey generated
     * @param pPrivKey - pointer to Input privateKey used for generating
     * publicKey
     * @return true
     * @return false
     */
    alc_error_t generate_public_key(Uint8* pPublicKey, const Uint8* pPrivKey);

    /**
     * @brief Function compute secret key with publicKey from remotePeer and
     * local privatekey.
     *
     * @param pSecretKey - pointer to output secretKey
     * @param pPublicKey - pointer to Input privateKey used for generating
     * publicKey
     * @param pKeyLength - pointer to keyLength
     * @return true
     * @return false
     */
    alc_error_t compute_secret_key(Uint8*       pSecretKey,
                                   const Uint8* pPublicKey,
                                   Uint64*      pKeyLength);

    void reset();
};
} // namespace alcp::testing
