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

#pragma once

#include "ec.hh"

#define ALCP_X25519_ADDED 0

#if ALCP_X25519_ADDED
void
alcpScalarMulX25519(Uint8*       mypublic,
                    const Uint8* secret,
                    const Uint8* basepoint);
#endif

class EcX25519 : public Ec
{
  public:
    EcX25519();
    ~EcX25519() = default;

    /**
     * @brief Function generates x25519 public key using input privateKey
     * generated public key is shared with the peer.
     *
     * @param  pPublicKey  pointer to Output Publickey generated
     * @param  pPrivKey    pointer to Input privateKey used for generating
     * publicKey
     * @return alc_error_t Error code
     */
    ALCP_API_EXPORT alc_error_t
    GeneratePublicKey(Uint8* pPublicKey, const Uint8* pPrivKey) override;

    /**
     * @brief Function computes x25519 secret key with publicKey from remotePeer
     * and local privatekey.
     *
     * @param  pSecretKey  pointer to output secretKey
     * @param  pPublicKey  pointer to Input privateKey used for generating
     * publicKey
     * @param  pKeyLength  pointer to keyLength
     * @return alc_error_t Error code
     */
    ALCP_API_EXPORT alc_error_t ComputeSecretKey(Uint8*       pSecretKey,
                                                 const Uint8* pPublicKey,
                                                 Uint64* pKeyLength) override;

    /**
     * @brief Function validates public key from remote peer
     *
     * @param  pPublicKey  pointer to public key publicKey
     * @param  pKeyLength  pointer to keyLength
     * @return alc_error_t Error code
     */
    virtual alc_error_t ValidatePublicKey(const Uint8* pPublicKey,
                                          Uint64       pKeyLength) override;
    /**
     * @brief Function resets the internal state
     *
     * @return nothing
     */
    void reset() override;

    /**
     * @brief  Returns the key size in bytes
     * @return key size
     */
    Uint64 getKeySize() override;

  private:
    std::vector<Uint8> m_pPrivKey;
};

// x2519 apis

// NIST curves
// p-256 api
