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

#include "alcp/alcp.hh"
#include "alcp/ec.hh"

#ifdef COMPILER_IS_GCC
#define UNROLL_4  _Pragma("GCC unroll 4")
#define UNROLL_16 _Pragma("GCC unroll 16")
#define UNROLL_30 _Pragma("GCC unroll 30")
#define UNROLL_51 _Pragma("GCC unroll 51")
#define UNROLL_52 _Pragma("GCC unroll 52")
#else
#define UNROLL_4
#define UNROLL_16
#define UNROLL_30
#define UNROLL_51
#define UNROLL_52
#endif

namespace alcp::ec {

struct PrecomputedPoint
{
    Uint64 m_x[4]{};
    Uint64 m_y[4]{};
    Uint64 m_z[4]{};
    PrecomputedPoint()
    {
        m_x[0] = 1;
        m_y[0] = 1;
    }
    void init()
    {
        m_x[0] = 1;
        m_y[0] = 1;
        m_x[1] = 0;
        m_y[1] = 0;
        m_x[2] = 0;
        m_y[2] = 0;
        m_x[3] = 0;
        m_y[3] = 0;
        m_z[0] = 0;
        m_z[1] = 0;
        m_z[2] = 0;
        m_z[3] = 0;
    }
};

class X25519 : public Ec
{
  public:
    ALCP_API_EXPORT X25519();
    ~X25519();

    /**
     * @brief Function generates x25519 public key using input privateKey
     * generated public key is shared with the peer.
     *
     * @param  pPublicKey  pointer to Output Publickey generated
     * @param  pPrivKey    pointer to Input privateKey used for generating
     * publicKey
     * @return Status Error code
     */
    ALCP_API_EXPORT Status generatePublicKey(Uint8*       pPublicKey,
                                             const Uint8* pPrivKey) override;

    /**
     * @brief Function computes x25519 secret key with publicKey from remotePeer
     * and local privatekey.
     *
     * @param  pSecretKey  pointer to output secretKey
     * @param  pPublicKey  pointer to Input privateKey used for generating
     * publicKey
     * @param  pKeyLength  pointer to keyLength
     * @return Status Error code
     */
    ALCP_API_EXPORT Status computeSecretKey(Uint8*       pSecretKey,
                                            const Uint8* pPublicKey,
                                            Uint64*      pKeyLength) override;

    /**
     * @brief Function validates public key from remote peer
     *
     * @param  pPublicKey  pointer to public key publicKey
     * @param  pKeyLength  pointer to keyLength
     * @return Status Error code
     */
    virtual Status validatePublicKey(const Uint8* pPublicKey,
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
    Uint8 m_PrivKey[32] = {};
};

} // namespace alcp::ec

// x2519 apis

// NIST curves
// p-256 api
