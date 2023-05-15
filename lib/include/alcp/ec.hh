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

/* C++ headers */
#include "alcp/base.hh"

#include <array>
#include <cstdint>
#include <functional>
#include <iostream>

namespace alcp::ec {

// FIXME: modifty the macro a equation based.
constexpr Uint8 ALC_MAX_EC_PRECISION_IN_64BITS = 4;
struct AlcpEcPoint
{
    Uint64 x[ALC_MAX_EC_PRECISION_IN_64BITS]; // Mont curves only x co-ordinate
                                              // in ec point
    Uint64 y[ALC_MAX_EC_PRECISION_IN_64BITS];
    Uint64 z[ALC_MAX_EC_PRECISION_IN_64BITS];
};

struct AlcpEcPointExtended
{
    AlcpEcPointExtended()
    {
        y[0] = 1;
        z[0] = 1;
    }

    Uint64 x[ALC_MAX_EC_PRECISION_IN_64BITS]{}; // Mont curves only x
                                                // co-ordinate in ec point
    Uint64 y[ALC_MAX_EC_PRECISION_IN_64BITS]{};
    Uint64 z[ALC_MAX_EC_PRECISION_IN_64BITS]{};
    Uint64 t[ALC_MAX_EC_PRECISION_IN_64BITS]{};
};

// FIXME: AlcpEcParam may not be exposed right now.
struct AlcpEcParam
{
    Uint64 prime[ALC_MAX_EC_PRECISION_IN_64BITS];
    Uint64 a[ALC_MAX_EC_PRECISION_IN_64BITS];
    Uint64 b[ALC_MAX_EC_PRECISION_IN_64BITS];

    // distinguished point in an elliptic curve group that generates a subgroup
    // of prime order n
    AlcpEcPoint G;
    Uint64      n_order[ALC_MAX_EC_PRECISION_IN_64BITS];
    Uint64      h_cofactor[ALC_MAX_EC_PRECISION_IN_64BITS];

    int q;

    Uint8*       seed;
    unsigned int seedLen;
};

// FIXME: alc_key_info may not be exposed right now.
struct alc_key_param
{
    AlcpEcParam ecParam;

    // private keys
    Uint64 de[ALC_MAX_EC_PRECISION_IN_64BITS]; // ephermeral
    Uint64 ds[ALC_MAX_EC_PRECISION_IN_64BITS]; // static

    // public keys
    AlcpEcPoint Qe; // ephermeral
    AlcpEcPoint Qs; // static

    // public key Peer
    AlcpEcPoint QeP; // ephermeral
    AlcpEcPoint QsP; // static

    Uint64 z[ALC_MAX_EC_PRECISION_IN_64BITS]; // shared secret key
};

class IEc
{
  public:
    IEc() {}

  public:
    virtual Status setPrivateKey(const Uint8* pPrivKey) = 0;

    virtual Status generatePublicKey(Uint8*       pPublicKey,
                                     const Uint8* pPrivKey) = 0;

    virtual Status computeSecretKey(Uint8*       pSecretKey,
                                    const Uint8* pPublicKey,
                                    Uint64*      pKeyLength) = 0;

    virtual Status validatePublicKey(const Uint8* pPublicKey,
                                     Uint64       pKeyLength) = 0;

    virtual void reset() = 0;

    /**
     * @return The key size in bytes
     */
    virtual Uint64 getKeySize() = 0;

  protected:
    virtual ~IEc() {}
};

class Ec : public IEc
{
  protected:
    Uint64 m_secretkey_len_bytes;
    // FIXME needs to modified after NIST curves implementation.
    AlcpEcPoint m_data;

  protected:
    Ec()          = default;
    virtual ~Ec() = default;
};

} // namespace alcp::ec
