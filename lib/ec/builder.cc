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

#include "capi/ec/builder.hh"
#include "capi/ec/ctx.hh"

#include "ec.hh"
#include "ec/ecdh.hh"

namespace alcp::ec {

using Context = alcp::ec::Context;

template<typename ECTYPE>
static alc_error_t
__ec_getPublicKey_wrapper(void* pEc, Uint8* pPublicKey, const Uint8* pPrivKey)
{
    alc_error_t e  = ALC_ERROR_NONE;
    auto        ap = static_cast<ECTYPE*>(pEc);
    e              = ap->GeneratePublicKey(pPublicKey, pPrivKey);

    return e;
}

template<typename ECTYPE>
static alc_error_t
__ec_getSecretKey_wrapper(void*        pEc,
                          Uint8*       pSecretKey,
                          const Uint8* pPublicKey,
                          Uint64*      pKeyLength)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<ECTYPE*>(pEc);
    e       = ap->ComputeSecretKey(pSecretKey, pPublicKey, pKeyLength);

    return e;
}

template<typename ECTYPE>
static alc_error_t
__ec_dtor(void* pEc)
{
    alc_error_t e  = ALC_ERROR_NONE;
    auto        ap = static_cast<ECTYPE*>(pEc);
    // FIXME: Not a good idea!
    ap->~ECTYPE();
    return e;
}

class x25519Builder
{
  public:
    static alc_error_t Build(const alc_ec_info_t& rEcInfo, Context& rCtx)
    {
        alc_error_t err   = ALC_ERROR_NONE;
        auto        addr  = reinterpret_cast<Uint8*>(&rCtx) + sizeof(rCtx);
        auto        algo  = new (addr) EcX25519();
        rCtx.m_ec         = static_cast<void*>(algo);
        rCtx.getPublicKey = __ec_getPublicKey_wrapper<EcX25519>;
        rCtx.getSecretKey = __ec_getSecretKey_wrapper<EcX25519>;
        rCtx.finish       = __ec_dtor<EcX25519>;
        // rCtx.reset       = __sha_reset_wrapper<x25519>;
        return err;
    }
};

#if 0
Uint32
EcBuilder::getSize(const alc_ec_info_t& rEcInfo)
{
    switch (rEcInfo.ecCurveId) {
        case ALCP_EC_CURVE25519:
            return sizeof(EcX25519);
            break;
        case ALCP_EC_SECP256R1:
            return 0;//return sizeof(Sha3);
            break;
        default:
            return 0;
    }
}
#endif

alc_error_t
EcBuilder::Build(const alc_ec_info_t& rEcInfo, Context& rCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (rEcInfo.ecCurveId) {
        case ALCP_EC_CURVE25519:
            err = x25519Builder::Build(rEcInfo, rCtx);
            break;
        case ALCP_EC_SECP256R1:
            // err = p256Builder::Build(rEcInfo, rCtx);
            break;

        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

} // namespace alcp::ec
