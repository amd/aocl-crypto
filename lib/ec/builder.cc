/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/capi/ec/builder.hh"
#include "alcp/capi/ec/ctx.hh"

#include "alcp/ec.hh"
#include "alcp/ec/ecdh.hh"

namespace alcp::ec {

using Context = alcp::ec::Context;

template<typename ECTYPE>
static Status
__ec_setPrivateKey_wrapper(void* pEc, const Uint8* pPrivKey)
{
    auto ap = static_cast<ECTYPE*>(pEc);
    return ap->setPrivateKey(pPrivKey);
}

template<typename ECTYPE>
static Status
__ec_getPublicKey_wrapper(void* pEc, Uint8* pPublicKey, const Uint8* pPrivKey)
{
    auto ap = static_cast<ECTYPE*>(pEc);
    return ap->generatePublicKey(pPublicKey, pPrivKey);
}

template<typename ECTYPE>
static Status
__ec_getSecretKey_wrapper(void*        pEc,
                          Uint8*       pSecretKey,
                          const Uint8* pPublicKey,
                          Uint64*      pKeyLength)
{
    auto ap = static_cast<ECTYPE*>(pEc);
    return ap->computeSecretKey(pSecretKey, pPublicKey, pKeyLength);
}

template<typename ECTYPE>
static Status
__ec_dtor(void* pEc)
{
    auto ap = static_cast<ECTYPE*>(pEc);
    // FIXME: Not a good idea!
    ap->~ECTYPE();
    return StatusOk();
}

template<typename ECTYPE>
static Status
__ec_reset_wrapper(void* pEc)
{
    auto ap = static_cast<ECTYPE*>(pEc);
    // FIXME: Not a good idea!
    ap->reset();
    return StatusOk();
}

class x25519Builder
{
  public:
    static Status Build(const alc_ec_info_t& rEcInfo, Context& rCtx)
    {
        auto addr = reinterpret_cast<Uint8*>(&rCtx) + sizeof(rCtx);
        auto algo = new (addr) X25519();
        rCtx.m_ec = static_cast<void*>(algo);

        rCtx.setPrivateKey = __ec_setPrivateKey_wrapper<X25519>;
        rCtx.getPublicKey  = __ec_getPublicKey_wrapper<X25519>;
        rCtx.getSecretKey  = __ec_getSecretKey_wrapper<X25519>;
        rCtx.finish        = __ec_dtor<X25519>;
        rCtx.reset         = __ec_reset_wrapper<X25519>;
        return StatusOk();
    }
};

class p256Builder
{
  public:
    static Status Build(const alc_ec_info_t& rEcInfo, Context& rCtx)
    {
        auto addr = reinterpret_cast<Uint8*>(&rCtx) + sizeof(rCtx);
        auto algo = new (addr) P256(); // FIXME: Placement New is Depriciated
        rCtx.m_ec = static_cast<void*>(algo);

        rCtx.setPrivateKey = __ec_setPrivateKey_wrapper<P256>;
        rCtx.getPublicKey  = __ec_getPublicKey_wrapper<P256>;
        rCtx.getSecretKey  = __ec_getSecretKey_wrapper<P256>;
        rCtx.finish        = __ec_dtor<P256>;
        rCtx.reset         = __ec_reset_wrapper<P256>;
        return StatusOk();
    }
};

Uint32
EcBuilder::getSize(const alc_ec_info_t& rEcInfo)
{
    switch (rEcInfo.ecCurveId) {
        case ALCP_EC_CURVE25519:
            return sizeof(X25519);
            break;
        case ALCP_EC_SECP256R1:
            return sizeof(P256); // return sizeof(Sha3);
            break;
        default:
            return 0;
    }
}

Status
EcBuilder::Build(const alc_ec_info_t& rEcInfo, Context& rCtx)
{

    Status status = StatusOk();
    switch (rEcInfo.ecCurveId) {
        case ALCP_EC_CURVE25519:
            status = x25519Builder::Build(rEcInfo, rCtx);
            break;
        case ALCP_EC_SECP256R1:
            status = p256Builder::Build(rEcInfo, rCtx);
            break;
        default:
            status = Status(GenericError(ErrorCode::eNotImplemented),
                            "Curve not implemented");
            break;
    }

    return status;
}

} // namespace alcp::ec
