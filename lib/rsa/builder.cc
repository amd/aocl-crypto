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

#include "alcp/capi/rsa/builder.hh"
#include "alcp/capi/rsa/ctx.hh"

#include "alcp/rsa.hh"

namespace alcp::rsa {

using Context = alcp::rsa::Context;

static Status
__rsa_getEncrBufWithPub_wrapper(void*                    pRsaHandle,
                                alc_rsa_encr_dcr_padding pad,
                                const Uint8*             pPublicKey,
                                const Uint8*             pText,
                                Uint8*                   pEncText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->getEncrBufWithPub(pad, pPublicKey, pText, pEncText);
}

static Status
__rsa_getDecrBufWithPriv_wrapper(void*                    pRsaHandle,
                                 alc_rsa_encr_dcr_padding pad,
                                 const Uint8*             pEncText,
                                 Uint8*                   pText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->getDecrBufWithPriv(pad, pEncText, pText);
}

static Status
__rsa_dtor(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    // FIXME: Not a good idea!
    ap->~Rsa();
    return StatusOk();
}

static Status
__rsa_reset_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    // FIXME: Not a good idea!
    ap->reset();
    return StatusOk();
}

Uint32
RsaBuilder::getSize()
{
    return sizeof(Rsa);
}

Status
RsaBuilder::Build(Context& rCtx)
{

    Status status           = StatusOk();
    auto   addr             = reinterpret_cast<Uint8*>(&rCtx) + sizeof(rCtx);
    auto   algo             = new (addr) Rsa();
    rCtx.m_rsa              = static_cast<void*>(algo);
    rCtx.getEncrBufWithPub  = __rsa_getEncrBufWithPub_wrapper;
    rCtx.getDecrBufWithPriv = __rsa_getDecrBufWithPriv_wrapper;
    rCtx.finish             = __rsa_dtor;
    rCtx.reset              = __rsa_reset_wrapper;

    return status;
}

} // namespace alcp::rsa
