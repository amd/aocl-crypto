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
__rsa_encrBufWithPub_wrapper(void*        pRsaHandle,
                             const Uint8* pText,
                             Uint64       textSize,
                             Uint8*       pEncText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->encryptPublic(pText, textSize, pEncText);
}

static Status
__rsa_decrBufWithPriv_wrapper(void*        pRsaHandle,
                              const Uint8* pEncText,
                              Uint64       encSize,
                              Uint8*       pText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->decryptPrivate(pEncText, encSize, pText);
}

static Status
__rsa_oaepEncrBufWithPub_wrapper(void*        pRsaHandle,
                                 const Uint8* pText,
                                 Uint64       textSize,
                                 const Uint8* label,
                                 Uint64       labelSize,
                                 const Uint8* pSeed,
                                 Uint8*       pEncText)
{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->encryptPublicOaep(
        pText, textSize, label, labelSize, pSeed, pEncText);
}

static Status
__rsa_oaepDecrBufWithPriv_wrapper(void*        pRsaHandle,
                                  const Uint8* pEncText,
                                  Uint64       encSize,
                                  const Uint8* label,
                                  Uint64       labelSize,
                                  Uint8*       pText,
                                  Uint64&      textSize)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->decryptPrivateOaep(
        pEncText, encSize, label, labelSize, pText, textSize);
}

static Uint64
__rsa_getKeySize_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->getKeySize();
}

static Status
__rsa_getPublicKey_wrapper(void* pRsaHandle, RsaPublicKey& publicKey)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    Status status = ap->getPublickey(publicKey);
    return status;
}

static Status
__rsa_setPublicKey_wrapper(void*        pRsaHandle,
                           const Uint64 exponent,
                           const Uint8* mod,
                           const Uint64 size)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPublicKey(exponent, mod, size);
}

static Status
__rsa_setPrivateKey_wrapper(void*        pRsaHandle,
                            const Uint8* dp,
                            const Uint8* dq,
                            const Uint8* p,
                            const Uint8* q,
                            const Uint8* qinv,
                            const Uint8* mod,
                            const Uint64 size)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPrivateKey(dp, dq, p, q, qinv, mod, size);
}

static void
__rsa_setDigest_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    ap->setDigestOaep(digest);
}

static void
__rsa_setMgf_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    ap->setMgfOaep(digest);
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

    Status status             = StatusOk();
    auto   addr               = reinterpret_cast<Uint8*>(&rCtx) + sizeof(rCtx);
    auto   algo               = new (addr) Rsa();
    rCtx.m_rsa                = static_cast<void*>(algo);
    rCtx.encryptPublicFn      = __rsa_encrBufWithPub_wrapper;
    rCtx.decryptPrivateFn     = __rsa_decrBufWithPriv_wrapper;
    rCtx.encryptPublicOaepFn  = __rsa_oaepEncrBufWithPub_wrapper;
    rCtx.decryptPrivateOaepFn = __rsa_oaepDecrBufWithPriv_wrapper;
    rCtx.getKeySize           = __rsa_getKeySize_wrapper;
    rCtx.getPublickey         = __rsa_getPublicKey_wrapper;
    rCtx.setPublicKey         = __rsa_setPublicKey_wrapper;
    rCtx.setPrivateKey        = __rsa_setPrivateKey_wrapper;
    rCtx.setDigest            = __rsa_setDigest_wrapper;
    rCtx.setMgf               = __rsa_setMgf_wrapper;
    rCtx.finish               = __rsa_dtor;
    rCtx.reset                = __rsa_reset_wrapper;

    return status;
}

} // namespace alcp::rsa
