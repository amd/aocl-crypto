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
#include "alcp/rsa/rsaerror.hh"

namespace alcp::rsa {

using Context = alcp::rsa::Context;

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_encrBufWithPub_wrapper(void*        pRsaHandle,
                             const Uint8* pText,
                             Uint64       textSize,
                             Uint8*       pEncText)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    return ap->encryptPublic(pText, textSize, pEncText);
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_decrBufWithPriv_wrapper(void*        pRsaHandle,
                              const Uint8* pEncText,
                              Uint64       encSize,
                              Uint8*       pText)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    return ap->decryptPrivate(pEncText, encSize, pText);
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_oaepEncrBufWithPub_wrapper(void*        pRsaHandle,
                                 const Uint8* pText,
                                 Uint64       textSize,
                                 const Uint8* label,
                                 Uint64       labelSize,
                                 const Uint8* pSeed,
                                 Uint8*       pEncText)
{

    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    return ap->encryptPublicOaep(
        pText, textSize, label, labelSize, pSeed, pEncText);
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_oaepDecrBufWithPriv_wrapper(void*        pRsaHandle,
                                  const Uint8* pEncText,
                                  Uint64       encSize,
                                  const Uint8* label,
                                  Uint64       labelSize,
                                  Uint8*       pText,
                                  Uint64&      textSize)

{

    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    return ap->decryptPrivateOaep(
        pEncText, encSize, label, labelSize, pText, textSize);
}

template<alc_rsa_key_size KEYSIZE>
static Uint64
__rsa_getKeySize_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    return ap->getKeySize();
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_getPublicKey_wrapper(void* pRsaHandle, RsaPublicKey& publicKey)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    Status status = ap->getPublickey(publicKey);
    return status;
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_setPublicKey_wrapper(void*        pRsaHandle,
                           const Uint64 exponent,
                           const Uint8* mod,
                           const Uint64 size)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    return ap->setPublicKey(exponent, mod, size);
}

template<alc_rsa_key_size KEYSIZE>
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
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    return ap->setPrivateKey(dp, dq, p, q, qinv, mod, size);
}

template<alc_rsa_key_size KEYSIZE>
static void
__rsa_setDigest_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    ap->setDigestOaep(digest);
}

template<alc_rsa_key_size KEYSIZE>
static void
__rsa_setMgf_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);

    ap->setMgfOaep(digest);
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_dtor(void* pRsaHandle)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    // FIXME: Not a good idea!
    ap->~Rsa();
    return StatusOk();
}

template<alc_rsa_key_size KEYSIZE>
static Status
__rsa_reset_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa<KEYSIZE>*>(pRsaHandle);
    // FIXME: Not a good idea!
    ap->reset();
    return StatusOk();
}

template<alc_rsa_key_size KEYSIZE>
static Status
__build_rsa(Context& ctx)
{
    auto addr = reinterpret_cast<Uint8*>(&ctx) + sizeof(ctx);
    auto algo = new (addr) Rsa<KEYSIZE>;

    ctx.m_rsa                = static_cast<void*>(algo);
    ctx.encryptPublicFn      = __rsa_encrBufWithPub_wrapper<KEYSIZE>;
    ctx.decryptPrivateFn     = __rsa_decrBufWithPriv_wrapper<KEYSIZE>;
    ctx.encryptPublicOaepFn  = __rsa_oaepEncrBufWithPub_wrapper<KEYSIZE>;
    ctx.decryptPrivateOaepFn = __rsa_oaepDecrBufWithPriv_wrapper<KEYSIZE>;
    ctx.getKeySize           = __rsa_getKeySize_wrapper<KEYSIZE>;
    ctx.getPublickey         = __rsa_getPublicKey_wrapper<KEYSIZE>;
    ctx.setPublicKey         = __rsa_setPublicKey_wrapper<KEYSIZE>;
    ctx.setPrivateKey        = __rsa_setPrivateKey_wrapper<KEYSIZE>;
    ctx.setDigest            = __rsa_setDigest_wrapper<KEYSIZE>;
    ctx.setMgf               = __rsa_setMgf_wrapper<KEYSIZE>;
    ctx.finish               = __rsa_dtor<KEYSIZE>;
    ctx.reset                = __rsa_reset_wrapper<KEYSIZE>;

    return StatusOk();
}

Uint32
RsaBuilder::getSize(const alc_rsa_key_size keySize)
{
    switch (keySize) {
        case KEY_SIZE_1024:
            return sizeof(Rsa<KEY_SIZE_1024>);
        case KEY_SIZE_2048:
            return sizeof(Rsa<KEY_SIZE_2048>);
        default:
            return 0;
    }
}

Status
RsaBuilder::Build(const alc_rsa_key_size keySize, Context& rCtx)
{

    Status status = StatusOk();

    switch (keySize) {
        case KEY_SIZE_1024:
            return __build_rsa<KEY_SIZE_1024>(rCtx);
            // rCtx.m_rsa = new (addr) Rsa<1024>;
        case KEY_SIZE_2048:
            return __build_rsa<KEY_SIZE_2048>(rCtx);
            // rCtx.m_rsa = new (addr) Rsa<2048>;
        default:
            return alcp::rsa::status::NotPermitted("Key size not supported");
    }

    return status;
}

} // namespace alcp::rsa
