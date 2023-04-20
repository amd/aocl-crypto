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

#include "alcp/alcp.hh"
#include "alcp/capi/defs.hh"
#include "alcp/capi/rsa/builder.hh"
#include "alcp/capi/rsa/ctx.hh"

#include "alcp/rsa.h"
#include "alcp/rsa/rsaerror.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_rsa_context_size()
{
    Uint64 size = sizeof(rsa::Context) + rsa::RsaBuilder::getSize();
    return size;
}

alc_error_t
alcp_rsa_supported()
{
    alc_error_t err = ALC_ERROR_NOT_SUPPORTED;

    return err;
}

alc_error_t
alcp_rsa_request(alc_rsa_handle_p pRsaHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    Status status = rsa::RsaBuilder::Build(*ctx);

    return status.ok() ? err : ALC_ERROR_GENERIC;
}

alc_error_t
alcp_rsa_publickey_encrypt(const alc_rsa_handle_p pRsaHandle,
                           alc_rsa_padding        pad,
                           const Uint8*           pPublicKeyMod,
                           Uint64                 pPublicKeyModSize,
                           Uint64                 publicKeyExp,
                           const Uint8*           pText,
                           Uint64                 textSize,
                           Uint8*                 pEncText)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pPublicKeyMod, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    // Todo : Remove the const cast.
    // This is needed to pack the const variable in a const structure
    const rsa::RsaPublicKey pub_key = { publicKeyExp,
                                        const_cast<Uint8*>(pPublicKeyMod),
                                        pPublicKeyModSize };

    Status status = ctx->encryptPublicFn(
        ctx->m_rsa, pad, pub_key, pText, textSize, pEncText);

    if (status.ok()) {
        return err;
    } else {
        // fetching the module error
        Uint16 module_error = (status.code() >> 16) & 0xff;
        return (alcp::rsa::ErrorCode::eNotPermitted == module_error)
                   ? ALC_ERROR_NOT_PERMITTED
                   : ALC_ERROR_GENERIC;
    }
}

alc_error_t
alcp_rsa_privatekey_decrypt(const alc_rsa_handle_p pRsaHandle,
                            alc_rsa_padding        pad,
                            const Uint8*           pEncText,
                            Uint64                 encSize,
                            Uint8*                 pText)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    Status status =
        ctx->decryptPrivateFn(ctx->m_rsa, pad, pEncText, encSize, pText);

    return status.ok() ? err : ALC_ERROR_GENERIC;
}

Uint64
alcp_rsa_get_key_size(const alc_rsa_handle_p pRsaHandle)
{
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    return ctx->getKeySize(ctx->m_rsa);
}

alc_error_t
alcp_rsa_get_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64*                publicKey,
                       Uint8*                 pModulus,
                       Uint64                 keySize)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pModulus, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    rsa::RsaPublicKey pub_key;
    pub_key.modulus = pModulus;
    pub_key.size    = keySize;

    Status status = ctx->getPublickey(ctx->m_rsa, pub_key);

    *publicKey = pub_key.public_exponent;

    return status.ok() ? err : ALC_ERROR_GENERIC;
}

void
alcp_rsa_finish(const alc_rsa_handle_p pRsaHandle)
{
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ctx->finish(ctx->m_rsa);
}

void
alcp_rsa_reset(const alc_rsa_handle_p pRsaHandle)
{
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ctx->reset(ctx->m_rsa);
}

EXTERN_C_END
