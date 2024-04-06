/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest.h"

#include "alcp/alcp.hh"
#include "alcp/capi/digest/builder.hh"
#include "alcp/capi/digest/ctx.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_digest_context_size()
{
    Uint64 size = sizeof(digest::Context);
    return size;
}

alc_error_t
alcp_digest_request(alc_digest_mode_t mode, alc_digest_handle_p pDigestHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    new (ctx) digest::Context;

    err = digest::DigestBuilder::Build(mode, *ctx);

    return err;
}

alc_error_t
alcp_digest_init(alc_digest_handle_p pDigestHandle)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    // FIMXE: Change update to return Status and assign it to ctx->status
    err = ctx->init(ctx->m_digest);
    return err;
}

alc_error_t
alcp_digest_update(const alc_digest_handle_p pDigestHandle,
                   const Uint8*              pMsgBuf,
                   Uint64                    size)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pMsgBuf, err);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    // FIMXE: Change update to return Status and assign it to ctx->status
    err = ctx->update(ctx->m_digest, pMsgBuf, size);

    return err;
}

alc_error_t
alcp_digest_finalize(const alc_digest_handle_p pDigestHandle,
                     const Uint8*              pMsgBuf,
                     Uint64                    size)
{
    alc_error_t err;

    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    // FIMXE: Modify finalize to return Status and assign it to ctx->status
    err = ctx->finalize(ctx->m_digest, pMsgBuf, size);

    return err;
}

void
alcp_digest_finish(const alc_digest_handle_p pDigestHandle)
{
    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    /* TODO: fix the argument */
    ctx->finish(ctx->m_digest);

    ctx->~Context();
}

alc_error_t
alcp_digest_copy(const alc_digest_handle_p pDigestHandle,
                 Uint8*                    pBuf,
                 Uint64                    size)
{
    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    // FIMXE: Modify copy to return Status and assign it to ctx->status
    return ctx->copy(ctx->m_digest, pBuf, size);
}

alc_error_t
alcp_digest_error(alc_digest_handle_p pDigestHandle, Uint8* pBuff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);

    auto p_ctx = static_cast<digest::Context*>(pDigestHandle->context);

    String message = String(p_ctx->status.message());

    int size_to_copy = size > message.size() ? message.size() : size;
    snprintf((char*)pBuff, size_to_copy, "%s", message.c_str());

    return err;
}

alc_error_t
alcp_digest_set_shake_length(const alc_digest_handle_p pDigestHandle,
                             Uint64                    digestSize)

{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    if (ctx->setShakeLength == nullptr) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    ctx->setShakeLength(ctx->m_digest, digestSize);

    return err;
}

alc_error_t
alcp_digest_shake_squeeze(const alc_digest_handle_p pDigestHandle,
                          Uint8*                    pBuff,
                          Uint64                    size)

{
    ALCP_BAD_PTR_ERR_RET(pDigestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pBuff, err);

    if (size == 0) {
        return ALC_ERROR_NONE;
    }

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    if (ctx->shakeSqueeze == nullptr) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    return ctx->shakeSqueeze(ctx->m_digest, pBuff, size);
}
alc_error_t
alcp_digest_context_copy(const alc_digest_handle_p pSrcHandle,
                         const alc_digest_handle_p pDestHandle)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pSrcHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDestHandle, err);
    ALCP_BAD_PTR_ERR_RET(pSrcHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pDestHandle->context, err);

    auto src_ctx  = static_cast<digest::Context*>(pSrcHandle->context);
    auto dest_ctx = static_cast<digest::Context*>(pDestHandle->context);

    new (dest_ctx) digest::Context;

    err = digest::DigestBuilder::BuildWithCopy(*src_ctx, *dest_ctx);

    return err;
}

EXTERN_C_END
