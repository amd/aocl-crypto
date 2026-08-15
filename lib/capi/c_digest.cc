/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
#include "alcp/capi/defs.hh"
#include "alcp/capi/digest/builder.hh"
#include "alcp/capi/digest/ctx.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_digest_context_size()
{
    Uint64 size = sizeof(digest::Context);
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CtxSize %6ld", size);
#endif
    return size;
}

alc_error_t
alcp_digest_request(alc_digest_mode_t mode, alc_digest_handle_p pDigestHandle)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO, "Mode: %d", mode);
#endif
    ALCP_BAD_PTR_ERR_RET(pDigestHandle);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);

    new (ctx) digest::Context;

    return digest::DigestBuilder::Build(mode, *ctx);
}
ALCP_CATCH_ERR_RET

alc_error_t
alcp_digest_flush(const alc_digest_handle_p pDigestHandle,
                  const Uint8**             ppMsgBuf,
                  const Uint64              numBuffers,
                  const Uint64              msgLen)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(
        LOG_INFO, "numBuffers %6ld, msgLen %6ld", numBuffers, msgLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pDigestHandle);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ppMsgBuf);
    ALCP_ZERO_LEN_ERR_RET(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        ALCP_BAD_PTR_ERR_RET(ppMsgBuf[i]);
    }

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->flush);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);

    err = ctx->flush(ctx->m_digest, ppMsgBuf, numBuffers, msgLen);
    return err;
}
ALCP_CATCH_ERR_RET

alc_error_t
alcp_digest_dequeue(const alc_digest_handle_p pDigestHandle,
                    Uint8**                   ppDstBuf,
                    const Uint64              numBuffers,
                    const Uint64              digestLen)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(
        LOG_INFO, "numBuffers %6ld, digestLen %6ld", numBuffers, digestLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pDigestHandle);
    ALCP_BAD_PTR_ERR_RET(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ppDstBuf);
    ALCP_ZERO_LEN_ERR_RET(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        ALCP_BAD_PTR_ERR_RET(ppDstBuf[i]);
    }

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->dequeue);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);

    err = ctx->dequeue(ctx->m_digest, ppDstBuf, numBuffers, digestLen);
    return err;
}
ALCP_CATCH_ERR_RET

alc_error_t
alcp_digest_init(alc_digest_handle_p pDigestHandle)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pDigestHandle);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);

    return ctx->init(ctx->m_digest);
}
ALCP_CATCH_ERR_RET

alc_error_t
alcp_digest_update(const alc_digest_handle_p pDigestHandle,
                   const Uint8*              pMsgBuf,
                   Uint64                    size)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "DigestSize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pDigestHandle);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->update);
    ALCP_BAD_PTR_ERR_RET(pMsgBuf);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);

    return ctx->update(ctx->m_digest, pMsgBuf, size);
}
ALCP_CATCH_ERR_RET

alc_error_t
alcp_digest_finalize(const alc_digest_handle_p pDigestHandle,
                     Uint8*                    buf,
                     Uint64                    size)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "DigestSize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pDigestHandle);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->finalize);
    ALCP_BAD_PTR_ERR_RET(buf);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);
    return ctx->finalize(ctx->m_digest, buf, size);
}
ALCP_CATCH_ERR_RET

void
alcp_digest_finish(const alc_digest_handle_p pDigestHandle)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    if (pDigestHandle && pDigestHandle->context) {
        auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
        if (ctx->m_digest) {
            /* TODO: fix the argument */
            ctx->finish(ctx->m_digest);
        }
        ctx->~Context();
    }
}
ALCP_CATCH_IGNORE

alc_error_t
alcp_digest_shake_squeeze(const alc_digest_handle_p pDigestHandle,
                          Uint8*                    pBuff,
                          Uint64                    size)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "DigestSize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pDigestHandle);

    auto ctx = static_cast<digest::Context*>(pDigestHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx);
    ALCP_BAD_PTR_ERR_RET(ctx->shakeSqueeze);
    ALCP_BAD_PTR_ERR_RET(pBuff);
    ALCP_BAD_PTR_ERR_RET(ctx->m_digest);

    if (size == 0) {
        /* FIXME this should return zerolen error*/
        return ALC_ERROR_NONE;
    }

    if (ctx->shakeSqueeze == nullptr) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    return ctx->shakeSqueeze(ctx->m_digest, pBuff, size);
}
ALCP_CATCH_ERR_RET
alc_error_t
alcp_digest_context_copy(const alc_digest_handle_p pSrcHandle,
                         const alc_digest_handle_p pDestHandle)
try {
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pSrcHandle);
    ALCP_BAD_PTR_ERR_RET(pDestHandle);

    auto src_ctx  = static_cast<digest::Context*>(pSrcHandle->context);
    auto dest_ctx = static_cast<digest::Context*>(pDestHandle->context);
    ALCP_BAD_PTR_ERR_RET(src_ctx);
    ALCP_BAD_PTR_ERR_RET(src_ctx->duplicate);
    ALCP_BAD_PTR_ERR_RET(dest_ctx);
    ALCP_BAD_PTR_ERR_RET(src_ctx->m_digest);

    new (dest_ctx) digest::Context;

    err = digest::DigestBuilder::BuildWithCopy(*src_ctx, *dest_ctx);

    return err;
}
ALCP_CATCH_ERR_RET

EXTERN_C_END
