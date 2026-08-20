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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/base.hh"
#include "alcp/base/error.hh"
#include "alcp/capi/defs.hh"
#include "alcp/capi/mac/builder.hh"
#include "alcp/capi/mac/ctx.hh"
#include "alcp/mac.h"
#include "alcp/mac/mac.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_mac_context_size(void)
{
    Uint64 size = sizeof(mac::Context);
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CtxSize %6ld", size);
#endif
    return size;
}

alc_error_t
alcp_mac_request(alc_mac_handle_p pMacHandle, alc_mac_type_t mi_type)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    new (p_ctx) mac::Context;
    return mac::MacBuilder::build(mi_type, p_ctx);
}

alc_error_t
alcp_mac_update(alc_mac_handle_p pMacHandle, const Uint8* buff, Uint64 size)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "MacSize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->update);

    return p_ctx->update(p_ctx->m_mac, buff, size);
}

alc_error_t
alcp_mac_finalize(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "MacSize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->finalize);

    return p_ctx->finalize(p_ctx->m_mac, buff, size);
}

alc_error_t
alcp_mac_finish(alc_mac_handle_p pMacHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->finish);
    p_ctx->finish(p_ctx->m_mac, p_ctx->m_digest);
    p_ctx->~Context();
    // FIXME: This function is always returning no errors
    return ALC_ERROR_NONE;
}

alc_error_t
alcp_mac_reset(alc_mac_handle_p pMacHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->reset);

    return p_ctx->reset(p_ctx->m_mac);
}

alc_error_t
alcp_mac_init(alc_mac_handle_p pMacHandle,
              const Uint8*     key,
              Uint64           size,
              alc_mac_info_t*  info)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeySize %6ld", size);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(key);

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->init);
    return p_ctx->init(p_ctx, key, size, info);
}

alc_error_t
alcp_mac_context_copy(const alc_mac_handle_p pSrcHandle,
                      const alc_mac_handle_p pDestHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pSrcHandle);
    ALCP_BAD_PTR_ERR_RET(pDestHandle);

    auto src_ctx  = static_cast<mac::Context*>(pSrcHandle->ch_context);
    auto dest_ctx = static_cast<mac::Context*>(pDestHandle->ch_context);

    ALCP_BAD_PTR_ERR_RET(src_ctx);
    ALCP_BAD_PTR_ERR_RET(dest_ctx);

    new (dest_ctx) mac::Context;

    return mac::MacBuilder::BuildWithCopy(src_ctx, dest_ctx);
}

alc_error_t
alcp_mac_flush(alc_mac_handle_p pMacHandle,
               const Uint8**    ppMsgBuf,
               Uint64           numBuffers,
               Uint64           msgLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "NumBuffers %6ld, MsgLen %6ld", numBuffers, msgLen);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ppMsgBuf);
    ALCP_ZERO_LEN_ERR_RET(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        ALCP_BAD_PTR_ERR_RET(ppMsgBuf[i]);
    }

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->flush);

    return p_ctx->flush(p_ctx->m_mac, ppMsgBuf, numBuffers, msgLen);
}

alc_error_t
alcp_mac_dequeue(alc_mac_handle_p pMacHandle,
                 Uint8**          ppDstBuf,
                 Uint64           numBuffers)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "NumBuffers %6ld", numBuffers);
#endif
    ALCP_BAD_PTR_ERR_RET(pMacHandle);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ppDstBuf);
    ALCP_ZERO_LEN_ERR_RET(numBuffers);
    for (Uint64 i = 0; i < numBuffers; i++) {
        ALCP_BAD_PTR_ERR_RET(ppDstBuf[i]);
    }

    auto p_ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(p_ctx->dequeue);

    return p_ctx->dequeue(p_ctx->m_mac, ppDstBuf, numBuffers);
}

EXTERN_C_END