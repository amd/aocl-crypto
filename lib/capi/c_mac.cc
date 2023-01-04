/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base/error.hh"
#include "alcp/capi/defs.hh"
#include "alcp/mac.h"
#include "capi/mac/builder.hh"
#include "capi/mac/ctx.hh"
#include "mac/mac.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_mac_context_size(const alc_mac_info_p pMacInfo)
{
    Uint64 size = sizeof(mac::Context);
    return size;
}

alc_error_t
alcp_mac_request(alc_mac_handle_p pMacHandle, const alc_mac_info_p pMacInfo)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pMacHandle, err);
    ALCP_BAD_PTR_ERR_RET(pMacInfo, err);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context, err);

    auto ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    err      = mac::MacBuilder::Build(*pMacInfo, *ctx);

    return err;
}

alc_error_t
alcp_mac_update(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pMacHandle, err);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context, err);

    auto ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    err      = ctx->update(ctx->m_mac, buff, size);

    return err;
}

alc_error_t
alcp_mac_finalize(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pMacHandle, err);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context, err);

    auto ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    err      = ctx->finalize(ctx->m_mac, buff, size);

    return err;
}

alc_error_t
alcp_mac_copy(alc_mac_handle_p pMacHandle, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pMacHandle, err);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(buff, err);

    auto ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    err      = ctx->copy(ctx->m_mac, buff, size);

    return err;
}

alc_error_t
alcp_mac_finish(alc_mac_handle_p pMacHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pMacHandle, err);
    ALCP_BAD_PTR_ERR_RET(pMacHandle->ch_context, err);

    auto ctx = static_cast<mac::Context*>(pMacHandle->ch_context);
    ctx->finish(ctx->m_mac, ctx->m_digest);

    return err;
}

EXTERN_C_END