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
#include "alcp/capi/drbg/builder.hh"
#include "alcp/capi/drbg/ctx.hh"

#include "alcp/drbg.h"
#include "alcp/rng/drbg.hh"

EXTERN_C_BEGIN
using namespace alcp;

namespace alcp::drbg {

Uint64
alcp_drbg_context_size(const alc_drbg_info_p pDrbgInfo)
{
    printf("Executing Context Size API\n");

    Uint64 size = sizeof(Context) + DrbgBuilder::getSize(*pDrbgInfo);
    return size;
}

alc_error_t
alcp_drbg_supported(const alc_drbg_info_p pcDrbgInfo)
{
    printf("Executing DRBG Supported API\n");
    return ALC_ERROR_NONE;
}

alc_error_t
alcp_drbg_request(alc_drbg_handle_p     pDrbgHandle,
                  const alc_drbg_info_p pDrbgInfo)
{
    printf("Executing alcp drbg request\n");

    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pDrbgHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDrbgInfo, err);
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle->ch_context, err);

    auto p_ctx = static_cast<drbg::Context*>(pDrbgHandle->ch_context);
    new (p_ctx) drbg::Context;
    p_ctx->status = drbg::DrbgBuilder::build(*pDrbgInfo, *p_ctx);
    return err;
}

alc_error_t
alcp_drbg_initialize(alc_drbg_handle_p pDrbgHandle,
                     int               cSecurityStrength,
                     Uint8*            personalization_string,
                     Uint64            personalization_string_length)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle->ch_context, err);

    auto p_ctx = static_cast<drbg::Context*>(pDrbgHandle->ch_context);

    p_ctx->status = p_ctx->initialize(p_ctx->m_drbg,
                                      cSecurityStrength,
                                      personalization_string,
                                      personalization_string_length);
    // TODO: Convert status to proper alc_error_t code and return
    if (!p_ctx->status.ok()) {
        err = ALC_ERROR_EXISTS;
    } else {
        err = ALC_ERROR_NONE;
    }
    return err;
}

alc_error_t
alcp_drbg_randomize(alc_drbg_handle_p pDrbgHandle,
                    Uint8             p_Output[],
                    const size_t      cOutputLength,
                    int               cSecurityStrength,
                    const Uint8       cAdditionalInput[],
                    const size_t      cAdditionalInputLength)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(p_Output, err);

    auto p_ctx = static_cast<drbg::Context*>(pDrbgHandle->ch_context);

    p_ctx->status = p_ctx->randomize(p_ctx->m_drbg,
                                     p_Output,
                                     cOutputLength,
                                     cSecurityStrength,
                                     cAdditionalInput,
                                     cAdditionalInputLength);
    // TODO: Convert status to proper alc_error_t code and return
    if (!p_ctx->status.ok()) {
        err = ALC_ERROR_EXISTS;
    } else {
        err = ALC_ERROR_NONE;
    }
    return err;
}

alc_error_t
alcp_drbg_finish(alc_drbg_handle_p pDrbgHandle)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDrbgHandle->ch_context, err);

    auto p_ctx = static_cast<drbg::Context*>(pDrbgHandle->ch_context);

    p_ctx->status = p_ctx->finish(p_ctx->m_drbg);
    // TODO: Convert status to proper alc_error_t code and return
    if (!p_ctx->status.ok()) {
        err = ALC_ERROR_EXISTS;
    } else {
        err = ALC_ERROR_NONE;
    }
    p_ctx->~Context();
    return err;
}
} // namespace alcp::drbg
EXTERN_C_END