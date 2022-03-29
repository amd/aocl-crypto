/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "capi/rng/builder.hh"
#include "rng.hh"

#include "error.hh"

EXTERN_C_BEGIN

uint64_t
alcp_rng_context_size(const alc_rng_info_p pRngInfo)
{
    uint64_t size = sizeof(alcp::rng::Context);
    return size;
}

alc_error_t
alcp_rng_supported(const alc_rng_info_p pRngInfo)
{
    alc_error_t error = ALC_ERROR_NONE;

    switch (pRngInfo->ri_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (pRngInfo->ri_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    switch (pRngInfo->ri_source) {
                        case ALC_RNG_SOURCE_OS:
                            break;
                        case ALC_RNG_SOURCE_ARCH:
                            break;
                        default:
                            error = ALC_ERROR_NOT_SUPPORTED;
                            break;
                    }
                    break;
                default:
                    error = ALC_ERROR_NOT_SUPPORTED;
                    break;
            }
            break;
        default:
            error = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return error;
}

alc_error_t
alcp_rng_request(const alc_rng_info_p pRngInfo, alc_rng_handle_p pHandle)
{
    alc_error_t error = ALC_ERROR_NOT_SUPPORTED;
    /*
     * TODO: Move this to builder, find a way to check support without redundant
     * code
     */
    switch (pRngInfo->ri_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (pRngInfo->ri_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM: {
                    auto ctx =
                        static_cast<alcp::rng::Context*>(pHandle->rh_context);
                    error = alcp::rng::RngBuilder::Build(*pRngInfo, *ctx);
                    break;
                }
                default:
                    error = ALC_ERROR_NOT_SUPPORTED;
                    break;
            }
            break;
        default:
            error = ALC_ERROR_NOT_SUPPORTED;
            break;
    }
    return error;
}

alc_error_t
alcp_rng_gen_random(alc_rng_handle_p pRngHandle,
                    uint8_t*         buf, /* RNG output buffer */
                    uint64_t         size /* output buffer size */
)
{
    if (buf == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    alcp::rng::Context* ctx = (alcp::rng::Context*)pRngHandle->rh_context;

    return ctx->read_random(ctx->m_rng, buf, size);
}

alc_error_t
alcp_rng_finish(alc_rng_handle_p pRngHandle)
{
    alcp::rng::Context* ctx = (alcp::rng::Context*)pRngHandle->rh_context;

    ctx->finish(ctx->m_rng);

    return ALC_ERROR_NONE;
}

EXTERN_C_END
