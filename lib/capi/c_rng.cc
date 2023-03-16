/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"

#include "alcp/capi/defs.hh"
#include "alcp/capi/rng/builder.hh"
#include "alcp/rng.hh"
#include "alcp/utils/cpuid.hh"

EXTERN_C_BEGIN

using namespace alcp::utils;

Uint64
alcp_rng_context_size(const alc_rng_info_p pRngInfo)
{
    Uint64 size = sizeof(alcp::rng::Context);
    return size;
}

alc_error_t
alcp_rng_supported(const alc_rng_info_p pRngInfo)
{
    alc_error_t error = ALC_ERROR_NONE;

    bool rd_rand_available = CpuId::cpuHasRdRand();
    bool rd_seed_available = CpuId::cpuHasRdSeed();

    switch (pRngInfo->ri_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (pRngInfo->ri_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    switch (pRngInfo->ri_source) {
                        case ALC_RNG_SOURCE_OS:
                            break;
                        case ALC_RNG_SOURCE_ARCH:
                            if (rd_rand_available && rd_seed_available) {
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
                    Uint8*           buf, /* RNG output buffer */
                    Uint64           size /* output buffer size */
)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (size == 0) {
        return err;
    }

    ALCP_BAD_PTR_ERR_RET(buf, err);

    alcp::rng::Context* ctx = (alcp::rng::Context*)pRngHandle->rh_context;

    return ctx->read_random(ctx->m_rng, buf, size);
}

alc_error_t
alcp_rng_reseed(alc_rng_handle_p pRngHandle)
{

    alcp::rng::Context* ctx = (alcp::rng::Context*)pRngHandle->rh_context;

    return ctx->reseed(ctx->m_rng);
}

alc_error_t
alcp_rng_finish(alc_rng_handle_p pRngHandle)
{
    alcp::rng::Context* ctx = (alcp::rng::Context*)pRngHandle->rh_context;

    ctx->finish(ctx->m_rng);

    return ALC_ERROR_NONE;
}

EXTERN_C_END
