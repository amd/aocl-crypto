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

#include "rng.hh"
#include "alcp/macros.h"
#include "error.hh"
#include <iostream>
#include <stdio.h>

EXTERN_C_BEGIN uint64_t
alcp_rng_context_size(const alc_rng_info_t rng_info)
{
    uint64_t size = sizeof(alcp::rng_Handle);
    return size;
}
alc_error_t
alcp_rng_supported(const alc_rng_info_t* tt)
{
    alc_error_t error = ALC_ERROR_NOT_SUPPORTED;

    switch (tt->r_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (tt->r_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    switch (tt->r_source) {
                        case ALC_RNG_SOURCE_OS:
                            error = ALC_ERROR_NONE;
                            break;
                        case ALC_RNG_SOURCE_ARCH:
                            error = ALC_ERROR_NONE;
                            break;
                    }
            }
    }

    return error;
}

alc_error_t
alcp_rng_request(const alc_rng_info_t* tt, alc_rng_handle_t* ctx)
{
    alc_error_t error = ALC_ERROR_NOT_SUPPORTED;
    /*
     * TODO: Move this to builder, find a way to check support without redundant
     * code
     */
    switch (tt->r_type) {
        case ALC_RNG_TYPE_DESCRETE:
            switch (tt->r_distrib) {
                case ALC_RNG_DISTRIB_UNIFORM:
                    error = ALC_ERROR_NONE;
                    alcp::rng::RngBuilder::Build(
                        tt, static_cast<alcp::rng_Handle*>(ctx->context));
                    break;
            }
    }
    return error;
}

alc_error_t
alcp_rng_gen_random(alc_rng_handle_t* tt,
                    uint8_t*          buf, /* RNG output buffer */
                    uint64_t          size /* output buffer size */
)
{
    alcp::rng_Handle* cntxt = (alcp::rng_Handle*)tt->context;
    uint64_t          randn = 0;
    int               tries = 10;
    if (buf == NULL) {
        return ALC_ERROR_INVALID_ARG;
    }
    randn += cntxt->read_random(cntxt->m_rng, buf, size);
    return ALC_ERROR_NONE;
}

alc_error_t
alcp_rng_finish(alc_rng_handle_t* tt)
{
    delete ((static_cast<alcp::rng_Handle*>(tt->context))->m_rng);
    return ALC_ERROR_NONE;
}

EXTERN_C_END
