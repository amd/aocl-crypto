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

#include "alcp/error.h"
#include "rng.hh"

namespace alcp::rng {
template<typename RNGTYPE>
static alc_error_t
__read_random_wrapper(void* pRng, uint8_t* buffer, int buffersize)
{
    int         randn = 0;  // Index location free in buffer
    int         tries = 10; // N tries before giving up
    alc_error_t e     = ALC_ERROR_NONE;
    auto        ap    = static_cast<RNGTYPE*>(pRng);
    while (randn != buffersize) {
        randn += ap->engineDefault(buffer + randn, buffersize - randn);
        tries -= 1;
        if (tries == 0) {
            e = ALC_ERROR_NO_ENTROPY;
            break;
        }
    }
    return e;
}

template<typename SOURCENAME>
static alc_error_t
__build_rng(const alc_rng_info_t* tt, rng_Handle* ctx)
{
    alc_error_t e      = ALC_ERROR_NONE;
    auto        source = new SOURCENAME();
    ctx->m_rng         = static_cast<void*>(source);
    ctx->read_random   = __read_random_wrapper<SOURCENAME>;
    // Add finish also some time later may be

    return e;
}
namespace RngBuilder {
    alc_error_t Build(const alc_rng_info_t* tt, rng_Handle* ctx)
    {
        alc_error_t e           = ALC_ERROR_NONE;
        ctx->rng_info.r_distrib = tt->r_distrib;
        ctx->rng_info.r_type    = tt->r_type;
        ctx->rng_info.r_source  = tt->r_source;
        ctx->rng_info.r_flags   = tt->r_flags;
        switch (tt->r_source) {
            case ALC_RNG_SOURCE_OS:
                __build_rng<OsRng>(tt, ctx);
                break;
            case ALC_RNG_SOURCE_ARCH:
                __build_rng<ArchRng>(tt, ctx);
                break;
            default:
                e = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
        return e;
    }
} // namespace RngBuilder
} // namespace alcp::rng