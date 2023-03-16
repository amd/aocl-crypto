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

#include "alcp/capi/rng/builder.hh"
#include "alcp/rng.hh"
#include "hardware_rng.hh"
#include "system_rng.hh"

namespace alcp::rng {

static alc_error_t
__read_random_wrapper(void* pRng, Uint8* buffer, int size)
{
    alc_error_t e    = ALC_ERROR_NONE;
    auto        p_ap = static_cast<IRng*>(pRng);

    // e = ap->readRandom(buffer, size);
    p_ap->randomize(buffer, size);

    return e;
}

static alc_error_t
__reseed_wrapper(void* pRng)
{
    alc_error_t e    = ALC_ERROR_NONE;
    auto        p_ap = static_cast<IRng*>(pRng);

    // e = ap->readRandom(buffer, size);
    p_ap->reseed();

    return e;
}

template<typename RNGTYPE>
static alc_error_t
__finish_wrapper(void* pRng)
{
    alc_error_t e    = ALC_ERROR_NONE;
    auto        p_ap = static_cast<RNGTYPE*>(pRng);

    // ap->finish();

    delete (p_ap);

    return e;
}

template<typename SOURCENAME>
static Status
__build_rng(const alc_rng_info_t& rRngInfo, Context& rCtx)
{
    auto p_source    = new SOURCENAME();
    rCtx.m_rng       = static_cast<void*>(p_source);
    rCtx.read_random = __read_random_wrapper;
    rCtx.reseed      = __reseed_wrapper;
    rCtx.finish      = __finish_wrapper<SOURCENAME>;

    return StatusOk();
}

#if 0
static Status
__buld_rng_class(const alc_rng_info_t& rRngInfo, void*& placed_memory)
{
    Status sts = StatusOk();
    switch (rRngInfo.ri_source) {
        case ALC_RNG_SOURCE_OS:
            new (placed_memory) SystemRng();
            break;

        case ALC_RNG_SOURCE_ARCH:
            new (placed_memory) HardwareRng();
            break;

        default:
            sts.update(InvalidArgumentError("RNG type specified is unknown"));
            break;
    }
    return sts;
}
#endif

alc_error_t
RngBuilder::Build(const alc_rng_info_t& rRngInfo, Context& rCtx)
{
    Status sts = StatusOk();
#if 0
        rCtx->rng_info.ri_distrib = rRngInfo.ri_distrib;
        rCtx->rng_info.ri_type    = rRngInfo.ri_type;
        rCtx->rng_info.ri_source  = rRngInfo.ri_source;
        rCtx->rng_info.ri_flags   = rRngInfo.ri_flags;
#endif
    switch (rRngInfo.ri_source) {
        case ALC_RNG_SOURCE_OS:
            sts.update(__build_rng<SystemRng>(rRngInfo, rCtx));
            break;
        case ALC_RNG_SOURCE_ARCH:
            sts.update(__build_rng<HardwareRng>(rRngInfo, rCtx));
            break;
        default:
            sts.update(status::NotPermitted("RNG type specified is unknown"));
            break;
    }

    return sts.code();
}

} // namespace alcp::rng
