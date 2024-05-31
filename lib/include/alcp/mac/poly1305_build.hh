/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#pragma once

#include "alcp/capi/mac/builder.hh"
#include "alcp/capi/mac/ctx.hh"
#include "alcp/error.h"
#include "alcp/mac.h"
#include "poly1305.hh"
#include <type_traits> /* for is_same_v<> */

namespace alcp::mac::poly1305 {
using namespace alcp::base::status;

// FIXME: Below code looks way similar to CMAC builder, we can combine it
class Poly1305Builder
{
  public:
    static Status build(Context* ctx);
};

template<CpuArchFeature feature>
static Status
__poly1305_wrapperInit(Context*        ctx,
                       const Uint8*    key,
                       Uint64          size,
                       alc_mac_info_t* info)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(ctx->m_mac);
    return p_poly1305->init(key, size);
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperUpdate(void* poly1305, const Uint8* buff, Uint64 size)
{

    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->update(buff, size);
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperFinalize(void* poly1305, Uint8* buff, Uint64 size)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->finalize(buff, size);
}

template<CpuArchFeature feature>
static void
__poly1305_wrapperFinish(void* poly1305, void* digest)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
#if 0
    p_poly1305->~Poly1305();
#else
    delete p_poly1305;
#endif

    // Not deleting the memory because it is allocated by application
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperReset(void* poly1305)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->reset();
}

template<CpuArchFeature feature>
static Status
__poly1305_build_with_copy(Context* srcCtx, Context* destCtx)
{
    auto poly1305_algo = new Poly1305<feature>(
        *reinterpret_cast<Poly1305<feature>*>(srcCtx->m_mac));

    destCtx->m_mac = static_cast<void*>(poly1305_algo);

    destCtx->init      = srcCtx->init;
    destCtx->update    = srcCtx->update;
    destCtx->finalize  = srcCtx->finalize;
    destCtx->finish    = srcCtx->finish;
    destCtx->reset     = srcCtx->reset;
    destCtx->duplicate = srcCtx->duplicate;

    return StatusOk();
}

template<CpuArchFeature feature>
static Status
__build_poly1305_arch(Context* ctx)
{
    using namespace status;
    Status status = StatusOk();

    auto p_algo = new Poly1305<feature>();

    if (p_algo == nullptr) {
        return InternalError("Unable to Allocate Memory for CMAC Object");
    }
    ctx->m_mac = static_cast<void*>(p_algo);

    ctx->init      = __poly1305_wrapperInit<feature>;
    ctx->update    = __poly1305_wrapperUpdate<feature>;
    ctx->finalize  = __poly1305_wrapperFinalize<feature>;
    ctx->finish    = __poly1305_wrapperFinish<feature>;
    ctx->reset     = __poly1305_wrapperReset<feature>;
    ctx->duplicate = __poly1305_build_with_copy<feature>;

    return status;
}

Status
Poly1305Builder::build(Context* ctx)
{
    CpuArchFeature feature = getCpuArchFeature();
    /* In the interst of Preventing VTable overheads, Interface is not used. */
    switch (feature) {
        case CpuArchFeature::eAvx512:
            return __build_poly1305_arch<CpuArchFeature::eAvx512>(ctx);
        case CpuArchFeature::eAvx2:
            return __build_poly1305_arch<CpuArchFeature::eAvx2>(ctx);
        case CpuArchFeature::eReference:
            return __build_poly1305_arch<CpuArchFeature::eReference>(ctx);
        case CpuArchFeature::eDynamic:
            return __build_poly1305_arch<CpuArchFeature::eDynamic>(ctx);
    }
    // Should be in theory unreachable code
    return status::InternalError("Dispatch Failure");
}

} // namespace alcp::mac::poly1305