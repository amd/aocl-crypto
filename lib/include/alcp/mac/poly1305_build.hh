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
    static Status build(const alc_mac_info_t& macInfo,
                        const alc_key_info_t& keyInfo,
                        Context&              ctx);
    static Uint64 getSize(const alc_mac_info_t& macInfo);
    static Status isSupported(const alc_mac_info_t& macInfo);
};

template<CpuArchFeature feature>
static Status
__poly1305_wrapperUpdate(void* poly1305, const Uint8* buff, Uint64 size)
{

    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->update(buff, size);
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperFinalize(void* poly1305, const Uint8* buff, Uint64 size)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->finalize(buff, size);
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperCopy(void* poly1305, Uint8* buff, Uint64 size)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->copy(buff, size);
}

template<CpuArchFeature feature>
static void
__poly1305_wrapperFinish(void* poly1305, void* digest)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    p_poly1305->finish();
#if 0
    p_poly1305->~Poly1305();
#else
    delete p_poly1305;
#endif

    // Not deleting the memory because it is allocated by application
}

template<CpuArchFeature feature>
static Status
__poly1305_wrapperReset(void* poly1305, void* digest)
{
    auto p_poly1305 = static_cast<Poly1305<feature>*>(poly1305);
    return p_poly1305->reset();
}

template<CpuArchFeature feature>
static Status
__build_poly1305_arch(const alc_key_info_t& cKinfo, Context& ctx)
{
    using namespace status;
    Status status = StatusOk();
#if 0
    auto   addr   = reinterpret_cast<Uint8*>(&ctx) + sizeof(ctx);
    auto   p_algo = new (addr) Poly1305();
#else
    auto p_algo = new Poly1305<feature>();
#endif

    auto p_key = cKinfo.key;
    auto len   = cKinfo.len;
    p_algo->setKey(p_key, len);
    if (p_algo == nullptr) {
        return InternalError("Unable to Allocate Memory for CMAC Object");
    }
    ctx.m_mac = static_cast<void*>(p_algo);

    ctx.update   = __poly1305_wrapperUpdate<feature>;
    ctx.finalize = __poly1305_wrapperFinalize<feature>;
    ctx.copy     = __poly1305_wrapperCopy<feature>;
    ctx.finish   = __poly1305_wrapperFinish<feature>;
    ctx.reset    = __poly1305_wrapperReset<feature>;

    return status;
}

static Status
__build_poly1305(const alc_key_info_t& cKinfo, Context& ctx)
{
    using namespace status;
    CpuArchFeature feature = getCpuArchFeature();
    /* In the interst of Preventing VTable overheads, Interface is not used. */
    switch (feature) {
        case CpuArchFeature::eAvx512:
            return __build_poly1305_arch<CpuArchFeature::eAvx512>(cKinfo, ctx);
        case CpuArchFeature::eAvx2:
            return __build_poly1305_arch<CpuArchFeature::eAvx2>(cKinfo, ctx);
        case CpuArchFeature::eReference:
            return __build_poly1305_arch<CpuArchFeature::eReference>(cKinfo,
                                                                     ctx);
        case CpuArchFeature::eDynamic:
            return __build_poly1305_arch<CpuArchFeature::eDynamic>(cKinfo, ctx);
    }
    // Should be in theory unreachable code
    return status::InternalError("Dispatch Failure");
}

Status
Poly1305Builder::build(const alc_mac_info_t& macInfo,
                       const alc_key_info_t& keyInfo,
                       Context&              ctx)
{
    return __build_poly1305(keyInfo, ctx);
}

Uint64
Poly1305Builder::getSize(const alc_mac_info_t& macInfo)
{
    CpuArchFeature feature = getCpuArchFeature();
    /* In the interst of Preventing VTable overheads, Interface is not used. */
    switch (feature) {
        case CpuArchFeature::eAvx512:
            return sizeof(Poly1305<CpuArchFeature::eAvx512>);
        case CpuArchFeature::eAvx2:
            return sizeof(Poly1305<CpuArchFeature::eAvx2>);
        case CpuArchFeature::eReference:
            return sizeof(Poly1305<CpuArchFeature::eReference>);
        case CpuArchFeature::eDynamic:
            return sizeof(Poly1305<CpuArchFeature::eDynamic>);
    }
    return 0; // Should never reach here, ideally..
}

Status
Poly1305Builder::isSupported(const alc_mac_info_t& macInfo)
{
    Status status{ StatusOk() };
    if (macInfo.mi_keyinfo.len != 256) {
        status.update(InvalidArgument("Invalid Key Size."));
    }
    return status;
}
} // namespace alcp::mac::poly1305