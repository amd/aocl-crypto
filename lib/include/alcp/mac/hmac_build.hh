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

#include "alcp/base.hh"
#include "alcp/capi/digest/builder.hh"
#include "alcp/capi/mac/ctx.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha512.hh"
#include "hmac.hh"

namespace alcp::mac {
using namespace status;

Status
validate_keys(const alc_key_info_t& rKeyInfo)
{

    Status status = StatusOk();

    if (rKeyInfo.len == 0) {
        return InvalidArgument("HMAC: Key Size Cannot be Zero");
    }
    if (rKeyInfo.key == nullptr) {
        return InvalidArgument("HMAC: Key cannot be NULL");
    }

    return status;
}

class HmacBuilder
{
  public:
    static Status build(const alc_mac_info_t& macInfo,
                        const alc_key_info_t& keyInfo,
                        Context&              ctx);

    static Uint64 getSize(const alc_mac_info_t& macInfo);
};

static Status
__hmac_wrapperUpdate(void* hmac, const Uint8* buff, Uint64 size)
{
    auto ap = static_cast<Hmac*>(hmac);
    return ap->update(buff, size);
}

static Status
__hmac_wrapperFinalize(void* hmac, Uint8* buff, Uint64 size)
{
    auto ap = static_cast<Hmac*>(hmac);
    return ap->finalize(buff, size);
}

template<typename DIGESTALGORITHM>
static void
__hmac_wrapperFinish(void* hmac, void* digest)
{
    auto ap       = static_cast<Hmac*>(hmac);
    auto digest_p = static_cast<DIGESTALGORITHM*>(digest);
    delete digest_p;
    delete ap;
}

static Status
__hmac_wrapperReset(void* hmac)
{
    auto ap = static_cast<Hmac*>(hmac);

    return ap->reset();
}

template<typename DIGESTALGORITHM>
static Status
__hmac_wrapperInit(void* hmac, const Uint8* key, Uint64 size, void* digest)
{
    auto hmac_algo = static_cast<Hmac*>(hmac);

    return hmac_algo->init(key, size, *reinterpret_cast<DIGESTALGORITHM*>(digest));
}

template<typename DIGESTALGORITHM>
static Status
__build_with_copy_hmac(Context& srcCtx, Context& destCtx)
{
    destCtx.m_digest = new DIGESTALGORITHM(
        *reinterpret_cast<DIGESTALGORITHM*>(srcCtx.m_digest));

    auto hmac_algo =
        new Hmac(*reinterpret_cast<Hmac*>(srcCtx.m_mac));
    destCtx.m_mac = static_cast<void*>(hmac_algo);

    destCtx.update    = srcCtx.update;
    destCtx.finalize  = srcCtx.finalize;
    destCtx.finish    = srcCtx.finish;
    destCtx.duplicate = srcCtx.duplicate;
    destCtx.reset     = srcCtx.reset;

    return StatusOk();
}

template<typename DIGESTALGORITHM>
static Status
__build_hmac(const alc_mac_info_t& macInfo, Context& ctx)
{
    Status status = StatusOk();

    status = validate_keys(macInfo.mi_keyinfo);
    if (!status.ok()) {
        return status;
    }

    auto digest = new DIGESTALGORITHM();
    if (digest == nullptr) {
        status.update(InternalError("Out of Memory"));
        return status;
    }
    ctx.m_digest = static_cast<void*>(digest);

    auto hmac_algo = new Hmac();
    if (hmac_algo == nullptr) {
        status.update(InternalError("Out of Memory"));
        return status;
    }
    ctx.m_mac = static_cast<void*>(hmac_algo);

    ctx.update    = __hmac_wrapperUpdate;
    ctx.finalize  = __hmac_wrapperFinalize;
    ctx.finish    = __hmac_wrapperFinish<DIGESTALGORITHM>;
    ctx.reset     = __hmac_wrapperReset;
    ctx.init      = __hmac_wrapperInit<DIGESTALGORITHM>;
    ctx.duplicate = __build_with_copy_hmac<DIGESTALGORITHM>;

    if (macInfo.mi_keyinfo.len % 8 != 0) {
        return InternalError("HMAC: HMAC Key should be multiple of 8");
    }

    return status;
}

Status
HmacBuilder::build(const alc_mac_info_t& macInfo,
                   const alc_key_info_t& keyInfo,
                   Context&              ctx)
{
    Status status = StatusOk();

    switch (macInfo.mi_algoinfo.hmac.digest_mode) {
        case ALC_SHA2_256: {
            status = __build_hmac<digest::Sha256>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_224: {
            status = __build_hmac<digest::Sha224>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_384: {
            status = __build_hmac<digest::Sha384>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512: {
            status = __build_hmac<digest::Sha512>(macInfo, ctx);
            break;
        }
        case ALC_SHA3_224:
            status = __build_hmac<digest::Sha3_224>(macInfo, ctx);
            break;
        case ALC_SHA3_256:
            status = __build_hmac<digest::Sha3_256>(macInfo, ctx);
            break;
        case ALC_SHA3_384:
            status = __build_hmac<digest::Sha3_384>(macInfo, ctx);
            break;
        case ALC_SHA3_512: {
            status = __build_hmac<digest::Sha3_512>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512_224: {
            status = __build_hmac<digest::Sha512_224>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512_256: {
            status = __build_hmac<digest::Sha512_256>(macInfo, ctx);
            break;
        }
        default: {
            status.update(InternalError("Digest algorithm Unknown"));
            break;
        }
    }
    return status;
}

Uint64
HmacBuilder::getSize(const alc_mac_info_t& macInfo)
{
    return sizeof(Hmac);
}
} // namespace alcp::mac
