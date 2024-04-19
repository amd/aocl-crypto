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

    // For RAW assignments
    switch (rKeyInfo.fmt) {
        case ALC_KEY_FMT_RAW:
            if (rKeyInfo.len == 0) {
                return InvalidArgument("HMAC: Key Size Cannot be Zero");
            }
            if (rKeyInfo.key == nullptr) {
                return InvalidArgument("HMAC: Key cannot be NULL");
            }
            break;
        case ALC_KEY_FMT_BASE64:
            // TODO: For base64 conversions
            return InvalidArgument("HMAC: Base64 Key Format not supported yet");
            break;
        // TODO: Subsequest switch cases for other formats
        default:
            return InvalidArgument("HMAC: Key Format not supported ");
            break;
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

    static Status isSupported(const alc_mac_info_t& macInfo);
};

template<typename MACALGORITHM>
static Status
__hmac_wrapperUpdate(void* hmac, const Uint8* buff, Uint64 size)
{

    auto ap = static_cast<MACALGORITHM*>(hmac);
    return ap->update(buff, size);
}

template<typename MACALGORITHM>
static Status
__hmac_wrapperFinalize(void* hmac, const Uint8* buff, Uint64 size)
{
    auto ap = static_cast<MACALGORITHM*>(hmac);
    return ap->finalize(buff, size);
}

template<typename MACALGORITHM>
static Status
__hmac_wrapperCopy(void* hmac, Uint8* buff, Uint64 size)
{
    auto ap = static_cast<MACALGORITHM*>(hmac);
    return ap->copyHash(buff, size);
}

template<typename MACALGORITHM, typename DIGESTALGORITHM>
static void
__hmac_wrapperFinish(void* hmac, void* digest)
{
    auto ap       = static_cast<MACALGORITHM*>(hmac);
    auto digest_p = static_cast<DIGESTALGORITHM*>(digest);
    ap->finish();
    delete digest_p;
    ap->~MACALGORITHM();
}

template<typename MACALGORITHM, typename DIGESTALGORITHM>
static Status
__hmac_wrapperReset(void* hmac, void* digest)
{
    auto ap = static_cast<MACALGORITHM*>(hmac);

    return ap->reset();
}
template<typename DIGESTALGORITHM, typename MACALGORITHM>
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

    auto addr      = reinterpret_cast<Uint8*>(&ctx) + sizeof(ctx);
    auto hmac_algo = new (addr) MACALGORITHM();
    if (hmac_algo == nullptr) {
        status.update(InternalError("Out of Memory"));
        return status;
    }
    ctx.m_mac = static_cast<void*>(hmac_algo);

    ctx.update   = __hmac_wrapperUpdate<MACALGORITHM>;
    ctx.finalize = __hmac_wrapperFinalize<MACALGORITHM>;
    ctx.copy     = __hmac_wrapperCopy<MACALGORITHM>;
    ctx.finish   = __hmac_wrapperFinish<MACALGORITHM, DIGESTALGORITHM>;
    ctx.reset    = __hmac_wrapperReset<MACALGORITHM, DIGESTALGORITHM>;

    if (macInfo.mi_keyinfo.len % 8 != 0) {
        return InternalError("HMAC: HMAC Key should be multiple of 8");
    }

    status = hmac_algo->setDigest(*digest);
    if (!status.ok()) {
        return status;
    }
    auto p_key  = macInfo.mi_keyinfo.key;
    auto keylen = macInfo.mi_keyinfo.len / 8;
    status      = hmac_algo->setKey(p_key, keylen);
    if (!status.ok()) {
        return status;
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
            status = __build_hmac<digest::Sha256, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_224: {
            status = __build_hmac<digest::Sha224, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_384: {
            status = __build_hmac<digest::Sha384, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512: {
            status = __build_hmac<digest::Sha512, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA3_224:
            status = __build_hmac<digest::Sha3_224, Hmac>(macInfo, ctx);
            break;
        case ALC_SHA3_256:
            status = __build_hmac<digest::Sha3_256, Hmac>(macInfo, ctx);
            break;
        case ALC_SHA3_384:
            status = __build_hmac<digest::Sha3_384, Hmac>(macInfo, ctx);
            break;
        case ALC_SHA3_512: {
            status = __build_hmac<digest::Sha3_512, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512_224: {
            status = __build_hmac<digest::Sha512_224, Hmac>(macInfo, ctx);
            break;
        }
        case ALC_SHA2_512_256: {
            status = __build_hmac<digest::Sha512_256, Hmac>(macInfo, ctx);
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

Status
isDigestSupported(alc_digest_mode_t mode)
{
    Status status{ StatusOk() };
    switch (mode) {
        case ALC_SHA2_256: {
            break;
        }
        case ALC_SHA2_224: {
            break;
        }
        case ALC_SHA2_384: {
            break;
        }
        case ALC_SHA2_512: {
            break;
        }
        case ALC_SHA2_512_224: {
            break;
        }
        case ALC_SHA2_512_256: {
            break;
        }
        case ALC_SHA3_224: {
            break;
        }
        case ALC_SHA3_256: {
            break;
        }
        case ALC_SHA3_384: {
            break;
        }
        case ALC_SHA3_512: {
            break;
        }
        default: {
            status.update(InvalidArgument("Digest algorithm Unknown"));
            break;
        }
    }
    return status;
}

Status
HmacBuilder::isSupported(const alc_mac_info_t& macInfo)
{
    return isDigestSupported(macInfo.mi_algoinfo.hmac.digest_mode);
}

} // namespace alcp::mac
