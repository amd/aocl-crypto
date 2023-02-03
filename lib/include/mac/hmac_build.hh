/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"
#include "digest/sha2_384.hh"
#include "digest/sha3.hh"
#include "hmac.hh"
#include <type_traits> /* for is_same_v<> */

using Context = alcp::mac::Context;

class HmacBuilder
{
  public:
    static alcp::base::Status Build(const alc_mac_info_t& macInfo,
                                    const alc_key_info_t& keyInfo,
                                    Context&              ctx);
};

template<typename MACALGORITHM>
static alcp::base::Status
__hmac_wrapperUpdate(void* hmac, Uint8* buff, Uint64 size)
{

    auto ap = static_cast<MACALGORITHM*>(hmac);
    return ap->update(buff, size);
}

template<typename MACALGORITHM>
static alcp::base::Status
__hmac_wrapperFinalize(void* hmac, Uint8* buff, Uint64 size)
{
    auto ap = static_cast<MACALGORITHM*>(hmac);
    return ap->finalize(buff, size);
}

template<typename MACALGORITHM>
static alcp::base::Status
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
    digest_p->finish();
    delete ap;
    delete digest_p;
}

template<typename MACALGORITHM, typename DIGESTALGORITHM>
static alcp::base::Status
__hmac_wrapperReset(void* hmac, void* digest)
{
    auto ap = static_cast<MACALGORITHM*>(hmac);

    return ap->reset();
}
template<typename DIGESTALGORITHM, typename MACALGORITHM>
static alcp::base::Status
__build_hmac(const alc_mac_info_t& macInfo, Context& ctx)
{
    alcp::base::Status status = alcp::base::StatusOk();

    auto digest = new DIGESTALGORITHM();
    if (digest == nullptr) {
        // TODO: Update proper Out of Memory Status
        return status;
    }
    auto algo = new MACALGORITHM(macInfo, digest);
    if (algo == nullptr) {
        // TODO: Update proper Out of Memory Status
        return status;
    }
    ctx.m_mac    = static_cast<void*>(algo);
    ctx.m_digest = static_cast<void*>(digest);

    ctx.update   = __hmac_wrapperUpdate<MACALGORITHM>;
    ctx.finalize = __hmac_wrapperFinalize<MACALGORITHM>;
    ctx.copy     = __hmac_wrapperCopy<MACALGORITHM>;
    ctx.finish   = __hmac_wrapperFinish<MACALGORITHM, DIGESTALGORITHM>;
    ctx.reset    = __hmac_wrapperReset<MACALGORITHM, DIGESTALGORITHM>;

    return status;
}
template<typename MACALGORITHM>
static alcp::base::Status
__build_hmac_sha3(const alc_mac_info_t& macInfo, Context& ctx)
{
    alcp::base::Status status = alcp::base::StatusOk();

    auto sha3 = new alcp::digest::Sha3(macInfo.mi_algoinfo.hmac.hmac_digest);
    if (sha3 == nullptr) {
        // TODO: Update proper Out of Memory Status
        return status;
    }

    auto algo = new MACALGORITHM(macInfo, sha3);
    if (algo == nullptr) {
        // TODO: Update proper Out of Memory Status
        return status;
    }
    ctx.m_mac    = static_cast<void*>(algo);
    ctx.m_digest = static_cast<void*>(sha3);

    ctx.update   = __hmac_wrapperUpdate<MACALGORITHM>;
    ctx.finalize = __hmac_wrapperFinalize<MACALGORITHM>;
    ctx.copy     = __hmac_wrapperCopy<MACALGORITHM>;
    ctx.finish   = __hmac_wrapperFinish<MACALGORITHM, alcp::digest::Sha3>;
    ctx.reset    = __hmac_wrapperReset<MACALGORITHM, alcp::digest::Sha3>;

    return status;
}
alcp::base::Status
HmacBuilder::Build(const alc_mac_info_t& macInfo,
                   const alc_key_info_t& keyInfo,
                   Context&              ctx)
{
    alcp::base::Status status = alcp::base::StatusOk();

    switch (macInfo.mi_algoinfo.hmac.hmac_digest.dt_type) {
        case ALC_DIGEST_TYPE_SHA2: {
            switch (macInfo.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2) {
                case ALC_SHA2_256: {
                    status =
                        __build_hmac<alcp::digest::Sha256, alcp::mac::Hmac>(
                            macInfo, ctx);
                    break;
                }
                case ALC_SHA2_224: {
                    status =
                        __build_hmac<alcp::digest::Sha224, alcp::mac::Hmac>(
                            macInfo, ctx);
                    break;
                }
                case ALC_SHA2_384: {
                    status =
                        __build_hmac<alcp::digest::Sha384, alcp::mac::Hmac>(
                            macInfo, ctx);
                    break;
                }
                case ALC_SHA2_512: {
                    status =
                        __build_hmac<alcp::digest::Sha512, alcp::mac::Hmac>(
                            macInfo, ctx);
                    break;
                }
            }
            break;
        }
        case ALC_DIGEST_TYPE_SHA3: {
            switch (macInfo.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3) {
                case ALC_SHA3_224: {
                    status = __build_hmac_sha3<alcp::mac::Hmac>(macInfo, ctx);
                    break;
                }
                case ALC_SHA3_256: {
                    status = __build_hmac_sha3<alcp::mac::Hmac>(macInfo, ctx);
                    break;
                }
                case ALC_SHA3_384: {
                    status = __build_hmac_sha3<alcp::mac::Hmac>(macInfo, ctx);
                    break;
                }
                case ALC_SHA3_512: {
                    status = __build_hmac_sha3<alcp::mac::Hmac>(macInfo, ctx);
                    break;
                }
                default: {
                    // status = ALC_ERROR_NOT_SUPPORTED;
                    // TODO: update status to not supported HMAC Digest
                    break;
                }
            }
            break;
        }
        default: {
            // err = ALC_ERROR_NOT_SUPPORTED;
            // TODO: Update Status error coded to not supported
            break;
        }
    }
    return status;
}
