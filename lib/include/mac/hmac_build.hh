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
#include "digest/sha2_512.hh"
#include "hmac.hh"

#ifndef _MAC_HMAC_BUILD_HH
#define _MAC_HMAC_BUILD_HH 2

using Context = alcp::mac::Context;

class HmacBuilder
{
  public:
    static alc_error_t Build(const alc_mac_info_t& macInfo,
                             const alc_key_info_t& keyInfo,
                             Context&              ctx);
};

template<typename MACALGORITHM>
static alc_error_t
__hmac_wrapperUpdate(void* hmac, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    auto        ap  = static_cast<MACALGORITHM*>(hmac);
    err             = ap->update(buff, size);
    return err;
}

template<typename MACALGORITHM>
static alc_error_t
__hmac_wrapperFinalize(void* hmac, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    auto        ap  = static_cast<MACALGORITHM*>(hmac);
    err             = ap->finalize(buff, size);
    return err;
}

template<typename MACALGORITHM>
static alc_error_t
__hmac_wrapperCopy(void* hmac, Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    auto        ap  = static_cast<MACALGORITHM*>(hmac);
    err             = ap->copyHash(buff, size);
    return err;
}

template<typename MACALGORITHM, typename DIGESTALGORITHM>
static void
__hmac_wrapperFinish(void* hmac, void* digest)
{
    auto ap       = static_cast<MACALGORITHM*>(hmac);
    auto digest_p = static_cast<DIGESTALGORITHM*>(digest);
    ap->finish();
    delete ap;
    delete digest_p;
}
template<typename DIGESTALGORITHM, typename MACALGORITHM>
static alc_error_t
__build_hmac(DIGESTALGORITHM*      digest,
             const alc_mac_info_t& macInfo,
             Context&              ctx)
{
    auto err = ALC_ERROR_NONE;

    auto algo    = new MACALGORITHM(macInfo, digest);
    ctx.m_mac    = static_cast<void*>(algo);
    ctx.m_digest = static_cast<void*>(digest);

    ctx.update   = __hmac_wrapperUpdate<MACALGORITHM>;
    ctx.finalize = __hmac_wrapperFinalize<MACALGORITHM>;
    ctx.copy     = __hmac_wrapperCopy<MACALGORITHM>;
    ctx.finish   = __hmac_wrapperFinish<MACALGORITHM, DIGESTALGORITHM>;
    return err;
}

alc_error_t
HmacBuilder::Build(const alc_mac_info_t& macInfo,
                   const alc_key_info_t& keyInfo,
                   Context&              ctx)
{
    alc_error_t err = ALC_ERROR_NONE;
    // switch (macInfo.mi_algoinfo.hmac.hmac_digest.dt_type) {
    //     case ALC_DIGEST_TYPE_SHA2:
    //         switch (macInfo.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2) {
    //             case ALC_SHA2_256:

    //                 break;
    //         }
    //         break;
    // }

    // TODO: Function to build Sha
    // TODO: Add the switch case here
    auto sha256 = new alcp::digest::Sha256();
    err         = __build_hmac<alcp::digest::Sha256, alcp::mac::Hmac>(
        sha256, macInfo, ctx);
    return err;
}

#endif /* _MAC_HMAC_BUILD_HH */
