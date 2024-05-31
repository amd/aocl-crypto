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

class HmacBuilder
{
  public:
    static Status build(Context* ctx);
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

static void
__hmac_wrapperFinish(void* hmac, void* digest)
{
    auto ap = static_cast<Hmac*>(hmac);
    // ToDo : check if the objects are destructed properly
    delete static_cast<digest::IDigest*>(digest);
    delete ap;
}

static Status
__hmac_wrapperReset(void* hmac)
{
    auto ap = static_cast<Hmac*>(hmac);

    return ap->reset();
}

static Status
__hmac_wrapperInit(Context*        ctx,
                   const Uint8*    key,
                   Uint64          size,
                   alc_mac_info_t* info)
{
    auto hmac_algo = static_cast<Hmac*>(ctx->m_mac);

    if (ctx->m_digest) {
        delete static_cast<digest::IDigest*>(ctx->m_digest);
    }

    alc_digest_mode_t mode   = info->hmac.digest_mode;
    void*             digest = nullptr;
    switch (mode) {
        case ALC_SHA2_256: {
            digest = new digest::Sha256;
            break;
        }
        case ALC_SHA2_224: {
            digest = new digest::Sha224;
            break;
        }
        case ALC_SHA2_384: {
            digest = new digest::Sha384;
            break;
        }
        case ALC_SHA2_512: {
            digest = new digest::Sha512;
            break;
        }
        case ALC_SHA3_224:
            digest = new digest::Sha3_224;
            break;
        case ALC_SHA3_256:
            digest = new digest::Sha3_256;
            break;
        case ALC_SHA3_384:
            digest = new digest::Sha3_384;
            break;
        case ALC_SHA3_512: {
            digest = new digest::Sha3_512;
            break;
        }
        case ALC_SHA2_512_224: {
            digest = new digest::Sha512_224;
            break;
        }
        case ALC_SHA2_512_256: {
            digest = new digest::Sha512_256;
            break;
        }
        case ALC_SHAKE_128:
        case ALC_SHAKE_256: {
            digest        = nullptr;
            Status status = StatusOk();
            status.update(InternalError("Not Supported"));
            return status;
        }
    }

    ctx->m_digest = digest;
    return hmac_algo->init(key, size, static_cast<digest::IDigest*>(digest));
}

static Status
__build_with_copy_hmac(Context* srcCtx, Context* destCtx)
{
    using namespace digest;
    auto hmac_algo = new Hmac(*reinterpret_cast<Hmac*>(srcCtx->m_mac));

    IDigest* src_digest  = static_cast<digest::IDigest*>(srcCtx->m_digest);
    IDigest* dest_digest = nullptr;

    if (dest_digest = dynamic_cast<Sha256*>(src_digest);
        dest_digest != nullptr) {
        dest_digest = new Sha256(*static_cast<Sha256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<Sha224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha224(*static_cast<Sha224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha384*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha384(*static_cast<Sha384*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512(*static_cast<Sha512*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512_224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512_224(*static_cast<Sha512_224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512_256*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512_256(*static_cast<Sha512_256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_224(*static_cast<Sha3_224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_256*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_256(*static_cast<Sha3_256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_384*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_384(*static_cast<Sha3_384*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_512*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_512(*static_cast<Sha3_512*>(dest_digest));
    }

    hmac_algo->setDigest(dest_digest);
    destCtx->m_mac    = static_cast<void*>(hmac_algo);
    destCtx->m_digest = dest_digest;

    destCtx->update    = srcCtx->update;
    destCtx->finalize  = srcCtx->finalize;
    destCtx->finish    = srcCtx->finish;
    destCtx->duplicate = srcCtx->duplicate;
    destCtx->reset     = srcCtx->reset;

    return StatusOk();
}

Status
HmacBuilder::build(Context* ctx)
{
    Status status = StatusOk();

    auto hmac_algo = new Hmac();
    if (hmac_algo == nullptr) {
        status.update(InternalError("Out of Memory"));
        return status;
    }
    ctx->m_mac = static_cast<void*>(hmac_algo);

    ctx->update    = __hmac_wrapperUpdate;
    ctx->finalize  = __hmac_wrapperFinalize;
    ctx->finish    = __hmac_wrapperFinish;
    ctx->reset     = __hmac_wrapperReset;
    ctx->init      = __hmac_wrapperInit;
    ctx->duplicate = __build_with_copy_hmac;

    return status;
}

} // namespace alcp::mac
