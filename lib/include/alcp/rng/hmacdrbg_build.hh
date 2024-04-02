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
#include "alcp/capi/mac/builder.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha2_384.hh"
#include "alcp/digest/sha2_512.hh"
#include "alcp/digest/sha3.hh"
#include "drbg_hmac.hh"
namespace alcp::drbg {
class HmacDrbgBuilder
{
  public:
    static Status build(const alc_drbg_info_t& drbgInfo, Context& ctx);

    static Uint64 getSize(const alc_drbg_info_t& drbgInfo);

    static Status isSupported(const alc_drbg_info_t& drbgInfo);
};

Status
HmacDrbgBuilder::build(const alc_drbg_info_t& drbgInfo, Context& ctx)
{
    auto  status   = StatusOk();
    auto  addr     = reinterpret_cast<Uint8*>(&ctx) + sizeof(ctx);
    auto* hmacdrbg = new (addr) alcp::rng::drbg::HmacDrbg();
    std::shared_ptr<alcp::digest::IDigest> p_digest;
    switch (drbgInfo.di_algoinfo.hmac_drbg.digest_info.dt_type) {
        case ALC_DIGEST_TYPE_SHA2: {
            switch (
                drbgInfo.di_algoinfo.hmac_drbg.digest_info.dt_mode.dm_sha2) {
                case ALC_SHA2_256: {
                    p_digest = std::make_shared<alcp::digest::Sha256>();
                    break;
                }
                case ALC_SHA2_224: {
                    p_digest = std::make_shared<alcp::digest::Sha224>();
                    break;
                }
                case ALC_SHA2_384: {
                    p_digest = std::make_shared<alcp::digest::Sha384>();
                    break;
                }
                case ALC_SHA2_512: {
                    p_digest = std::make_shared<alcp::digest::Sha512>();
                    break;
                }
                default: {
                    status.update(
                        InternalError("Unsupported HMAC Sha2 Algorithm"));
                }
            }
            break;
        }
        case ALC_DIGEST_TYPE_SHA3: {
            p_digest = std::make_shared<digest::Sha3>(
                drbgInfo.di_algoinfo.hmac_drbg.digest_info);
            break;
        }
        default: {
            status.update(InternalError("Digest algorithm Unknown"));
            break;
        }
    }
    if (!status.ok()) {
        return status;
    }
    ctx.m_drbg = static_cast<void*>(hmacdrbg);

    status = hmacdrbg->setDigest(p_digest);
    if (!status.ok()) {
        return status;
    }

    return status;
}
Uint64
HmacDrbgBuilder::getSize(const alc_drbg_info_t& drbgInfo)
{
    return sizeof(alcp::rng::drbg::HmacDrbg);
}

Status
HmacDrbgBuilder::isSupported(const alc_drbg_info_t& drbgInfo)
{
    return mac::isDigestSupported(drbgInfo.di_algoinfo.hmac_drbg.digest_info);
}
} // namespace alcp::drbg