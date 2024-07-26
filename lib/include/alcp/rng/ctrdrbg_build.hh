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

#include "alcp/base.hh"
#include "drbg_ctr.hh"

using namespace alcp::base::status;
namespace alcp::drbg {
class CtrDrbgBuilder
{
  public:
    static alc_error_t build(const alc_drbg_info_t& drbgInfo, Context& ctx);

    static Uint64 getSize(const alc_drbg_info_t& drbgInfo);

    static alc_error_t isSupported(const alc_drbg_info_t& drbgInfo);
};

alc_error_t
CtrDrbgBuilder::build(const alc_drbg_info_t& drbgInfo, Context& ctx)
{
    auto addr    = reinterpret_cast<Uint8*>(&ctx) + sizeof(ctx);
    auto ctrdrbg = new (addr) alcp::rng::drbg::CtrDrbg();
    // FIXME: KeySize has to be validated
    ctrdrbg->setKeySize(drbgInfo.di_algoinfo.ctr_drbg.di_keysize / 8);
    ctrdrbg->setUseDerivationFunction(
        drbgInfo.di_algoinfo.ctr_drbg.use_derivation_function);

    ctx.m_drbg = static_cast<void*>(ctrdrbg);
    return ALC_ERROR_NONE;
}
Uint64
CtrDrbgBuilder::getSize(const alc_drbg_info_t& drbgInfo)
{
    return sizeof(alcp::rng::drbg::CtrDrbg);
}

alc_error_t
CtrDrbgBuilder::isSupported(const alc_drbg_info_t& drbgInfo)
{
    if ((drbgInfo.di_algoinfo.ctr_drbg.di_keysize == 128)
        | (drbgInfo.di_algoinfo.ctr_drbg.di_keysize == 192)
        | (drbgInfo.di_algoinfo.ctr_drbg.di_keysize == 256)) {
        return ALC_ERROR_NONE;
    } else {
        // CTR-DRBG: Unsupported CTR Key Size
        return ALC_ERROR_INVALID_ARG;
    }
    return ALC_ERROR_NONE;
}
} // namespace alcp::drbg