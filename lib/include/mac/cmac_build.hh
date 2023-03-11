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
#pragma once

#include "alcp/error.h"
#include "cmac.hh"
#include <type_traits> /* for is_same_v<> */

namespace alcp::mac {

class CmacBuilder
{
  public:
    static Status build(const alc_mac_info_t& macInfo,
                        const alc_key_info_t& keyInfo,
                        Context&              ctx);
};

static Status
__cmac_wrapperUpdate(void* cmac, const Uint8* buff, Uint64 size)
{

    auto p_cmac = static_cast<Cmac*>(cmac);
    return p_cmac->update(buff, size);
}

static Status
__cmac_wrapperFinalize(void* cmac, const Uint8* buff, Uint64 size)
{
    auto p_cmac = static_cast<Cmac*>(cmac);
    return p_cmac->finalize(buff, size);
}

static Status
__cmac_wrapperCopy(void* cmac, Uint8* buff, Uint64 size)
{
    auto p_cmac = static_cast<Cmac*>(cmac);
    return p_cmac->copy(buff, size);
}

static void
__cmac_wrapperFinish(void* cmac, void* digest)
{
    auto p_cmac = static_cast<Cmac*>(cmac);
    p_cmac->finish();
    delete p_cmac;
}

static Status
__cmac_wrapperReset(void* cmac, void* digest)
{
    auto p_cmac = static_cast<Cmac*>(cmac);
    return p_cmac->reset();
}

static Status
__build_cmac(const alc_cipher_info_t& cipherInfo,
             const alc_key_info_t     cKinfo,
             Context&                 ctx)
{
    Status status = StatusOk();
    auto   p_algo = new Cmac();

    auto p_key = cKinfo.key;
    auto len = cKinfo.len;
    p_algo->setKey(p_key, len);
    if (p_algo == nullptr) {
        // FIXME: Update proper Out of Memory Status
        return status;
    }
    ctx.m_mac = static_cast<void*>(p_algo);

    ctx.update   = __cmac_wrapperUpdate;
    ctx.finalize = __cmac_wrapperFinalize;
    ctx.copy     = __cmac_wrapperCopy;
    ctx.finish   = __cmac_wrapperFinish;
    ctx.reset    = __cmac_wrapperReset;

    return status;
}
Status
CmacBuilder::build(const alc_mac_info_t& macInfo,
                   const alc_key_info_t& keyInfo,
                   Context&              ctx)
{
    return __build_cmac(macInfo.mi_algoinfo.cmac.cmac_cipher, keyInfo, ctx);
}
} // namespace alcp::mac