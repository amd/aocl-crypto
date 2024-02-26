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

#include "alcp/capi/mac/builder.hh"
#include "alcp/mac/cmac_build.hh"
#include "alcp/mac/hmac_build.hh"
#include "alcp/mac/poly1305_build.hh"

namespace alcp::mac {

using poly1305::Poly1305Builder;

Status
MacBuilder::build(const alc_mac_info_t& macInfo, Context& ctx)
{
    using namespace status;
    Status status = StatusOk();
    switch (macInfo.mi_type) {
        case ALC_MAC_HMAC:
            status = HmacBuilder::build(macInfo, macInfo.mi_keyinfo, ctx);
            break;
        case ALC_MAC_CMAC:
            status = CmacBuilder::build(macInfo, macInfo.mi_keyinfo, ctx);
            break;
        case ALC_MAC_POLY1305:
            status = Poly1305Builder::build(macInfo, macInfo.mi_keyinfo, ctx);
            break;
        default:
            status.update(InvalidArgument("Unknown MAC Type"));
            break;
    }
    return status;
}

Uint64
MacBuilder::getSize(const alc_mac_info_t& macInfo)
{
    Uint64 size = 0;
    switch (macInfo.mi_type) {
        case ALC_MAC_CMAC:
            size = CmacBuilder::getSize(macInfo);
            break;
        case ALC_MAC_HMAC:
            size = HmacBuilder::getSize(macInfo);
            break;
        case ALC_MAC_POLY1305:
            size = Poly1305Builder::getSize(macInfo);
        default:
            size = 0;
    }
    return size;
}

Status
MacBuilder::isSupported(const alc_mac_info_t& macInfo)
{
    Status s{ StatusOk() };

    switch (macInfo.mi_type) {
        case ALC_MAC_CMAC:
            s = CmacBuilder::isSupported(macInfo);
            break;
        case ALC_MAC_HMAC:
            s = HmacBuilder::isSupported(macInfo);
            break;
        case ALC_MAC_POLY1305:
            s = Poly1305Builder::isSupported(macInfo);
            break;
        default:
            return InvalidArgument("Invalid MAC Algorithm");
            break;
    }

    return s;
}

} // namespace alcp::mac