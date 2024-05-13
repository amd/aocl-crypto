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

#include "mac/ipp_mac_common.hh"

IppStatus
alcp_MacInit(alc_mac_type_t   macType,
             ipp_wrp_mac_ctx* p_mac_ctx,
             const Ipp8u*     pKey,
             int              keyLen,
             alc_mac_info_t   info)
{
    p_mac_ctx->handle.ch_context = malloc(alcp_mac_context_size());

    if (p_mac_ctx->handle.ch_context == NULL) {
        return ippStsErr;
    }

    auto err = alcp_mac_request(&p_mac_ctx->handle, macType);
    if (err != ALC_ERROR_NONE) {
        printErr("ALCP MAC Provider:  Request failed\n");
        return ippStsErr;
    }

    err = alcp_mac_init(&p_mac_ctx->handle, pKey, keyLen, info);
    if (err != ALC_ERROR_NONE) {
        printErr("ALCP MAC Provider:  Init failed\n");
        return ippStsErr;
    }

    return ippStsNoErr;
}

IppStatus
alcp_MacUpdate(const Ipp8u* pSrc, int len, ipp_wrp_mac_ctx* p_mac_ctx)
{

    auto err = alcp_mac_update(&p_mac_ctx->handle,
                               static_cast<const Uint8*>(pSrc),
                               static_cast<Uint64>(len));
    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in updating");
        return ippStsErr;
    }
    return ippStsNoErr;
}

IppStatus
alcp_MacFinalize(Ipp8u* pMD, int len, ipp_wrp_mac_ctx* p_mac_ctx)
{

    auto err = alcp_mac_finalize(
        &p_mac_ctx->handle, static_cast<Uint8*>(pMD), static_cast<Uint64>(len));

    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in Finalizing");
        return ippStsErr;
    }

    err = alcp_mac_finish(&p_mac_ctx->handle);
    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in Finish");
        return ippStsErr;
    }
    p_mac_ctx->~ipp_wrp_mac_ctx();
    free(p_mac_ctx->handle.ch_context);
    p_mac_ctx->handle.ch_context = nullptr;
    return ippStsNoErr;
}