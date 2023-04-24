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
 */

#include "common/context.hh"
#include "common/error.hh"
#include <alcp/alcp.h>
#include <alcp/types.h>
#include <iostream>
#include <ippcp.h>
#include <stdint.h>
#include <string.h>

IppStatus
alcp_DigestUpdate(const Ipp8u* pSrc, int len, ipp_wrp_sha2_ctx* pState)
{
    ipp_wrp_sha2_ctx* context = pState;
    alc_error_t       err;

    err = alcp_digest_update(&(context->handle), (const Uint8*)pSrc, len);
    if (alcp_is_error(err)) {
        printErr("Unable to compute SHA2 hash\n");
        return ippStsUnderRunErr;
    }
    return ippStsNoErr;
}

IppStatus
alcp_DigestFinal(Ipp8u* pMD, ipp_wrp_sha2_ctx* pState)
{
    ipp_wrp_sha2_ctx* context = pState;
    alc_error_t       err;

    alcp_digest_finalize(&(context->handle), nullptr, 0);

    err = alcp_digest_copy(
        &(context->handle), (Uint8*)pMD, context->dinfo.dt_len / 8);
    if (alcp_is_error(err)) {
        printErr("Unable to copy digest\n");
        return ippStsUnderRunErr;
    }
    // Messup digest to test wrapper
    // *(reinterpret_cast<Uint8*>(pMD)) = 0x00;
    return ippStsNoErr;
}
