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

#include "common/context.hh"
#include "common/error.hh"
#include <alcp/alcp.h>
#include <alcp/types.h>
#include <iostream>
#include <ippcp.h>
#include <sstream>
#include <stdint.h>
#include <string.h>

IppStatus
ippsSHA224GetSize(int* pSize)
{
    printMsg("GetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsSHA256GetSize(int* pSize)
{
    printMsg("GetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsSHA384GetSize(int* pSize)
{
    printMsg("GetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsSHA512GetSize(int* pSize)
{
    printMsg("GetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("GetSize End");
    return ippStsNoErr;
}

IppStatus
ippsHashGetSize(int* pSize)
{
    printMsg("HashGetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("HashGetSize End");
    return ippStsNoErr;
}

IppStatus
ippsHashGetSize_rmf(int* pSize)
{
    printMsg("HashGetSize");
    *pSize = sizeof(ipp_wrp_sha2_ctx);
    printMsg("HashGetSize End");
    return ippStsNoErr;
}

IppStatus
alcp_SHA2Init(ipp_wrp_sha2_ctx* pState,
              alc_digest_len_t  len,
              alc_sha2_mode_t   mode)
{
    printMsg("Init");
    ipp_wrp_sha2_ctx* context = pState;
    alc_error_t       err;

    alc_digest_info_t dinfo;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    dinfo.dt_len          = len;
    dinfo.dt_mode.dm_sha2 = mode;

    Uint64 size           = alcp_digest_context_size(&dinfo);
    context->handle.context = malloc(size);
    context->dinfo          = dinfo;

    err = alcp_digest_request(&dinfo, &(context->handle));

    if (alcp_is_error(err)) {
        return ippStsBadArgErr;
    }
    printMsg("Init End");
    return ippStsNoErr;
}

IppStatus
ippsSHA224Init(IppsSHA256State* pState)
{
    printMsg("SHA2-224");
    return alcp_SHA2Init(
        (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_224, ALC_SHA2_224);
}

IppStatus
ippsSHA256Init(IppsSHA256State* pState)
{
    printMsg("SHA2-256");
    return alcp_SHA2Init(
        (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_256, ALC_SHA2_256);
}

IppStatus
ippsSHA384Init(IppsSHA384State* pState)
{
    printMsg("SHA2-384");
    return alcp_SHA2Init(
        (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_384, ALC_SHA2_384);
}

IppStatus
ippsSHA512Init(IppsSHA512State* pState)
{
    printMsg("SHA2-512");
    return alcp_SHA2Init(
        (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_512, ALC_SHA2_512);
}

IppStatus
ippsHashInit(IppsHashState* pState, IppHashAlgId hashAlg)
{
    switch (hashAlg) {
        case ippHashAlg_SHA224:
            printMsg("SHA2-224");
            return alcp_SHA2Init(
                (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_224, ALC_SHA2_224);
        case ippHashAlg_SHA256:
            printMsg("SHA2-256");
            return alcp_SHA2Init(
                (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_256, ALC_SHA2_256);
        case ippHashAlg_SHA384:
            printMsg("SHA2-384");
            return alcp_SHA2Init(
                (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_384, ALC_SHA2_384);
        case ippHashAlg_SHA512:
            printMsg("SHA2-512");
            return alcp_SHA2Init(
                (ipp_wrp_sha2_ctx*)pState, ALC_DIGEST_LEN_512, ALC_SHA2_512);
        default:
            return ippStsNotSupportedModeErr;
    }
    return ippStsNoErr;
}

IppStatus
ippsHashInit_rmf(IppsHashState_rmf* pState, const IppsHashMethod* pMethod)
{
    ipp_wrp_sha2_ctx*      context    = (ipp_wrp_sha2_ctx*)pState;
    ipp_sha2_rmf_algo_ctx* method_ctx = (ipp_sha2_rmf_algo_ctx*)pMethod;
    IppHashAlgId           hashAlg    = method_ctx->algId;
    switch (hashAlg) {
        case ippHashAlg_SHA224:
            printMsg("SHA2-224");
            return alcp_SHA2Init(context, ALC_DIGEST_LEN_224, ALC_SHA2_224);
        case ippHashAlg_SHA256:
            printMsg("SHA2-256");
            return alcp_SHA2Init(context, ALC_DIGEST_LEN_256, ALC_SHA2_256);
        case ippHashAlg_SHA384:
            printMsg("SHA2-384");
            return alcp_SHA2Init(context, ALC_DIGEST_LEN_384, ALC_SHA2_384);
        case ippHashAlg_SHA512:
            printMsg("SHA2-512");
            return alcp_SHA2Init(context, ALC_DIGEST_LEN_512, ALC_SHA2_512);
        default:
            return ippStsNotSupportedModeErr;
    }
    return ippStsNoErr;
}