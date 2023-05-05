/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met_rmf:
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
#include <ippcp.h>

IppStatus
ippsHMACGetSize_rmf(int* pSize)
{
    printMsg("ALCP Provider HMAC GETSIZE_rmf: ENTRY ");

    // FIXME: Should be using alcp_mac_context_size but macinfo needs to know
    // the type of digest which is not available in this call.
    *pSize = sizeof(ipp_wrp_mac_ctx);
    printMsg("ALCP Provider HMAC GETSIZE_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACInit_rmf(const Ipp8u*          pKey,
                 int                   keyLen,
                 IppsHMACState_rmf*    pCtx,
                 const IppsHashMethod* pMethod)
{
    printMsg("ALCP Provider  ippsHMACInit_rmf_rmf: ENTRY ");

    auto p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);
    new (p_mac_ctx) ipp_wrp_mac_ctx;

    const alc_key_info_t cKinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                    .fmt  = ALC_KEY_FMT_RAW,
                                    .algo = ALC_KEY_ALG_MAC,
                                    .len  = static_cast<Uint32>(keyLen * 8),
                                    .key  = static_cast<const Uint8*>(pKey) };

    alc_sha2_mode_t  sha2_mode;
    alc_digest_len_t sha_length;

    ipp_sha2_rmf_algo_ctx* p_method_ctx = (ipp_sha2_rmf_algo_ctx*)pMethod;
    IppHashAlgId           hashAlg      = p_method_ctx->algId;
    switch (hashAlg) {
        case ippHashAlg_SHA224: {

            printMsg("SHA2-224");
            sha_length = ALC_DIGEST_LEN_224;
            sha2_mode  = ALC_SHA2_224;
            break;
        }
        case ippHashAlg_SHA256: {

            printMsg("SHA2-256");
            sha_length = ALC_DIGEST_LEN_256;
            sha2_mode  = ALC_SHA2_256;
            break;
        }
        case ippHashAlg_SHA384: {

            printMsg("SHA2-384");
            sha_length = ALC_DIGEST_LEN_384;
            sha2_mode  = ALC_SHA2_384;
            break;
        }
        case ippHashAlg_SHA512: {

            printMsg("SHA2-512");
            sha_length = ALC_DIGEST_LEN_512;
            sha2_mode  = ALC_SHA2_512;
            break;
        }
        case ippHashAlg_SHA512_224: {

            printMsg("SHA2-512_224");
            sha_length = ALC_DIGEST_LEN_224;
            sha2_mode  = ALC_SHA2_512;
            break;
        }
        case ippHashAlg_SHA512_256: {

            printMsg("SHA2-512_256");
            sha_length = ALC_DIGEST_LEN_256;
            sha2_mode  = ALC_SHA2_512;
            break;
        }
        default:
            return ippStsNotSupportedModeErr;
    }
    alc_mac_info_t macinfo = {
        .mi_type = ALC_MAC_HMAC,
        .mi_algoinfo={
            .hmac={
                .hmac_digest = {
                    .dt_type = ALC_DIGEST_TYPE_SHA2,
                    .dt_len = sha_length,
                    .dt_mode = {.dm_sha2 = sha2_mode,},
                }
            }
        },
        .mi_keyinfo = cKinfo
    };
    auto err = alcp_mac_supported(&macinfo);

    if (err == ALC_ERROR_NONE) {
        p_mac_ctx->handle.ch_context = malloc(alcp_mac_context_size(&macinfo));
    } else {
        printMsg(
            "ALCP MAC Provider: CMAC Information provided is unsupported\n");
        return ippStsNotSupportedModeErr;
    }

    err = alcp_mac_request(&p_mac_ctx->handle, &macinfo);
    if (err != ALC_ERROR_NONE) {
        printMsg("ALCP MAC Provider: CMAC Request failed\n");
        return ippStsErr;
    }

    printMsg("ALCP Provider  ippsHMACInit_rmf_rmf: EXIT ");
    return ippStsNoErr;
}

IppStatus
ippsHMACPack_rmf(const IppsHMACState_rmf* pCtx, Ipp8u* pBuffer, int bufSize)
{
    printMsg("ALCP Provider  ippsHMACPack_rmf_rmf: ENTRY ");

    printMsg("ALCP Provider  ippsHMACPack_rmf_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACUnpack_rmf(const Ipp8u* pBuffer, IppsHMACState_rmf* pCtx)
{
    printMsg("ALCP Provider  ippsHMACUnpack_rmf: ENTRY ");
    printMsg("ALCP Provider  ippsHMACUnpack_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACDuplicate_rmf(const IppsHMACState_rmf* pSrcCtx,
                      IppsHMACState_rmf*       pDstCtx)
{
    printMsg("ALCP Provider  ippsHMACDuplicate_rmf: ENTRY ");
    printMsg("ALCP Provider  ippsHMACDuplicate_rmf: EXIT ");
    return ippStsNoErr;
}

IppStatus
ippsHMACUpdate_rmf(const Ipp8u* pSrc, int len, IppsHMACState_rmf* pCtx)
{
    printMsg("ALCP Provider  ippsHMACUpdate_rmf: ENTRY ");
    auto p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);
    auto err       = alcp_mac_update(&p_mac_ctx->handle,
                               static_cast<const Uint8*>(pSrc),
                               static_cast<Uint64>(len));
    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in updating");
        return ippStsErr;
    }
    printMsg("ALCP Provider  ippsHMACUpdate_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACFinal_rmf(Ipp8u* pMD, int mdLen, IppsHMACState_rmf* pCtx)
{
    printMsg("ALCP Provider  ippsHMACFinal_rmf: ENTRY ");
    auto p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);

    auto err = alcp_mac_finalize(&p_mac_ctx->handle, nullptr, 0);

    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in Finalizing");
        return ippStsErr;
    }

    err = alcp_mac_copy(&p_mac_ctx->handle,
                        static_cast<Uint8*>(pMD),
                        static_cast<Uint64>(mdLen));
    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in Copying MAC");
        return ippStsErr;
    }
    err = alcp_mac_finish(&p_mac_ctx->handle);
    if (alcp_is_error(err)) {
        printErr("ALCP Provider: Error in Finish");
        return ippStsErr;
    }
    free(p_mac_ctx->handle.ch_context);

    printMsg("ALCP Provider  ippsHMACFinal_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACGetTag_rmf(Ipp8u* pMD, int mdLen, const IppsHMACState_rmf* pCtx)
{
    printMsg("ALCP Provider  ippsHMACGetTag_rmf: ENTRY ");
    printMsg("ALCP Provider  ippsHMACGetTag_rmf: EXIT ");
    return ippStsNoErr;
}
IppStatus
ippsHMACMessage_rmf(const Ipp8u*          pMsg,
                    int                   msgLen,
                    const Ipp8u*          pKey,
                    int                   keyLen,
                    Ipp8u*                pMD,
                    int                   mdLen,
                    const IppsHashMethod* pMethod)
{
    printMsg("ALCP Provider  ippsHMACMessage_rmf: ENTRY ");
    printMsg("ALCP Provider  ippsHMACMessage_rmf: EXIT ");
    return ippStsNoErr;
}