/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include "mac/ipp_mac_common.hh"

IppStatus
ippsHMACGetSize_rmf(int* pSize)
{
    printMsg("ippsHMACGetSize_rmf: ENTRY");

    // FIXME: Should be using alcp_mac_context_size but macinfo needs to know
    // the type of digest which is not available in this call.
    *pSize = sizeof(ipp_wrp_mac_ctx);
    printMsg("ippsHMACGetSize_rmf: EXIT");
    return ippStsNoErr;
}

// Utility Function to seperate out formation of alc_mac_info
IppStatus
createHmacInfo(alc_mac_info_p        pMacInfo,
               const Ipp8u*          pKey,
               int                   keyLen,
               const IppsHashMethod* pMethod)
{

    const alc_key_info_t cKinfo = { ALC_KEY_TYPE_SYMMETRIC,
                                    ALC_KEY_FMT_RAW,
                                    ALC_KEY_ALG_MAC,
                                    ALC_KEY_LEN_CUSTOM,
                                    static_cast<Uint32>(keyLen * 8),
                                    static_cast<const Uint8*>(pKey) };

    alc_digest_mode_t sha2_mode;
    alc_digest_len_t  sha_length;

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

    pMacInfo->mi_type                              = ALC_MAC_HMAC;
    pMacInfo->mi_algoinfo.hmac.hmac_digest.dt_type = ALC_DIGEST_TYPE_SHA2;
    pMacInfo->mi_algoinfo.hmac.hmac_digest.dt_len  = sha_length;
    pMacInfo->mi_algoinfo.hmac.hmac_digest.dt_mode = sha2_mode;

    pMacInfo->mi_keyinfo = cKinfo;

    return ippStsNoErr;
}

IppStatus
ippsHMACInit_rmf(const Ipp8u*          pKey,
                 int                   keyLen,
                 IppsHMACState_rmf*    pCtx,
                 const IppsHashMethod* pMethod)
{
    printMsg("ippsHMACInit_rmf_rmf: ENTRY");
    auto p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);
    new (p_mac_ctx) ipp_wrp_mac_ctx;
    alc_mac_info_t mac_info;
    auto           status = createHmacInfo(&mac_info, pKey, keyLen, pMethod);
    if (status != ippStsNoErr) {
        return status;
    }
    status = alcp_MacInit(&mac_info, p_mac_ctx);
    printMsg("ippsHMACInit_rmf_rmf: EXIT");
    return status;
}

IppStatus
ippsHMACPack_rmf(const IppsHMACState_rmf* pCtx, Ipp8u* pBuffer, int bufSize)
{
    printMsg("ippsHMACPack_rmf_rmf: ENTRY");
    // FIXME: ALCP Does not have an API to copy context
    printMsg("ippsHMACPack_rmf_rmf: EXIT");
    return ippStsNoErr;
}
IppStatus
ippsHMACUnpack_rmf(const Ipp8u* pBuffer, IppsHMACState_rmf* pCtx)
{
    printMsg("ippsHMACUnpack_rmf: ENTRY");
    // FIXME: ALCP Does not have an API to copy context
    printMsg("ippsHMACUnpack_rmf: EXIT");
    return ippStsNoErr;
}
IppStatus
ippsHMACDuplicate_rmf(const IppsHMACState_rmf* pSrcCtx,
                      IppsHMACState_rmf*       pDstCtx)
{
    printMsg("ippsHMACDuplicate_rmf: ENTRY");
    // FIXME: ALCP Does not have an API to copy context
    printMsg("ippsHMACDuplicate_rmf: EXIT");
    return ippStsNoErr;
}

IppStatus
ippsHMACUpdate_rmf(const Ipp8u* pSrc, int len, IppsHMACState_rmf* pCtx)
{
    printMsg("ippsHMACUpdate_rmf: ENTRY");
    auto      p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);
    IppStatus status    = alcp_MacUpdate(pSrc, len, p_mac_ctx);
    printMsg("ippsHMACUpdate_rmf: EXIT");
    return status;
}
IppStatus
ippsHMACFinal_rmf(Ipp8u* pMD, int mdLen, IppsHMACState_rmf* pCtx)
{
    printMsg("ippsHMACFinal_rmf: ENTRY");
    auto      p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pCtx);
    IppStatus status    = alcp_MacFinalize(pMD, mdLen, p_mac_ctx);
    printMsg("ippsHMACFinal_rmf: EXIT");
    return status;
}
IppStatus
ippsHMACGetTag_rmf(Ipp8u* pMD, int mdLen, const IppsHMACState_rmf* pCtx)
{
    printMsg("ippsHMACGetTag_rmf: ENTRY");
    // FIXME: ALCP Does not have an API to copy context. Hence will need to
    // implement a method to copy, save context and then restore it
    printMsg("ippsHMACGetTag_rmf: EXIT");
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
    // TODO: Add a test case for this function
    printMsg("ippsHMACMessage_rmf: ENTRY");
    int ctx_size = 0;
    ippsHMACGetSize_rmf(&ctx_size);
    auto* p_context = reinterpret_cast<IppsHMACState_rmf*>(new Uint8[ctx_size]);
    auto  status    = ippsHMACInit_rmf(pKey, keyLen, p_context, pMethod);
    if (status != ippStsNoErr) {
        return status;
    }
    status = ippsHMACUpdate_rmf(pMsg, msgLen, p_context);
    if (status != ippStsNoErr) {
        return status;
    }
    status = ippsHMACFinal_rmf(pMD, mdLen, p_context);
    if (status != ippStsNoErr) {
        return status;
    }
    printMsg("ippsHMACMessage_rmf: EXIT");
    return ippStsNoErr;
}