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
ippsAES_CMACGetSize(int* pSize)
{
    printMsg("ippsAES_CMACGetSize:  ENTRY");

    Uint64 context_size = alcp_mac_context_size();
    *pSize = sizeof(ipp_wrp_mac_ctx) + static_cast<int>(context_size);
    printMsg("ippsAES_CMACGetSize:  EXIT");
    return ippStsNoErr;
}

IppStatus
ippsAES_CMACInit(const Ipp8u*       pKey,
                 int                keyLen,
                 IppsAES_CMACState* pState,
                 int                ctxSize)
{
    printMsg("ippsAES_CMACInit: ENTRY");

    auto p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pState);
    new (p_mac_ctx) ipp_wrp_mac_ctx;

    alc_mac_info_t info;
    info.cmac   = { ALC_AES_MODE_NONE };
    auto status = alcp_MacInit(ALC_MAC_CMAC, p_mac_ctx, pKey, keyLen, info);
    printMsg("ippsAES_CMACInit: EXIT ");
    return status;
}
IppStatus
ippsAES_CMACUpdate(const Ipp8u* pSrc, int len, IppsAES_CMACState* pState)
{
    printMsg("ippsAES_CMACUpdate: ENTRY");
    auto      p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pState);
    IppStatus status    = alcp_MacUpdate(pSrc, len, p_mac_ctx);
    printMsg("ippsAES_CMACUpdate: EXIT");
    return status;
}
IppStatus
ippsAES_CMACFinal(Ipp8u* pMD, int mdLen, IppsAES_CMACState* pState)
{
    printMsg("ippsAES_CMACFinal: ENTRY");
    auto      p_mac_ctx = reinterpret_cast<ipp_wrp_mac_ctx*>(pState);
    IppStatus status    = alcp_MacFinalize(pMD, mdLen, p_mac_ctx);
    printMsg("ippsAES_CMACFinal: EXIT");
    return status;
}
IppStatus
ippsAES_CMACGetTag(Ipp8u* pMD, int mdLen, const IppsAES_CMACState* pState)
{
    // FIXME: CMAC Get Tag. Duplicate context and restore context. Write
    // Testcase to test it.
    printMsg("ippsAES_CMACGetTag: Not Implemented");
    printMsg("ippsAES_CMACGetTag: EXIT");

    return ippStsNoErr;
}
