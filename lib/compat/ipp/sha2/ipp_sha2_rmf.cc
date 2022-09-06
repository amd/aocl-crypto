/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "ipp_sha2_common.hh"

IppStatus
ippsHashUpdate(const Ipp8u* pSrc, int len, IppsHashState* pState)
{
    printMsg("Hash Update");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("Hash Update End");
    return sts;
}

IppStatus
ippsHashUpdate_rmf(const Ipp8u* pSrc, int len, IppsHashState_rmf* pState)
{
    printMsg("Hash Update RMF");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("Hash Update RMF End");
    return sts;
}

IppStatus
ippsHashFinal(Ipp8u* pMD, IppsHashState* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("Hash Final");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("Hash Final End");
    return sts;
}

IppStatus
ippsHashFinal_rmf(Ipp8u* pMD, IppsHashState_rmf* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("Hash Final RMF");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("Hash Final RMF End");
    return sts;
}