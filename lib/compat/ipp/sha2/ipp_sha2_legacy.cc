/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "sha2/ipp_sha2_common.hh"

IppStatus
ippsSHA224Update(const Ipp8u* pSrc, int len, IppsSHA224State* pState)
{
    printMsg("SHA224 Update");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("SHA224 Update End");
    return sts;
}

IppStatus
ippsSHA256Update(const Ipp8u* pSrc, int len, IppsSHA256State* pState)
{
    printMsg("SHA256 Update");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("SHA256 Update End");
    return sts;
}

IppStatus
ippsSHA384Update(const Ipp8u* pSrc, int len, IppsSHA384State* pState)
{
    printMsg("SHA384 Update");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("SHA384 Update End");
    return sts;
}

IppStatus
ippsSHA512Update(const Ipp8u* pSrc, int len, IppsSHA512State* pState)
{
    printMsg("SHA512 Update");
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts     = alcp_DigestUpdate(pSrc, len, context);
    printMsg("SHA512 Update End");
    return sts;
}

IppStatus
ippsSHA224Final(Ipp8u* pMD, IppsSHA224State* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("SHA224 Final");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("SHA224 Final End");
    return sts;
}

IppStatus
ippsSHA256Final(Ipp8u* pMD, IppsSHA256State* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("SHA256 Final");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("SHA256 Final End");
    return sts;
}

IppStatus
ippsSHA384Final(Ipp8u* pMD, IppsSHA384State* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("SHA384 Final");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("SHA384 Final End");
    return sts;
}

IppStatus
ippsSHA512Final(Ipp8u* pMD, IppsSHA512State* pState)
{
    ipp_wrp_sha2_ctx* context = reinterpret_cast<ipp_wrp_sha2_ctx*>(pState);
    IppStatus         sts;

    printMsg("SHA512 Final");
    sts = alcp_DigestFinal(pMD, context);
    printMsg("SHA512 Final End");
    return sts;
}