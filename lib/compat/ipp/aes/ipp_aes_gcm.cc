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

#include "aes/ipp_aes_common.hh"

IppStatus
ippsAES_GCMStart(const Ipp8u*      pIV,
                 int               ivLen,
                 const Ipp8u*      pAAD,
                 int               aadLen,
                 IppsAES_GCMState* pState)
{
    printMsg("GCM Start");

    // Should replace below with something better as it does discard const
    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);

    alc_error_t err = ALC_ERROR_NONE;

    // Initialize the context with the IV.
    err = alcp_cipher_aead_init(
        &(context_aead->handle), nullptr, 0, (Uint8*)pIV, ivLen);
    if (alcp_is_error(err)) {
        printf("Error: GCM encrypt init failure! code:11\n");
        return ippStsErr;
    }

    // Feed additional data into the algorithm
    if (aadLen != 0 && pAAD != nullptr) {
        err = alcp_cipher_aead_set_aad(&(context_aead->handle), pAAD, aadLen);
        if (alcp_is_error(err)) {
            return ippStsErr;
        }
    }

    printMsg("GCM Start End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMEncrypt(const Ipp8u*      pSrc,
                   Ipp8u*            pDst,
                   int               len,
                   IppsAES_GCMState* pState)
{
    printMsg("GCMEncrypt Start");

    alc_error_t err = ALC_ERROR_NONE;

    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = true;

    // GCM Encrypt
    err = alcp_cipher_aead_encrypt(
        &(context_aead->handle), (Uint8*)pSrc, (Uint8*)pDst, len);
    if (alcp_is_error(err)) {
        return ippStsErr;
    }

    printMsg("GCMEncrypt End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMDecrypt(const Ipp8u*      pSrc,
                   Ipp8u*            pDst,
                   int               len,
                   IppsAES_GCMState* pState)
{
    printMsg("GCMDecrypt Start");
    alc_error_t err;

    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = false;

    // GCM Decrypt
    err = alcp_cipher_aead_decrypt(
        &(context_aead->handle), (Uint8*)pSrc, (Uint8*)pDst, len);
    if (alcp_is_error(err)) {
        return ippStsErr;
    }

    printMsg("GCMDecrypt End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMGetTag(Ipp8u* pDstTag, int tagLen, const IppsAES_GCMState* pState)
{
    printMsg("GCMGetTag Start");
    alc_error_t err;

    ipp_wrp_aes_ctx* context_aead =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->aead_ctx);

    // Get the tag
    err = alcp_cipher_aead_get_tag(
        &(context_aead->handle), (Uint8*)pDstTag, tagLen);

    // Finish the transaction
    alcp_cipher_aead_finish(&(context_aead->handle));

    if (alcp_is_error(err)) {
        printf("GCM tag fetch failure! code:4\n");
        return false;
    }

    printMsg("GCMGetTag End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMReset(IppsAES_GCMState* pState)
{
    ((ipp_wrp_aes_aead_ctx*)(pState))->is_encrypt = false;
    // FIXME: Add a reset API for cipher
    return ippStsNoErr;
}