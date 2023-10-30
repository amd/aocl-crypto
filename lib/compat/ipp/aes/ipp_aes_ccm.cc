/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

// FIXME: Code Duplication CCM and GCM can use common path

IppStatus
ippsAES_CCMStart(const Ipp8u*      pIV,
                 int               ivLen,
                 const Ipp8u*      pAAD,
                 int               aadLen,
                 IppsAES_CCMState* pState)
{
    printMsg("CCM Start");
    // Should replace below with something better as it does discard const
    auto             ctx = (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState));
    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);

    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    /* Continue initialization as we didnt have iv in initialization function
       if we already have context then it's already good, we can take it as
       already initialized. */
    // Continue Enc
    if (context_aead->handle.ch_context == nullptr) {
        context_aead->c_aeadinfo.ci_type            = ALC_CIPHER_TYPE_AES;
        context_aead->c_aeadinfo.ci_algo_info.ai_iv = (Uint8*)pIV;

        // context->cinfo = cinfo;
        err = alcp_cipher_aead_supported(&(context_aead->c_aeadinfo));
        if (alcp_is_error(err)) {
            printErr("not supported");
            alcp_error_str(err, err_buf, err_size);
            return ippStsNotSupportedModeErr;
        }
        context_aead->handle.ch_context =
            malloc(alcp_cipher_aead_context_size(&(context_aead->c_aeadinfo)));
        err = alcp_cipher_aead_request(&(context_aead->c_aeadinfo),
                                       &(context_aead->handle));
        if (alcp_is_error(err)) {
            printErr("unable to request");
            alcp_error_str(err, err_buf, err_size);
            free(context_aead->handle.ch_context);
            context_aead->handle.ch_context = nullptr;
            return ippStsErr;
        }
    }

    // CCM Init

    /* Encrypt Init */
    err =
        alcp_cipher_aead_set_tag_length(&(context_aead->handle), ctx->tag_len);
    if (alcp_is_error(err)) {
        printErr("CCM decrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    err = alcp_cipher_aead_set_iv(&(context_aead->handle), ivLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        printf("Error: CCM encrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    // Additional Datas
    if (aadLen != 0 && pAAD != nullptr) {
        err = alcp_cipher_aead_set_aad(&(context_aead->handle), pAAD, aadLen);
        if (alcp_is_error(err)) {
            return ippStsErr;
        }
    }

    printMsg("CCM Start End");
    return ippStsNoErr;
}

IppStatus
ippsAES_CCMEncrypt(const Ipp8u*      pSrc,
                   Ipp8u*            pDst,
                   int               len,
                   IppsAES_CCMState* pState)
{
    printMsg("CCMEncrypt Start");
    alc_error_t err;
    // const int   err_size = 256;
    // Uint8     err_buf[err_size];

    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = true;

    // CCM Encrypt
    err = alcp_cipher_aead_encrypt_update(
        &(context_aead->handle),
        (Uint8*)pSrc,
        (Uint8*)pDst,
        len,
        context_aead->c_aeadinfo.ci_algo_info.ai_iv);
    if (alcp_is_error(err)) {
        return ippStsErr;
    }
    printMsg("CCMEncrypt End");
    return ippStsNoErr;
}

IppStatus
ippsAES_CCMDecrypt(const Ipp8u*      pSrc,
                   Ipp8u*            pDst,
                   int               len,
                   IppsAES_CCMState* pState)
{
    printMsg("CCMDecrypt Start");
    alc_error_t err;
    // const int   err_size = 256;
    // Uint8     err_buf[err_size];

    ipp_wrp_aes_ctx* context_aead =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->aead_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = false;
    // CCM Encrypt
    err = alcp_cipher_aead_decrypt_update(
        &(context_aead->handle),
        (Uint8*)pSrc,
        (Uint8*)pDst,
        len,
        context_aead->c_aeadinfo.ci_algo_info.ai_iv);
    if (alcp_is_error(err)) {
        return ippStsErr;
    }
    printMsg("CCMDecrypt End");
    return ippStsNoErr;
}

IppStatus
ippsAES_CCMGetTag(Ipp8u* pDstTag, int tagLen, const IppsAES_CCMState* pState)
{
    printMsg("CCMGetTag Start");
    alc_error_t      err;
    const int        err_size = 256;
    Uint8            err_buf[err_size];
    ipp_wrp_aes_ctx* context_aead =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->aead_ctx);
    if (((ipp_wrp_aes_aead_ctx*)(pState))->is_encrypt == true) {
        err = alcp_cipher_aead_get_tag(
            &(context_aead->handle), (Uint8*)pDstTag, tagLen);
    } else {
        err = alcp_cipher_aead_get_tag(
            &(context_aead->handle), (Uint8*)pDstTag, tagLen);
    }

    // As per IPP Documentation once CCMGetTag is called, the AES_CCMStart where
    // alcp_cipher_aead_request is called and memory again allocated for
    // context thus preserving the lifecycle without memory leaks
    alcp_cipher_aead_finish(&(context_aead->handle));

    if (context_aead->handle.ch_context) {
        free(context_aead->handle.ch_context);
        context_aead->handle.ch_context = nullptr;
    }

    if (alcp_is_error(err)) {
        printf("CCM tag fetch failure! code:4\n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    printMsg("CCMGetTag End");
    return ippStsNoErr;
}

IppStatus
ippsAES_CCMMessageLen(Ipp64u msgLen, IppsAES_CCMState* pState)
{
    auto ctx = (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState));
    printMsg("CCM MessageLen");
    ctx->msg_len = (size_t)msgLen;
    printMsg("CCM MessageLen End");
    return ippStsNoErr;
}

IppStatus
ippsAES_CCMTagLen(int tagLen, IppsAES_CCMState* pState)
{
    auto ctx     = (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState));
    ctx->tag_len = (size_t)tagLen;

    return ippStsNoErr;
}