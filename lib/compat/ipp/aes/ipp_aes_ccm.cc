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
    ipp_wrp_aes_ctx* context_dec =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->encrypt_ctx);

    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    /* Continue initialization as we didnt have iv in initialization function
       if we already have context then it's already good, we can take it as
       already initialized. */

    // Continue Dec
    if (context_dec->handle.ch_context == nullptr) {
        context_dec->cinfo.ci_type            = ALC_CIPHER_TYPE_AES;
        context_dec->cinfo.ci_algo_info.ai_iv = (Uint8*)pIV;

        // context->cinfo = cinfo;
        err = alcp_cipher_supported(&(context_dec->cinfo));
        if (alcp_is_error(err)) {
            printErr("not supported");
            alcp_error_str(err, err_buf, err_size);
            return ippStsNotSupportedModeErr;
        }
        context_dec->handle.ch_context =
            malloc(alcp_cipher_context_size(&(context_dec->cinfo)));
        err =
            alcp_cipher_request(&(context_dec->cinfo), &(context_dec->handle));
        if (alcp_is_error(err)) {
            printErr("unable to request");
            alcp_error_str(err, err_buf, err_size);
            free(context_dec->handle.ch_context);
            context_dec->handle.ch_context = nullptr;
            return ippStsErr;
        }
    }
    // Continue Enc
    if (context_enc->handle.ch_context == nullptr) {
        context_enc->cinfo.ci_type            = ALC_CIPHER_TYPE_AES;
        context_enc->cinfo.ci_algo_info.ai_iv = (Uint8*)pIV;

        // context->cinfo = cinfo;
        err = alcp_cipher_supported(&(context_enc->cinfo));
        if (alcp_is_error(err)) {
            printErr("not supported");
            alcp_error_str(err, err_buf, err_size);
            return ippStsNotSupportedModeErr;
        }
        context_enc->handle.ch_context =
            malloc(alcp_cipher_context_size(&(context_enc->cinfo)));
        err =
            alcp_cipher_request(&(context_enc->cinfo), &(context_enc->handle));
        if (alcp_is_error(err)) {
            printErr("unable to request");
            alcp_error_str(err, err_buf, err_size);
            free(context_enc->handle.ch_context);
            context_enc->handle.ch_context = nullptr;
            return ippStsErr;
        }
    }

    // CCM Init
    /* Decrypt Init */
    err = alcp_cipher_set_tag_length(&(context_dec->handle), ctx->tag_len);
    if (alcp_is_error(err)) {
        printErr("CCM decrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    err = alcp_cipher_set_iv(&(context_dec->handle), ivLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        printErr("CCM decrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    // Additional Data
    Uint8* aad = (Uint8*)pAAD;
    if (aadLen == 0 && aad == nullptr) {
        // FIXME: Hack to prevent ad from being null
        Uint8 a;
        aad = &a; // Some random value other than NULL
    }
    err = alcp_cipher_set_aad(&(context_dec->handle), aad, aadLen);

    /* Encrypt Init */
    err = alcp_cipher_set_tag_length(&(context_enc->handle), ctx->tag_len);
    if (alcp_is_error(err)) {
        printErr("CCM decrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    err = alcp_cipher_set_iv(&(context_enc->handle), ivLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        printf("Error: CCM encrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    err = alcp_cipher_set_aad(&(context_enc->handle), aad, aadLen);
    if (alcp_is_error(err)) {
        return ippStsErr;
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

    ipp_wrp_aes_ctx* context_enc =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->encrypt_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = true;

    // CCM Encrypt
    err = alcp_cipher_encrypt_update(&(context_enc->handle),
                                     (Uint8*)pSrc,
                                     (Uint8*)pDst,
                                     len,
                                     context_enc->cinfo.ci_algo_info.ai_iv);
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

    ipp_wrp_aes_ctx* context_dec =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->decrypt_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = false;
    // CCM Encrypt
    err = alcp_cipher_decrypt_update(&(context_dec->handle),
                                     (Uint8*)pSrc,
                                     (Uint8*)pDst,
                                     len,
                                     context_dec->cinfo.ci_algo_info.ai_iv);
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
    ipp_wrp_aes_ctx* context_dec =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->encrypt_ctx);
    if (((ipp_wrp_aes_aead_ctx*)(pState))->is_encrypt == true) {
        err = alcp_cipher_get_tag(
            &(context_enc->handle), (Uint8*)pDstTag, tagLen);
    } else {
        err = alcp_cipher_get_tag(
            &(context_dec->handle), (Uint8*)pDstTag, tagLen);
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