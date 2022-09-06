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

#include "aes_common.hh"

IppStatus
ippsAES_GCMStart(const Ipp8u*      pIV,
                 int               ivLen,
                 const Ipp8u*      pAAD,
                 int               aadLen,
                 IppsAES_GCMState* pState)
{
    printMsg("GCM Start");
    // Should replace below with something better as it does discard const
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
    // GCM Init
    /* Decrypt Init */
    err = alcp_cipher_decrypt_update(
        &(context_dec->handle), nullptr, nullptr, ivLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        printErr("GCM decrypt init failure! code:11\n");
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
    err = alcp_cipher_decrypt_update(
        &(context_dec->handle), aad, nullptr, aadLen, (Uint8*)pIV);

    /* Encrypt Init */
    err = alcp_cipher_encrypt_update(
        &(context_enc->handle), nullptr, nullptr, ivLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        printf("Error: GCM encrypt init failure! code:11\n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }
    err = alcp_cipher_encrypt_update(
        &(context_enc->handle), aad, nullptr, aadLen, (Uint8*)pIV);
    if (alcp_is_error(err)) {
        return ippStsErr;
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
    alc_error_t err;
    // const int   err_size = 256;
    // Uint8     err_buf[err_size];

    ipp_wrp_aes_ctx* context_enc =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->encrypt_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = true;

    // GCM Encrypt
    err = alcp_cipher_encrypt_update(&(context_enc->handle),
                                     (Uint8*)pSrc,
                                     (Uint8*)pDst,
                                     len,
                                     context_enc->cinfo.ci_algo_info.ai_iv);
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
    // const int   err_size = 256;
    // Uint8     err_buf[err_size];

    ipp_wrp_aes_ctx* context_dec =
        &((reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->decrypt_ctx);
    (reinterpret_cast<ipp_wrp_aes_aead_ctx*>(pState))->is_encrypt = false;
    // GCM Encrypt
    err = alcp_cipher_decrypt_update(&(context_dec->handle),
                                     (Uint8*)pSrc,
                                     (Uint8*)pDst,
                                     len,
                                     context_dec->cinfo.ci_algo_info.ai_iv);
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
    alc_error_t      err;
    const int        err_size = 256;
    Uint8            err_buf[err_size];
    ipp_wrp_aes_ctx* context_dec =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->encrypt_ctx);
    if (((ipp_wrp_aes_aead_ctx*)(pState))->is_encrypt == true) {
        err = alcp_cipher_encrypt_update(&(context_enc->handle),
                                         nullptr,
                                         (Uint8*)pDstTag,
                                         tagLen,
                                         context_dec->cinfo.ci_algo_info.ai_iv);
    } else {
        err = alcp_cipher_decrypt_update(&(context_dec->handle),
                                         nullptr,
                                         (Uint8*)pDstTag,
                                         tagLen,
                                         context_dec->cinfo.ci_algo_info.ai_iv);
    }
    if (alcp_is_error(err)) {
        printf("GCM tag fetch failure! code:4\n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    printMsg("GCMGetTag End");
    return ippStsNoErr;
}

IppStatus
ippsAES_GCMReset(IppsAES_GCMState* pState)
{
    ipp_wrp_aes_ctx* context_dec =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->decrypt_ctx);
    ipp_wrp_aes_ctx* context_enc =
        &(((ipp_wrp_aes_aead_ctx*)(pState))->encrypt_ctx);
    ((ipp_wrp_aes_aead_ctx*)(pState))->is_encrypt = false;
    free(context_dec->handle.ch_context);
    free(context_enc->handle.ch_context);
    return ippStsNoErr;
}