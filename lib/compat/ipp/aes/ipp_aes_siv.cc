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
#include "aes/ipp_aes_init_common.hh"
#include <memory>

IppStatus
ippsAES_SIVEncrypt(const Ipp8u* pSrc,
                   Ipp8u*       pDst,
                   int          len,
                   Ipp8u*       pSIV,
                   const Ipp8u* pAuthKey,
                   const Ipp8u* pConfKey,
                   int          keyLen,
                   const Ipp8u* AD[],
                   const int    ADlen[],
                   int          numAD)
{
    static alc_cipher_handle_t handle;
    alc_key_info_t             kinfo = {
                    .type = ALC_KEY_TYPE_SYMMETRIC,
                    .fmt  = ALC_KEY_FMT_RAW,
    };

    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    kinfo.key = pConfKey;
    kinfo.len = ((Uint32)keyLen) * 8;

    alc_cipher_mode_siv_info_t siv_info = { &kinfo };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .len     = ((Uint32)keyLen)*8,
            .key     = pAuthKey,
        },
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_SIV,
           .ai_iv   = NULL,
           .ai_siv = siv_info,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD; i++) {
        err = alcp_cipher_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_encrypt(&handle, pSrc, pDst, len, pSIV);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    err = alcp_cipher_get_tag(&handle, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    return ippStsNoErr;
}

IppStatus
ippsAES_SIVDecrypt(const Ipp8u* pSrc,
                   Ipp8u*       pDst,
                   int          len,
                   int*         pAuthPassed,
                   const Ipp8u* pAuthKey,
                   const Ipp8u* pConfKey,
                   int          keyLen,
                   const Ipp8u* AD[],
                   const int    ADlen[],
                   int          numAD,
                   const Ipp8u* pSIV)
{
    static alc_cipher_handle_t handle;
    alc_key_info_t             kinfo = {
                    .type = ALC_KEY_TYPE_SYMMETRIC,
                    .fmt  = ALC_KEY_FMT_RAW,
    };

    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    kinfo.key = pConfKey;
    kinfo.len = ((Uint32)keyLen) * 8;

    alc_cipher_mode_siv_info_t siv_info = { &kinfo };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .len     = ((Uint32)keyLen)*8,
            .key     = pAuthKey,
        },
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_SIV,
           .ai_iv   = NULL,
           .ai_siv = siv_info,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD; i++) {
        err = alcp_cipher_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_decrypt(&handle, pSrc, pDst, len, pSIV);
    if (alcp_is_error(err)) {
        printf("Error: Tag Verification Failed \n");
        *pAuthPassed = false;
        return ippStsNoErr;
    }

    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    *pAuthPassed = true;

    return ippStsNoErr;
}

IppStatus
ippsAES_S2V_CMAC(const Ipp8u* pKey,
                 int          keyLen,
                 const Ipp8u* AD[],
                 const int    ADlen[],
                 int          numAD,
                 Ipp8u*       pSIV)
{
    static alc_cipher_handle_t handle;
    alc_key_info_t             kinfo = {
                    .type = ALC_KEY_TYPE_SYMMETRIC,
                    .fmt  = ALC_KEY_FMT_RAW,
    };

    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    std::unique_ptr<Uint8> pConfKey = std::make_unique<Uint8>(keyLen);

    kinfo.key = pConfKey.get();
    kinfo.len = ((Uint32)keyLen) * 8;

    alc_cipher_mode_siv_info_t siv_info = { &kinfo };

    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .len     = ((Uint32)keyLen)*8,
            .key     = pKey,
        },
        .ci_algo_info   = {
           .ai_mode = ALC_AES_MODE_SIV,
           .ai_iv   = NULL,
           .ai_siv = siv_info,
        },
    };

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD - 1; i++) {
        err = alcp_cipher_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    {
        std::vector<Uint8> fakeDest = std::vector<Uint8>(ADlen[numAD - 1]);
        err                         = alcp_cipher_encrypt(
            &handle, AD[numAD - 1], &fakeDest[0], fakeDest.size(), pSIV);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            alcp_error_str(err, err_buf, err_size);
            return ippStsErr;
        }
    }

    err = alcp_cipher_get_tag(&handle, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return ippStsErr;
    }

    alcp_cipher_finish(&handle);

    free(handle.ch_context);

    return ippStsNoErr;
}