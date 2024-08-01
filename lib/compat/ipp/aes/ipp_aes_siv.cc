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
    printMsg("Cipher: SIV Encrypt");
    static alc_cipher_handle_t handle;

    alc_error_t err;

    Uint8 combined_key[64] = {};
    std::copy(pAuthKey, pAuthKey + keyLen, combined_key);
    std::copy(pConfKey, pConfKey + keyLen, combined_key + keyLen);

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_aead_request(
        ALC_AES_MODE_SIV, ((Uint32)keyLen) * 8, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        free(handle.ch_context);
        return ippStsErr;
    }

    err = alcp_cipher_aead_init(
        &handle, combined_key, ((Uint32)keyLen) * 8, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD; i++) {
        err = alcp_cipher_aead_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_aead_encrypt(&handle, pSrc, pDst, len);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        return ippStsErr;
    }

    err = alcp_cipher_aead_get_tag(&handle, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        return ippStsErr;
    }

    alcp_cipher_aead_finish(&handle);

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
    printMsg("Cipher: SIV Decrypt");
    static alc_cipher_handle_t handle;

    alc_error_t err              = ALC_ERROR_NONE;
    Uint8       combined_key[64] = {};
    std::copy(pAuthKey, pAuthKey + keyLen, combined_key);
    std::copy(pConfKey, pConfKey + keyLen, combined_key + keyLen);

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_aead_request(
        ALC_AES_MODE_SIV, ((Uint32)keyLen) * 8, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        free(handle.ch_context);
        return ippStsErr;
    }

    err = alcp_cipher_aead_init(
        &handle, combined_key, ((Uint32)keyLen) * 8, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD; i++) {
        err = alcp_cipher_aead_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    err = alcp_cipher_aead_decrypt(&handle, pSrc, pDst, len);
    if (alcp_is_error(err)) {
        printf("Error: Tag Verification Failed \n");
        *pAuthPassed = false;
        return ippStsNoErr;
    }

    alcp_cipher_aead_finish(&handle);

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

    alc_error_t err;

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_aead_request(
        ALC_AES_MODE_SIV, ((Uint32)keyLen) * 8, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        free(handle.ch_context);
        return ippStsErr;
    }

    for (int i = 0; i < numAD - 1; i++) {
        err = alcp_cipher_aead_set_aad(&handle, AD[i], ADlen[i]);
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            return ippStsErr;
        }
    }

    // IV is not needed for encrypt, but still should not be NullPtr
    {
        std::vector<Uint8> fakeDest = std::vector<Uint8>(ADlen[numAD - 1]);
        err                         = alcp_cipher_aead_encrypt(
            &handle, AD[numAD - 1], &fakeDest[0], fakeDest.size());
        if (alcp_is_error(err)) {
            printf("Error: unable to encrypt \n");
            return ippStsErr;
        }
    }

    err = alcp_cipher_aead_get_tag(&handle, pSIV, 16);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        return ippStsErr;
    }

    alcp_cipher_aead_finish(&handle);

    free(handle.ch_context);

    return ippStsNoErr;
}