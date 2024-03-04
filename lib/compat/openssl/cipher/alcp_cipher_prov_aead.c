/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

// FIXME: init should be split to individual algorithm and further cleanup
// required.
static inline int
ALCP_prov_cipher_aead_encrypt_init(void*                vctx,
                                   const unsigned char* key,
                                   size_t               keylen,
                                   const unsigned char* iv,
                                   size_t               ivlen,
                                   const OSSL_PARAM     params[])
{
    ENTER();
    const OSSL_PARAM*      p;
    alc_prov_cipher_ctx_p  cctx       = vctx;
    alc_cipher_aead_info_p c_aeadinfo = &cctx->pc_cipher_aead_info;
    alc_error_t            err;

    // Locate TAG
    if (params) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->tagbuff = p->data;
            cctx->taglen  = p->data_size;
#ifdef DEBUG
            printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif
        }
        // Locate IV
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->ivlen = *((int*)(p->data));
#ifdef DEBUG
            printf("Provider: Got IVLen as :%d bytes\n", cctx->ivlen);
#endif
        }
        return 1;
    }

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key, key, (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }

    // Only for SIV allow IV to be NULL
    if ((cctx->iv == NULL) && c_aeadinfo->ci_mode != ALC_AES_MODE_SIV) {
#ifdef DEBUG
        printf("IV is NULL or Mode is not SIV Hence returning from init\n");
#endif
        return 1;
    }

    if (((cctx->is_key_assigned == false) || cctx->keylen == 0
         || cctx->ivlen == 0)) {

#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }

    // Mode Already set
    if (cctx->iv != NULL) {
        cctx->pc_cipher_aead_info.ci_iv = cctx->iv;
    }

    cctx->pc_cipher_aead_info.ci_key = cctx->key;

    // OpenSSL Speed likes to keep keylen 0
    if (cctx->keylen != 0) {
        cctx->pc_cipher_aead_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_aead_info.ci_keyLen = 128;
        cctx->pc_cipher_aead_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    alc_cipher_info_p cinfo = &cctx->pc_cipher_info;
    printf("Provider: %d keylen:%ld, key:%p\n", cinfo->ci_keyLen, keylen, key);
#endif

    // Manually allocate context
    (cctx->handle).ch_context =
        OPENSSL_malloc(alcp_cipher_aead_context_size(c_aeadinfo));

    // Request handle for the cipher
    err = alcp_cipher_aead_request(
        c_aeadinfo->ci_mode, c_aeadinfo->ci_keyLen, &(cctx->handle));

    if (alcp_is_error(err)) {
        OPENSSL_free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }

#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    // Enable Encryption Mode
    cctx->enc_flag = true;

#ifdef DEBUG
    printf("Provider: cctx->taglen: %d\n", cctx->taglen);
#endif
    cctx->add_inititalized = false;
    EXIT();

    return 1;
}

int
ALCP_prov_cipher_gcm_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: GCM\n");
    int ret = ALCP_prov_cipher_aead_encrypt_init(
        vctx, key, keylen, iv, ivlen, params);

    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ccm_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CCM\n");
    int ret = ALCP_prov_cipher_aead_encrypt_init(
        vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_siv_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: SIV\n");

    // For SIV, Authentication Key assumed to be same length as Decryption
    // Key Hence not modifying cinfo->ci_key or
    // cinfo->ci_keyLen
    // For openSSL SIV encryption and authentication key needs to be in
    // continous memory location. Second part of the key is
    // authentication key
    alc_prov_cipher_ctx_p  cctx                = vctx;
    alc_cipher_aead_info_p c_aeadinfo          = &cctx->pc_cipher_aead_info;
    alc_key_info_p         kinfo_siv_ctr_key   = &cctx->kinfo_siv_ctr_key;
    kinfo_siv_ctr_key->len                     = keylen;
    kinfo_siv_ctr_key->key                     = key + (keylen / 8);
    c_aeadinfo->ci_algo_info.ai_siv.xi_ctr_key = kinfo_siv_ctr_key;

    int ret = ALCP_prov_cipher_aead_encrypt_init(
        vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

static inline int
ALCP_prov_cipher_aead_decrypt_init(void*                vctx,
                                   const unsigned char* key,
                                   size_t               keylen,
                                   const unsigned char* iv,
                                   size_t               ivlen,
                                   const OSSL_PARAM     params[])
{
    const OSSL_PARAM*      p;
    alc_prov_cipher_ctx_p  cctx       = vctx;
    alc_cipher_aead_info_p c_aeadinfo = &cctx->pc_cipher_aead_info;

    alc_error_t err;

    // Locate TAG
    if (params) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->tagbuff = p->data;
            cctx->taglen  = p->data_size;
#ifdef DEBUG
            printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif
        }
        // Locate IV
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->ivlen = *((int*)(p->data));
#ifdef DEBUG
            printf("Provider: Got IVLen as :%d bytes\n", cctx->ivlen);
#endif
        }
        return 1;
    }

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key, key, (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }

    // Only for SIV allow IV to be NULL
    if ((cctx->iv == NULL) && c_aeadinfo->ci_mode != ALC_AES_MODE_SIV) {
#ifdef DEBUG
        printf("IV is NULL or Mode is not SIV Hence returning from init\n");
#endif
        return 1;
    }

    if (((cctx->is_key_assigned == false) || cctx->keylen == 0
         || cctx->ivlen == 0)) {

#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }

    cctx->pc_cipher_aead_info.ci_type = ALC_CIPHER_TYPE_AES;

    // Mode Already set
    if (cctx->iv != NULL) {
        cctx->pc_cipher_aead_info.ci_iv = cctx->iv;
    } else {
        // iv = OPENSSL_malloc(128); // Don't make sense
    }

    // update aead info
    cctx->pc_cipher_aead_info.ci_key = cctx->key;

    // Special handling for XTS Keylen is required if the below code is
    // ever commented out OpenSSL Speed likes to keep keylen 0
    if (keylen != 0) {
        cctx->pc_cipher_aead_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_aead_info.ci_keyLen = 128;
        cctx->pc_cipher_aead_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    alc_cipher_info_p cinfo = &cctx->pc_cipher_info;
    printf("Provider: %d keylen:%ld, key:%p\n", cinfo->ci_keyLen, keylen, iv);
#endif

    // Manually allocate context
    (cctx->handle).ch_context =
        OPENSSL_malloc(alcp_cipher_aead_context_size(c_aeadinfo));

    // Request handle for the aead
    err = alcp_cipher_aead_request(
        c_aeadinfo->ci_mode, c_aeadinfo->ci_keyLen, &(cctx->handle));

    if (err != ALC_ERROR_NONE) {
        OPENSSL_free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    // Enable Decryption Mode
    cctx->enc_flag         = false;
    cctx->add_inititalized = false;
    return 1;
}

int
ALCP_prov_cipher_ccm_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CCM\n");
    int ret = ALCP_prov_cipher_aead_decrypt_init(
        vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_gcm_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: GCM\n");
    int ret = ALCP_prov_cipher_aead_decrypt_init(
        vctx, key, keylen, iv, ivlen, params);

    alc_prov_cipher_ctx_p cctx = vctx;
    alc_error_t           err  = alcp_cipher_aead_init(&(cctx->handle),
                                            key,
                                            keylen,
                                            cctx->pc_cipher_aead_info.ci_iv,
                                            cctx->ivlen);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Error in aead init\n");
        return 0;
    }

    EXIT();
    return ret;
}

int
ALCP_prov_cipher_siv_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: SIV\n");
    alc_prov_cipher_ctx_p  cctx              = vctx;
    alc_key_info_p         kinfo_siv_ctr_key = &cctx->kinfo_siv_ctr_key;
    alc_cipher_aead_info_p c_aeadinfo        = &cctx->pc_cipher_aead_info;

    // For SIV, Authentication Key assumed to be same length as Encryption
    // Key Hence not modifying cinfo->ci_key or
    // cinfo->ci_keyLen
    // For openSSL SIV encryption and authentication key need to be in
    // continous memory location. Second part of the key is
    // authentication key
    kinfo_siv_ctr_key->len                     = keylen;
    kinfo_siv_ctr_key->key                     = key + (keylen / 8);
    c_aeadinfo->ci_algo_info.ai_siv.xi_ctr_key = kinfo_siv_ctr_key;

    int ret = ALCP_prov_cipher_aead_decrypt_init(
        vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_gcm_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    alc_prov_cipher_ctx_p cctx = vctx;
    alc_error_t           err  = ALC_ERROR_NONE;

    ENTER();
    PRINT("Provider: GCM\n");
    if (inl == 0) {
        *outl = inl;
        return 1;
    }

#ifdef DEBUG
    printf("ALCP Provider: GCM Mode Encrypt Update Call\n");
#endif
    if ((cctx->add_inititalized == false)
        && (cctx->iv != NULL && cctx->ivlen != 0)) {
        // set only iv
        err = alcp_cipher_aead_init(
            &(cctx->handle), NULL, 0, cctx->iv, cctx->ivlen);
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Error in aead init\n");
            return 0;
        }
    }
    if ((out == NULL) && (in != NULL && inl != 0)) {

        err = alcp_cipher_aead_set_aad(&(cctx->handle), in, inl);
        cctx->add_inititalized = true;
    }
    if (out != NULL && outl != 0 && in != NULL && inl != 0) {

        if (cctx->enc_flag) {

            err = alcp_cipher_aead_encrypt_update(
                &(cctx->handle), in, out, inl, cctx->iv);
        } else {
            err = alcp_cipher_aead_decrypt_update(
                &(cctx->handle), in, out, inl, cctx->iv);
        }
    }

    if (err != ALC_ERROR_NONE) {
        const int err_size = 256;
        Uint8     err_buf[err_size];
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%10" PRId64 "%p\n", (void*)in, inl, (void*)out);
        printf("%d\n", cctx->pc_cipher_info.ci_mode == ALC_AES_MODE_GCM);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    EXIT();
    *outl = inl;
    return 1;
}

int
ALCP_prov_cipher_ccm_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    alc_prov_cipher_ctx_p cctx = vctx;
    alc_error_t           err  = ALC_ERROR_NONE;

    ENTER();
    PRINT("Provider: CCM\n");
    if (inl == 0) {
        *outl = inl;
        return 1;
    }

    if (out == NULL && outl != NULL && in != NULL) { // AAD call
        cctx->aadlen = inl;
        cctx->aad    = in;
    } else if (out != NULL && outl != NULL && in != NULL) {
        if (cctx->taglen != 0) {
            err =
                alcp_cipher_aead_set_tag_length(&(cctx->handle), cctx->taglen);
            if (err != ALC_ERROR_NONE)
                goto out;
        }

        err = alcp_cipher_aead_init(
            &(cctx->handle), NULL, 0, cctx->iv, cctx->ivlen);
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Error in aead init\n");
            goto out;
        }

        if (err != ALC_ERROR_NONE)
            goto out;
        if (cctx->aadlen != 0) {
            err = alcp_cipher_aead_set_aad(
                &(cctx->handle), cctx->aad, cctx->aadlen);
            if (err != ALC_ERROR_NONE)
                goto out;
        }
        cctx->add_inititalized = true;

        if (cctx->enc_flag) {
            err = alcp_cipher_aead_encrypt_update(
                &(cctx->handle), in, out, inl, cctx->pc_cipher_aead_info.ci_iv);
        } else {
            err = alcp_cipher_aead_decrypt_update(
                &(cctx->handle), in, out, inl, cctx->pc_cipher_aead_info.ci_iv);
        }
    }
out:
    if (err != 0) {
        const int err_size = 256;
        Uint8     err_buf[err_size];
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%10" PRId64 "%p\n", (void*)in, inl, (void*)out);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    EXIT();
    *outl = inl;
    return 1;
}

int
ALCP_prov_cipher_siv_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    alc_prov_cipher_ctx_p cctx     = vctx;
    alc_error_t           err      = ALC_ERROR_NONE;
    const int             err_size = 256;
    Uint8                 err_buf[err_size];

    ENTER();
    PRINT("Provider: SIV\n");
    if (inl == 0) {
        *outl = inl;
        return 1;
    }

    if (out == NULL) {
        err = alcp_cipher_aead_set_aad(&(cctx->handle), in, inl);
    } else {
        if (cctx->enc_flag) {
            Uint8 fake_iv[100] = { 0 };
            err                = alcp_cipher_aead_encrypt(
                &(cctx->handle), in, out, inl, fake_iv);
        } else {
            // IV must be copied to cctx->tagbuff when application calls
            // EVP_CIPHER_CTX_ctrl call with EVP_CTRL_AEAD_SET_TAG. This
            // is done in ALCP_prov_cipher_set_ctx_params call.
            if (cctx->is_openssl_speed_siv && cctx->tagbuff == NULL) {
                Uint8 tag[16] = { 0 };
                alcp_cipher_decrypt(&(cctx->handle), in, out, inl, tag);
                // Ignoring the error code returned here as tag wont match for
                // openssl speed SIV since tagbuff is empty.
            } else {

                err = alcp_cipher_decrypt(
                    &(cctx->handle), in, out, inl, cctx->tagbuff);
            }
        }
    }

    if (err != ALC_ERROR_NONE) {
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%10" PRId64 "%p\n", (void*)in, inl, (void*)out);
        printf("%d\n", cctx->pc_cipher_info.ci_mode == ALC_AES_MODE_CFB);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    EXIT();
    *outl = inl;
    return 1;
}
