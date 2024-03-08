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
#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

void
ALCP_prov_cipher_freectx(void* vctx)
{
    ENTER();
    alc_prov_cipher_ctx_t* pcctx = vctx;

    if (pcctx->handle.ch_context != NULL) {
        alcp_cipher_finish(&pcctx->handle);
        OPENSSL_free(pcctx->handle.ch_context);
        pcctx->handle.ch_context = NULL;
    }

    OPENSSL_free(vctx);
    vctx = NULL;
    EXIT();
}

void*
ALCP_prov_cipher_newctx(void* vprovctx, const void* cinfo, bool is_aead)
{
    alc_prov_cipher_ctx_t* ciph_ctx;
    alc_prov_ctx_p         pctx = (alc_prov_ctx_p)vprovctx;

    ENTER();
    ciph_ctx = OPENSSL_zalloc(sizeof(*ciph_ctx));

    if (ciph_ctx != NULL) {
        ciph_ctx->pc_prov_ctx = pctx;
        ciph_ctx->pc_libctx   = pctx->ap_libctx;
        if (is_aead) {
            ciph_ctx->is_aead             = true;
            ciph_ctx->pc_cipher_aead_info = *((alc_cipher_aead_info_t*)cinfo);
            ciph_ctx->finalized           = false;

        } else {
            ciph_ctx->is_aead        = false;
            ciph_ctx->pc_cipher_info = *((alc_cipher_info_t*)cinfo);
        }
        ciph_ctx->is_key_assigned      = false;
        ciph_ctx->ivlen                = -1;
        ciph_ctx->is_openssl_speed_siv = false;
    }

    return ciph_ctx;
}

void*
ALCP_prov_cipher_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implement
    alc_prov_cipher_ctx_t* csrc = vctx;
    EXIT();
    return csrc;
}

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_cipher_gettable_params(void* provctx)
{
    EXIT();
    return cipher_known_gettable_params;
}

int
ALCP_prov_cipher_get_params(OSSL_PARAM params[],
                            int        mode,
                            int        key_size,
                            bool       is_aead)
{
    OSSL_PARAM* p;
    int         kbits   = key_size;
    int         blkbits = 128;
    int         ivbits  = is_aead ? 96 : 128;

    ENTER();

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, is_aead ? 1 : 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    EXIT();
    return 1;
}

const OSSL_PARAM*
ALCP_prov_cipher_gettable_ctx_params(void* cctx, void* provctx)
{
    return cipher_known_gettable_params;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_cipher_settable_ctx_params(void* cctx, void* provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END,
    };
    EXIT();
    return table;
}

int
ALCP_prov_cipher_set_params(const OSSL_PARAM params[])
{
    ENTER();
    return 1;
}

int
ALCP_prov_cipher_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    OSSL_PARAM*            p;
    alc_prov_cipher_ctx_t* cctx   = (alc_prov_cipher_ctx_t*)vctx;
    size_t                 keylen = 0;
    if (cctx->is_aead) {
        keylen = cctx->pc_cipher_aead_info.ci_keyLen;

    } else {
        keylen = cctx->pc_cipher_info.ci_keyLen;
    }

    ENTER();
    int ivlen = (cctx->ivlen < 0)
                    ? 16
                    : cctx->ivlen; // cctx->ivlen < 0 means ivlen was never set.
                                   // For non-AEAD modes default iv length is 16
                                   // and for AEAD modes default iv length is 12
    if ((cctx->ivlen < 0) && cctx->is_aead) {
        ivlen = 12;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    if (keylen > 0
        && (p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "tag")) != NULL) {
        const void* tag;
        size_t      used_length;
        if (!OSSL_PARAM_get_octet_string_ptr(params, &tag, &used_length)) {
            printf("Provider: An error has occurred\n");
        }
#ifdef DEBUG
        printf("Provider: Size is %ld and tag is %p\n", used_length, tag);
#endif
        cctx->taglen = used_length;
        if (!cctx->add_inititalized
            && (cctx->is_aead
                && (cctx->pc_cipher_aead_info.ci_mode == ALC_AES_MODE_CCM))) {
            Uint8 a;
            alcp_cipher_aead_set_tag_length(&(cctx->handle), cctx->taglen);

            alc_error_t err = alcp_cipher_aead_init(&(cctx->handle),
                                                    cctx->pc_cipher_info.ci_key,
                                                    keylen,
                                                    cctx->iv,
                                                    cctx->ivlen);
            if (err != ALC_ERROR_NONE) {
                printf("Provider: Error in aead init\n");
                return 0;
            }

            if (cctx->aadlen != 0)
                alcp_cipher_aead_set_aad(
                    &(cctx->handle), cctx->aad, cctx->aadlen);
            cctx->add_inititalized = true;
            alcp_cipher_aead_encrypt_update(&(cctx->handle), &a, &a, 0);
        }
        alc_error_t err =
            alcp_cipher_aead_get_tag(&(cctx->handle), (Uint8*)tag, used_length);
        if (alcp_is_error(err)) {
            printf("ALCP Provider: Error while getting GCM Tag\n");
            return 1;
        }
    }

    EXIT();
    return 1;
}

int
ALCP_prov_cipher_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM*      p;
    alc_prov_cipher_ctx_t* cctx = (alc_prov_cipher_ctx_t*)vctx;
    ENTER();

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;
        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
        if (cctx->is_aead) {
            cctx->pc_cipher_aead_info.ci_keyLen = keylen;

        } else {

            cctx->pc_cipher_info.ci_keyLen = keylen;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen;
        if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
#ifdef DEBUG
        printf("Provider: IVLEN Length is %ld \n", ivlen);
#endif
        cctx->ivlen = ivlen;
    }

    // Getting the Tag for AEAD including SIV
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            printf("Provider: TAG is in wrong format!\n");
            return 0;
        }
        cctx->tagbuff = p->data;
        cctx->taglen  = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, (int*)&cctx->is_openssl_speed_siv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
    }

#ifdef DEBUG
    printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif

    EXIT();
    return 1;
}

static inline int
ALCP_prov_cipher_aes_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    alc_prov_cipher_ctx_t* cctx  = vctx;
    alc_cipher_info_t*     cinfo = &cctx->pc_cipher_info;
    alc_error_t            err;

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key,
               key,
               (cinfo->ci_mode == ALC_AES_MODE_XTS ? 2 : 1)
                   * (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }

    if (((cctx->is_key_assigned == false) || (cctx->iv == NULL)
         || (cctx->keylen == 0) || (cctx->ivlen == 0))) {

#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }

    cctx->pc_cipher_info.ci_iv  = cctx->iv;
    cctx->pc_cipher_info.ci_key = cctx->key;

    // OpenSSL Speed likes to keep keylen 0
    if (cctx->keylen != 0) {
        cctx->pc_cipher_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_info.ci_keyLen = 128;
        cctx->pc_cipher_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n",
           cinfo->ci_keyLen,
           keylen,
           cctx->key);
#endif

    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        if (!((keylen == 128) || (keylen == 256))) {

#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with error
            return 0;
        }
    }

    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size());

    // Request handle for the cipher
    err =
        alcp_cipher_request(cinfo->ci_mode, cinfo->ci_keyLen, &(cctx->handle));

    if (err != ALC_ERROR_NONE) {
        free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (cctx->pc_cipher_info.ci_iv != NULL) {
#ifdef DEBUG
            printf("Provider: Setting iv length as %ld from %d\n",
                   ivlen,
                   cctx->ivlen);
#endif
            if (ivlen == 0) {
                cctx->ivlen = 16;
            } else {
                cctx->ivlen = ivlen;
            }
        }
    }

    err = alcp_cipher_init(&(cctx->handle),
                           cinfo->ci_key,
                           cinfo->ci_keyLen,
                           cinfo->ci_iv,
                           cctx->ivlen);
    if (alcp_is_error(err)) {
        printf("Error in cipher init\n");
        return 0;
    }

    // Enable Encryption Mode
    cctx->enc_flag         = true;
    cctx->add_inititalized = false;
    return 1;
}

int
ALCP_prov_cipher_cfb_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CFB\n");
    int err =
        ALCP_prov_cipher_aes_encrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();

    return err;
}

int
ALCP_prov_cipher_cbc_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CBC\n");
    int ret =
        ALCP_prov_cipher_aes_encrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ofb_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: OFB\n");
    int ret =
        ALCP_prov_cipher_aes_encrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ctr_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CTR\n");
    int ret =
        ALCP_prov_cipher_aes_encrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_xts_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: XTS\n");
    int ret =
        ALCP_prov_cipher_aes_encrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

static inline int
ALCP_prov_cipher_aes_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    alc_prov_cipher_ctx_t* cctx  = vctx;
    alc_cipher_info_t*     cinfo = &cctx->pc_cipher_info;

    alc_error_t err;

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key,
               key,
               (cinfo->ci_mode == ALC_AES_MODE_XTS ? 2 : 1)
                   * (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }
    if (((cctx->is_key_assigned == false) || (cctx->iv == NULL)
         || (cctx->keylen == 0) || (cctx->ivlen == 0))) {
#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }
    cctx->pc_cipher_info.ci_type = ALC_CIPHER_TYPE_AES;

    // Mode Already set
    if (cctx->iv != NULL) {
        cctx->pc_cipher_info.ci_iv = cctx->iv;
    } else {
        // FIXME:return error!
    }

    cctx->pc_cipher_info.ci_key = cctx->key;

    if (cctx->keylen != 0) {
        cctx->pc_cipher_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_info.ci_keyLen = 128;
        cctx->pc_cipher_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n", cinfo->ci_keyLen, keylen, iv);
#endif

    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        if (!((keylen == 128) || (keylen == 256))) {

#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with error
            return 0;
        }
    }

    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size());

    // Request handle for the cipher
    err =
        alcp_cipher_request(cinfo->ci_mode, cinfo->ci_keyLen, &(cctx->handle));
    if (err != ALC_ERROR_NONE) {
        free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (cctx->pc_cipher_info.ci_iv != NULL) {
#ifdef DEBUG
            printf("Provider: Setting iv length as %ld from %d\n",
                   ivlen,
                   cctx->ivlen);
#endif
            if (ivlen == 0) {
                cctx->ivlen = 16;
            } else {
                cctx->ivlen = ivlen;
            }
        }
    }

    err = alcp_cipher_init(&(cctx->handle),
                           cinfo->ci_key,
                           cinfo->ci_keyLen,
                           cinfo->ci_iv,
                           cctx->ivlen);
    if (alcp_is_error(err)) {
        printf("Error in cipher init\n");
        return 0;
    }

    // Enable Decryption Mode
    cctx->enc_flag = false;

    cctx->add_inititalized = false;
    EXIT();
    return 1;
}

int
ALCP_prov_cipher_cfb_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CFB\n");
    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ofb_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: OFB\n");
    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_cbc_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CBC\n");
    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ctr_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CTR\n");
    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_xts_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: XTS \n");

    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);

    EXIT();
    return ret;
}

static inline int
ALCP_prov_cipher_update(void*                vctx,
                        unsigned char*       out,
                        size_t*              outl,
                        size_t               outsize,
                        const unsigned char* in,
                        size_t               inl)
{
    alc_prov_cipher_ctx_t* cctx = vctx;
    alc_error_t            err  = ALC_ERROR_NONE;

    if (inl == 0) {
        *outl = inl;
        return 1;
    }

    if (cctx->enc_flag) {
        err = alcp_cipher_encrypt(&(cctx->handle), in, out, inl);
    } else {
        err = alcp_cipher_decrypt(&(cctx->handle), in, out, inl);
    }

    if (err != ALC_ERROR_NONE) {
        const int err_size = 256;
        Uint8     err_buf[err_size];
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%10" PRId64 "%p\n", (void*)in, inl, (void*)out);
        printf("%d\n", cctx->pc_cipher_info.ci_mode == ALC_AES_MODE_CFB);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    *outl = inl;
    return 1;
}
int
ALCP_prov_cipher_cfb_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: CFB\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_cbc_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: CBC\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ofb_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: OFB\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_ctr_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: CTR\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_xts_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: XTS\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}

int
ALCP_prov_cipher_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    ENTER();
    // alc_prov_cipher_ctx_t* cctx = vctx;

    // TODO: Introduce Finish here for finalising the context and
    // handle the corresponding memory issues.
    // alcp_cipher_finish(&cctx->handle);
    // Nothing to do!
    *outl                       = 0;
    int                    ret  = 1;
    alc_prov_cipher_ctx_t* cctx = vctx;
    if ((cctx->is_aead) && (cctx->tagbuff != NULL) && (cctx->taglen != 0)) {
        Uint8       tag[16]; // 16 is maximum tag length
        alc_error_t err =
            alcp_cipher_aead_get_tag(&(cctx->handle), tag, cctx->taglen);
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Error occurred in finalize while getting AEAD "
                   "Tag\n");
            ret = 0;
        }
        if (memcmp(cctx->tagbuff, tag, cctx->taglen)) {
            // Tag mismatch, hence finalize should return failure
            ret = 0;
        }
    }
    cctx->finalized = true;
    return ret;
}

static const char    CIPHER_DEF_PROP[]  = "provider=alcp,fips=no";
const OSSL_ALGORITHM ALC_prov_ciphers[] = {
    // CFB
    { ALCP_PROV_NAMES_AES_256_CFB, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB1, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB1, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB1, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB8, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB8, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB8, CIPHER_DEF_PROP, cfb_functions_128 },

// FIXME: Enable CBC and CTR after adding multi update APIs as enabling them
// is causing TLS Handshake failure in OpenSSL
#if 0
// CTR
    // Enabling CTR does not cause any failures but since OpenSSL is calling ALCP
    // CTR for CTR-DRBG its not proper to enable CTR without multi update API
    {ALCP_PROV_NAMES_AES_256_CTR, CIPHER_DEF_PROP, ctr_functions_256 },
    {ALCP_PROV_NAMES_AES_192_CTR, CIPHER_DEF_PROP, ctr_functions_192 },
    {ALCP_PROV_NAMES_AES_128_CTR, CIPHER_DEF_PROP, ctr_functions_128 },
// CBC
    // { ALCP_PROV_NAMES_AES_256_CBC, CIPHER_DEF_PROP, cbc_functions_256 },
    // { ALCP_PROV_NAMES_AES_192_CBC, CIPHER_DEF_PROP, cbc_functions_192 },
    // { ALCP_PROV_NAMES_AES_128_CBC, CIPHER_DEF_PROP, cbc_functions_128 },
#endif
    // OFB
    { ALCP_PROV_NAMES_AES_256_OFB, CIPHER_DEF_PROP, ofb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_OFB, CIPHER_DEF_PROP, ofb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_OFB, CIPHER_DEF_PROP, ofb_functions_128 },

/* ECB is disabled since ALCP does not support it. So all ECB calls will \
fall back to OpenSSL default provider */

#if 0
    { ALCP_PROV_NAMES_AES_256_ECB, CIPHER_DEF_PROP, ecb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_ECB, CIPHER_DEF_PROP, ecb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_ECB, CIPHER_DEF_PROP, ecb_functions_128 },

    // XTS
    { ALCP_PROV_NAMES_AES_256_XTS, CIPHER_DEF_PROP, xts_functions_256 },
    { ALCP_PROV_NAMES_AES_128_XTS, CIPHER_DEF_PROP, xts_functions_128 },
#endif
    // GCM
    { ALCP_PROV_NAMES_AES_128_GCM, CIPHER_DEF_PROP, gcm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_GCM, CIPHER_DEF_PROP, gcm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_GCM, CIPHER_DEF_PROP, gcm_functions_256 },

#if 0
    // CCM
    { ALCP_PROV_NAMES_AES_128_CCM, CIPHER_DEF_PROP, ccm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_CCM, CIPHER_DEF_PROP, ccm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_CCM, CIPHER_DEF_PROP, ccm_functions_256 },
    // SIV
    { ALCP_PROV_NAMES_AES_128_SIV, CIPHER_DEF_PROP, siv_functions_128 },
    { ALCP_PROV_NAMES_AES_192_SIV, CIPHER_DEF_PROP, siv_functions_192 },
    { ALCP_PROV_NAMES_AES_256_SIV, CIPHER_DEF_PROP, siv_functions_256 },
#endif
    // Terminate OpenSSL Algorithm list with Null Pointer.
    { NULL, NULL, NULL },
};

// FIXME: Refactor, offload some functionality to this function
EVP_CIPHER*
ALCP_prov_cipher_init(alc_prov_ctx_p cc)
{
    /* FIXME: this could be wrong */
    alc_prov_cipher_ctx_t* c = (alc_prov_cipher_ctx_t*)cc;

    ENTER();

    /* Some sanity checking. */
    int flags = c->pc_flags;
    switch (flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CTR_MODE:
        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:
            break;
        default:
            break;
    }

    EVP_CIPHER* tmp = NULL;
    return tmp;
}
