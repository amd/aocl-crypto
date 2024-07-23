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

#include "alcp_cipher_prov_aead.h"
#include "alcp_cipher_prov_common.h"
#include "provider/alcp_provider.h"

#define siv_stream_update siv_cipher
#define SIV_FLAGS         AEAD_FLAGS
#define SIV_LEN           16
static int
aes_siv_set_ctx_params(void* vctx, const OSSL_PARAM params[]);

void
ALCP_prov_siv_initctx(void*              provctx,
                      ALCP_PROV_AES_CTX* ctx,
                      size_t             keybits,
                      alc_cipher_mode_t  mode)
{
    ENTER();
    alc_prov_cipher_data_t* cipherctx = &(ctx->base.prov_cipher_data);

    cipherctx->tagLength       = SIV_LEN;
    cipherctx->mode            = mode;
    cipherctx->keyLen_in_bytes = keybits / 8;
    EXIT();
}

static void*
ALCP_prov_aes_siv_newctx(void*        provctx,
                         size_t       keybits,
                         unsigned int mode,
                         uint64_t     flags)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {

        // allocate context
        ctx->base.handle.ch_context =
            OPENSSL_malloc(alcp_cipher_aead_context_size());

        if (ctx->base.handle.ch_context == NULL) {
            printf("\n context allocation failed ");
            OPENSSL_clear_free(ctx, sizeof(*ctx));
            return NULL;
        }

        // Request handle for the cipher
        alc_error_t err = alcp_cipher_aead_request(
            ALC_AES_MODE_SIV, keybits / 2, &(ctx->base.handle));

        if (alcp_is_error(err)) {
            printf("Failure in SIV AEAD Request\n");
        }

        if (err == ALC_ERROR_NONE) {
            ALCP_prov_siv_initctx(provctx, ctx, keybits, mode);
        } else {
            OPENSSL_clear_free(ctx, sizeof(*ctx));
            return NULL;
        }
    }
    EXIT();
    return ctx;
}

static void
aes_siv_freectx(void* vctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx = (ALCP_PROV_AES_CTX*)vctx;
    if ((ctx != NULL) && (ctx->base.handle.ch_context != NULL)) {
        // free alcp
        alcp_cipher_finish(&(ctx->base.handle));
        OPENSSL_free(ctx->base.handle.ch_context);
        ctx->base.handle.ch_context = NULL;
    }
    OPENSSL_free(ctx);
    EXIT();
}

// FIXME: Revisit once ALCP Copy API has been implemented
static void*
siv_dupctx(void* vctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx  = (ALCP_PROV_AES_CTX*)vctx;
    ALCP_PROV_AES_CTX* dctx = NULL;

    dctx = OPENSSL_malloc(sizeof(*dctx));
    if (dctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    // if (dctx != NULL && dctx->base.prov_cipher_data->pKey != NULL)
    //     dctx->base.prov_cipher_data->pKey = (const Uint8*)&dctx->ks;
    EXIT();
    return dctx;
}

static int
siv_init(void*                vctx,
         const unsigned char* key,
         size_t               keylen,
         const unsigned char* iv,
         size_t               ivlen,
         const OSSL_PARAM     params[],
         int                  enc)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    cipherctx->enc = enc;

    if (key != NULL) {
        if (keylen != cipherctx->keyLen_in_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), key, cipherctx->keyLen_in_bytes * 8 / 2, NULL, 0);
        if (alcp_is_error(err)) {
            return 0;
        }
    }
    int ret = aes_siv_set_ctx_params(ctx, params);
    EXIT();
    return ret;
}

static int
siv_einit(void*                vctx,
          const unsigned char* key,
          size_t               keylen,
          const unsigned char* iv,
          size_t               ivlen,
          const OSSL_PARAM     params[])
{
    ENTER();
    int ret = siv_init(vctx, key, keylen, iv, ivlen, params, 1);
    EXIT();
    return ret;
}

static int
siv_dinit(void*                vctx,
          const unsigned char* key,
          size_t               keylen,
          const unsigned char* iv,
          size_t               ivlen,
          const OSSL_PARAM     params[])
{
    ENTER();
    int ret = siv_init(vctx, key, keylen, iv, ivlen, params, 0);
    EXIT();
    return ret;
}

static int
siv_cipher(void*                vctx,
           unsigned char*       out,
           size_t*              outl,
           size_t               outsize,
           const unsigned char* in,
           size_t               inl)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    /* Not AAD, just input and output empty calls to be ignored */
    if (out != NULL) {
        if (inl == 0) {
            if (outl != NULL)
                *outl = 0;
            return 1;
        }

        if (outsize < inl) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    } else {
        if (in != NULL) {
            if (alcp_cipher_aead_set_aad(&(ctx->handle), in, inl)) {
                printf("Error Occured in SIV setting AEAD\n");
                return 0;
            }
        }
    }
    if (in != NULL && out != NULL) {

        alc_error_t err = ALC_ERROR_NONE;
        if (cipherctx->enc) {
            err = alcp_cipher_aead_encrypt(&(ctx->handle), in, out, inl);
        } else {
            err = alcp_cipher_aead_decrypt(&(ctx->handle), in, out, inl);
        }
        if (alcp_is_error(err)) {
            return 0;
        }
    }

    if (outl != NULL)
        *outl = inl;
    EXIT();
    return 1;
}

static int
siv_stream_final(void* vctx, unsigned char* out, size_t* outl, size_t outsize)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    alc_error_t err = alcp_cipher_aead_get_tag(
        &(ctx->handle), cipherctx->buf, cipherctx->tagLength);
    if (alcp_is_error(err)) {
        return 0;
    }
    if (outl != NULL)
        *outl = 0;
    EXIT();
    return 1;
}

static int
aes_siv_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING) {
        if (!cipherctx->enc || p->data_size != cipherctx->tagLength
            || !OSSL_PARAM_set_octet_string(
                p, cipherctx->buf, cipherctx->tagLength)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->tagLength)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->keyLen_in_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    EXIT();
    return 1;
}

static const OSSL_PARAM aes_siv_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
aes_siv_gettable_ctx_params(ossl_unused void* cctx, ossl_unused void* provctx)
{
    ENTER();
    const OSSL_PARAM* ret = aes_siv_known_gettable_ctx_params;
    EXIT();
    return ret;
}

static int
aes_siv_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    const OSSL_PARAM* p;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (cipherctx->enc)
            return 1;
        memcpy(cipherctx->buf, p->data, p->data_size);
        cipherctx->tagLength = p->data_size;
        if (alcp_cipher_aead_init(&(ctx->handle),
                                  NULL,
                                  0,
                                  cipherctx->buf,
                                  cipherctx->tagLength)) {
            return 0;
        }
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            // Need to keep the tag buffer in the provider.
        ) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    // p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
    // if (p != NULL) {
    //     if (!OSSL_PARAM_get_uint(p, &speed)) {
    //         ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
    //         return 0;
    //     }
    //
    // }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The key length can not be modified */
        if (keylen != cipherctx->keyLen_in_bytes)
            return 0;
    }
    EXIT();
    return 1;
}

static const OSSL_PARAM aes_siv_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_SPEED, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
aes_siv_settable_ctx_params(ossl_unused void* cctx, ossl_unused void* provctx)
{
    ENTER();
    const OSSL_PARAM* ret = aes_siv_known_settable_ctx_params;
    return ret;
    EXIT();
}

#define IMPLEMENT_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)         \
    static OSSL_FUNC_cipher_newctx_fn         alg##kbits##lc##_newctx;           \
    static OSSL_FUNC_cipher_freectx_fn        alg##_##lc##_freectx;              \
    static OSSL_FUNC_cipher_dupctx_fn         lc##_dupctx;                       \
    static OSSL_FUNC_cipher_encrypt_init_fn   lc##_einit;                        \
    static OSSL_FUNC_cipher_decrypt_init_fn   lc##_dinit;                        \
    static OSSL_FUNC_cipher_update_fn         lc##_stream_update;                \
    static OSSL_FUNC_cipher_final_fn          lc##_stream_final;                 \
    static OSSL_FUNC_cipher_cipher_fn         lc##_cipher;                       \
    static OSSL_FUNC_cipher_get_params_fn     alg##_##kbits##_##lc##_get_params; \
    static OSSL_FUNC_cipher_get_ctx_params_fn alg##_##lc##_get_ctx_params;       \
    static OSSL_FUNC_cipher_gettable_ctx_params_fn                               \
                                              alg##_##lc##_gettable_ctx_params;  \
    static OSSL_FUNC_cipher_set_ctx_params_fn alg##_##lc##_set_ctx_params;       \
    static OSSL_FUNC_cipher_settable_ctx_params_fn                               \
               alg##_##lc##_settable_ctx_params;                                 \
    static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])            \
    {                                                                            \
        ENTER();                                                                 \
        int ret =                                                                \
            ALCP_prov_cipher_generic_get_params(params,                          \
                                                EVP_CIPH_##UCMODE##_MODE,        \
                                                flags,                           \
                                                2 * kbits,                       \
                                                blkbits,                         \
                                                ivbits);                         \
        return ret;                                                              \
        EXIT();                                                                  \
    }                                                                            \
    static void* alg##kbits##lc##_newctx(void* provctx)                          \
    {                                                                            \
        ENTER();                                                                 \
        void* ret = ALCP_prov_##alg##_##lc##_newctx(                             \
            provctx, 2 * kbits, EVP_CIPH_##UCMODE##_MODE, flags);                \
        return ret;                                                              \
        EXIT();                                                                  \
    }                                                                            \
    const OSSL_DISPATCH ALCP_prov_##alg##kbits##lc##_functions[] = {             \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },    \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_##lc##_freectx },      \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))lc##_dupctx },                \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))lc##_einit },           \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))lc##_dinit },           \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))lc##_stream_update },         \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))lc##_stream_final },           \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))lc##_cipher },                \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                           \
          (void (*)(void))alg##_##kbits##_##lc##_get_params },                   \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                      \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_params },            \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                       \
          (void (*)(void))alg##_##lc##_get_ctx_params },                         \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                  \
          (void (*)(void))alg##_##lc##_gettable_ctx_params },                    \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                       \
          (void (*)(void))alg##_##lc##_set_ctx_params },                         \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                  \
          (void (*)(void))alg##_##lc##_settable_ctx_params },                    \
        { 0, NULL }                                                              \
    };

IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 128, 8, 0)
    IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 192, 8, 0)
        IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 256, 8, 0)
