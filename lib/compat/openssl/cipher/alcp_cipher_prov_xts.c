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

#include "alcp_cipher_prov_common.h"
#include "cipher/alcp_cipher_aes.h"
#include <openssl/aes.h>
#include <openssl/modes.h>

#define AES_XTS_FLAGS      PROV_CIPHER_FLAG_CUSTOM_IV
#define AES_XTS_IV_BITS    128
#define AES_XTS_BLOCK_BITS 8

#define XTS_MAX_BLOCKS_PER_DATA_UNIT (1 << 20)

static void*
alcp_prov_aes_xts_dupctx(void* ctx)
{
    ALCP_PROV_CIPHER_CTX* ret;

    // TODO: Check if Provider is running

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    // TODO: Copy the ALCP context and classes once Copy API has been
    // implemented

    return ret;
}

static void*
alcp_prov_aes_xts_newctx(void*        provctx,
                         unsigned int mode,
                         uint64_t     flags,
                         size_t       kbits,
                         size_t       blkbits,
                         size_t       ivbits)
{
    ENTER();
    // TODO: Check if Provider is running
    ALCP_PROV_CIPHER_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->handle.ch_context = OPENSSL_malloc(alcp_cipher_context_size());
        if (ctx->handle.ch_context == NULL) {
            PRINT("\n context allocation failed ");
            return NULL;
        }
        alc_error_t err =
            alcp_cipher_request(ALC_AES_MODE_XTS, kbits / 2, &(ctx->handle));
        ctx->prov_cipher_data = ctx->prov_cipher_data;

        if (err == ALC_ERROR_NONE) {
            if (ctx != ((void*)0)) {
                ALCP_prov_cipher_generic_initkey(ctx,
                                                 kbits,
                                                 blkbits,
                                                 ivbits,
                                                 EVP_CIPH_XTS_MODE,
                                                 flags,
                                                 provctx);
            }
        } else {
            PRINT("CIPHER PROVIDER: Error in alcp_cipher_request")
            OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
    }
    EXIT();
    return ctx;
}

static int
alc_prov_aes_xts_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    const OSSL_PARAM*     p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (keylen != ctx->prov_cipher_data.keyLen_in_bytes)
            return 0;
    }
    EXIT();
    return 1;
}

static int
alc_prov_aes_xts_init(void*                vctx,
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
    cipherctx->enc                    = enc;

    if (iv != NULL) {
        if (!ALCP_prov_cipher_generic_initiv(
                (ALCP_PROV_CIPHER_CTX*)vctx, iv, ivlen)) {
            return 0;
        }
    }

    if ((key != NULL)) {
        if (keylen != cipherctx->keyLen_in_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        alc_error_t err =
            alcp_cipher_init(&(((ALCP_PROV_CIPHER_CTX*)vctx)->handle),
                             key,
                             (cipherctx->keyLen_in_bytes / 2) * 8,
                             cipherctx->iv_buff,
                             cipherctx->ivLen);
        if (alcp_is_error(err)) {
            PRINT("CIPHER PROVIDER: Error in alcp_cipher_init")
            return 0;
        }
    }

    int ret = alc_prov_aes_xts_set_ctx_params(vctx, params);
    EXIT();
    return ret;
}

static int
alc_prov_aes_xts_einit(void*                vctx,
                       const unsigned char* key,
                       size_t               keylen,
                       const unsigned char* iv,
                       size_t               ivlen,
                       const OSSL_PARAM     params[])
{
    ENTER();
    int ret = alc_prov_aes_xts_init(vctx, key, keylen, iv, ivlen, params, 1);
    EXIT();
    return ret;
}

static int
alc_prov_aes_xts_dinit(void*                vctx,
                       const unsigned char* key,
                       size_t               keylen,
                       const unsigned char* iv,
                       size_t               ivlen,
                       const OSSL_PARAM     params[])
{
    ENTER();
    int ret = alc_prov_aes_xts_init(vctx, key, keylen, iv, ivlen, params, 0);
    return ret;
    EXIT();
}

static int
alc_prov_aes_xts_cipher(void*                vctx,
                        unsigned char*       out,
                        size_t*              outl,
                        size_t               outsize,
                        const unsigned char* in,
                        size_t               inl)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    if (!cipherctx->ivState || out == NULL || in == NULL
        || inl < AES_BLOCK_SIZE)
        return 0;

    if (inl > XTS_MAX_BLOCKS_PER_DATA_UNIT * AES_BLOCK_SIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE);
        return 0;
    }

    alc_error_t err = ALC_ERROR_NONE;

    if (cipherctx->enc) {
        err = alcp_cipher_encrypt(&(ctx->handle), in, out, inl);
    } else {
        err = alcp_cipher_decrypt(&(ctx->handle), in, out, inl);
    }
    if (alcp_is_error(err)) {
        PRINT(
            "CIPHER PROVIDER: Error in alcp_cipher_encrypt/alcp_cipher_decrypt")
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    EXIT();
    return 1;
}

static int
alc_prov_aes_xts_stream_update(void*                vctx,
                               unsigned char*       out,
                               size_t*              outl,
                               size_t               outsize,
                               const unsigned char* in,
                               size_t               inl)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!alc_prov_aes_xts_cipher(ctx, out, outl, outsize, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    EXIT();
    return 1;
}

static int
alc_prov_aes_xts_stream_final(void*          vctx,
                              unsigned char* out,
                              size_t*        outl,
                              size_t         outsize)
{
    ENTER();
    // TODO: Check if Provider is running
    *outl = 0;
    EXIT();
    return 1;
}

static const OSSL_PARAM alcp_prov_aes_xts_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM*
alc_prov_aes_xts_settable_ctx_params(ossl_unused void* cctx,
                                     ossl_unused void* provctx)
{
    ENTER();
    const OSSL_PARAM* param = alcp_prov_aes_xts_known_settable_ctx_params;
    EXIT();
    return param;
}

static void
alc_prov_aes_xts_freectx(void* vctx)
{
    ENTER();
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    // free alcp
    if (ctx->handle.ch_context != NULL) {
        alcp_cipher_finish(&(ctx->handle));
        OPENSSL_free(ctx->handle.ch_context);
        ctx->handle.ch_context = NULL;
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
    EXIT();
}

#define IMPLEMENT_cipher(lcmode, UCMODE, kbits, flags)                         \
    static OSSL_FUNC_cipher_get_params_fn                                      \
               alc_prov_aes_##kbits##_##lcmode##_get_params;                   \
    static int alc_prov_aes_##kbits##_##lcmode##_get_params(                   \
        OSSL_PARAM params[])                                                   \
    {                                                                          \
        ENTER();                                                               \
        int ret =                                                              \
            ALCP_prov_cipher_generic_get_params(params,                        \
                                                EVP_CIPH_##UCMODE##_MODE,      \
                                                flags,                         \
                                                2 * kbits,                     \
                                                AES_XTS_BLOCK_BITS,            \
                                                AES_XTS_IV_BITS);              \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
    static OSSL_FUNC_cipher_newctx_fn alc_prov_aes_##kbits##_xts_newctx;       \
    static void* alc_prov_aes_##kbits##_xts_newctx(void* provctx)              \
    {                                                                          \
        ENTER();                                                               \
        void* ret = alcp_prov_aes_xts_newctx(provctx,                          \
                                             EVP_CIPH_##UCMODE##_MODE,         \
                                             flags,                            \
                                             2 * kbits,                        \
                                             AES_XTS_BLOCK_BITS,               \
                                             AES_XTS_IV_BITS);                 \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
    const OSSL_DISPATCH ALCP_prov_aes##kbits##xts_functions[] = {              \
        { OSSL_FUNC_CIPHER_NEWCTX,                                             \
          (void (*)(void))alc_prov_aes_##kbits##_xts_newctx },                 \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                       \
          (void (*)(void))alc_prov_aes_xts_einit },                            \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                       \
          (void (*)(void))alc_prov_aes_xts_dinit },                            \
        { OSSL_FUNC_CIPHER_UPDATE,                                             \
          (void (*)(void))alc_prov_aes_xts_stream_update },                    \
        { OSSL_FUNC_CIPHER_FINAL,                                              \
          (void (*)(void))alc_prov_aes_xts_stream_final },                     \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))alc_prov_aes_xts_cipher },  \
        { OSSL_FUNC_CIPHER_FREECTX,                                            \
          (void (*)(void))alc_prov_aes_xts_freectx },                          \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))alcp_prov_aes_xts_dupctx }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
          (void (*)(void))alc_prov_aes_##kbits##_##lcmode##_get_params },      \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_params },          \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_cipher_generic_get_ctx_params },           \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_aead_gettable_ctx_params },         \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
          (void (*)(void))alc_prov_aes_xts_set_ctx_params },                   \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
          (void (*)(void))alc_prov_aes_xts_settable_ctx_params },              \
        { 0, NULL }                                                            \
    }

IMPLEMENT_cipher(xts, XTS, 256, AES_XTS_FLAGS);
IMPLEMENT_cipher(xts, XTS, 128, AES_XTS_FLAGS);
