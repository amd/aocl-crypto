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

#pragma once

#define AES_BLOCK_SIZE 16

#define MAXCHUNK    ((size_t)1 << 30)
#define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

#define GENERIC_BLOCK_SIZE 16

#define PROV_CIPHER_FUNC(type, name, args) typedef type(*OSSL_##name##_fn) args

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD            0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV       0x0002
#define PROV_CIPHER_FLAG_CTS             0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK 0x0008
#define PROV_CIPHER_FLAG_RAND_KEY        0x0010
/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH 0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER  0x0200

#define ACLP_SSL3_VERSION 0x0300

int
ALCP_prov_cipher_generic_get_params(OSSL_PARAM   params[],
                                    unsigned int md,
                                    uint64_t     flags,
                                    size_t       kbits,
                                    size_t       blkbits,
                                    size_t       ivbits);

void
ALCP_prov_cipher_generic_reset_ctx(ALCP_PROV_CIPHER_CTX* ctx);
OSSL_FUNC_cipher_encrypt_init_fn    ALCP_prov_cipher_generic_einit;
OSSL_FUNC_cipher_decrypt_init_fn    ALCP_prov_cipher_generic_dinit;
OSSL_FUNC_cipher_update_fn          ALCP_prov_cipher_generic_block_update;
OSSL_FUNC_cipher_final_fn           ALCP_prov_cipher_generic_block_final;
OSSL_FUNC_cipher_update_fn          ALCP_prov_cipher_generic_stream_update;
OSSL_FUNC_cipher_final_fn           ALCP_prov_cipher_generic_stream_final;
OSSL_FUNC_cipher_cipher_fn          ALCP_prov_cipher_generic_cipher;
OSSL_FUNC_cipher_get_ctx_params_fn  ALCP_prov_cipher_generic_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn  ALCP_prov_cipher_generic_set_ctx_params;
OSSL_FUNC_cipher_gettable_params_fn ALCP_prov_cipher_generic_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn
    ALCP_prov_cipher_generic_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn
                                   ALCP_prov_cipher_generic_settable_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ALCP_prov_cipher_var_keylen_set_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn
    ALCP_prov_cipher_var_keylen_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn
    ALCP_prov_cipher_aead_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn
    ALCP_prov_cipher_aead_settable_ctx_params;

int
ALCP_prov_cipher_generic_get_params(OSSL_PARAM   params[],
                                    unsigned int md,
                                    uint64_t     flags,
                                    size_t       kbits,
                                    size_t       blkbits,
                                    size_t       ivbits);

void
ALCP_prov_cipher_generic_initkey(void*        vctx,
                                 size_t       kbits,
                                 size_t       blkbits,
                                 size_t       ivbits,
                                 unsigned int mode,
                                 uint64_t     flags,
                                 void*        provctx);

// this macro needs to be removed.
#define OSSL_PARAM_END                                                         \
    {                                                                          \
        NULL, 0, NULL, 0, 0                                                    \
    }

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(name)                         \
    static const OSSL_PARAM name##_known_gettable_ctx_params[] = {             \
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),                     \
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),                      \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                      \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),                          \
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),                \
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
    }                                                                          \
    ;                                                                          \
    const OSSL_PARAM* name##_gettable_ctx_params(ossl_unused void* cctx,       \
                                                 ossl_unused void* provctx)    \
    {                                                                          \
        return name##_known_gettable_ctx_params;                               \
    }

#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(name)                         \
    static const OSSL_PARAM name##_known_settable_ctx_params[] = {             \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                      \
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
    }                                                                          \
    ;                                                                          \
    const OSSL_PARAM* name##_settable_ctx_params(ossl_unused void* cctx,       \
                                                 ossl_unused void* provctx)    \
    {                                                                          \
        return name##_known_settable_ctx_params;                               \
    }

#define IMPLEMENT_generic_cipher_func(                                         \
    alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)            \
    const OSSL_DISPATCH ALCP_prov_##alg##kbits##lcmode##_functions[] = {       \
        { OSSL_FUNC_CIPHER_NEWCTX,                                             \
          (void (*)(void))alg##_##kbits##_##lcmode##_newctx },                 \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_freectx },           \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))alg##_dupctx },             \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_cipher_generic_einit },                    \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_cipher_generic_dinit },                    \
        { OSSL_FUNC_CIPHER_UPDATE,                                             \
          (void (*)(void))ALCP_prov_cipher_generic_##typ##_update },           \
        { OSSL_FUNC_CIPHER_FINAL,                                              \
          (void (*)(void))ALCP_prov_cipher_generic_##typ##_final },            \
        { OSSL_FUNC_CIPHER_CIPHER,                                             \
          (void (*)(void))ALCP_prov_cipher_generic_cipher },                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
          (void (*)(void))alg##_##kbits##_##lcmode##_get_params },             \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_cipher_generic_get_ctx_params },           \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_cipher_generic_set_ctx_params },           \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_params },          \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_ctx_params },      \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_generic_settable_ctx_params },      \
        { 0, NULL }                                                            \
    };

#define IMPLEMENT_var_keylen_cipher_func(                                      \
    alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)            \
    const OSSL_DISPATCH ALCP_prov_##alg##kbits##lcmode##_functions[] = {       \
        { OSSL_FUNC_CIPHER_NEWCTX,                                             \
          (void (*)(void))alg##_##kbits##_##lcmode##_newctx },                 \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_freectx },           \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))alg##_dupctx },             \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_cipher_generic_einit },                    \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_cipher_generic_dinit },                    \
        { OSSL_FUNC_CIPHER_UPDATE,                                             \
          (void (*)(void))ALCP_prov_cipher_generic_##typ##_update },           \
        { OSSL_FUNC_CIPHER_FINAL,                                              \
          (void (*)(void))ALCP_prov_cipher_generic_##typ##_final },            \
        { OSSL_FUNC_CIPHER_CIPHER,                                             \
          (void (*)(void))ALCP_prov_cipher_generic_cipher },                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
          (void (*)(void))alg##_##kbits##_##lcmode##_get_params },             \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_cipher_generic_get_ctx_params },           \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_cipher_var_keylen_set_ctx_params },        \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_params },          \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_ctx_params },      \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_var_keylen_settable_ctx_params },   \
        { 0, NULL }                                                            \
    };

#define IMPLEMENT_generic_cipher_genfn(                                        \
    alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)            \
    static OSSL_FUNC_cipher_get_params_fn                                      \
               alg##_##kbits##_##lcmode##_get_params;                          \
    static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])      \
    {                                                                          \
        return ALCP_prov_cipher_generic_get_params(                            \
            params, EVP_CIPH_##UCMODE##_MODE, flags, kbits, blkbits, ivbits);  \
    }                                                                          \
    static OSSL_FUNC_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;       \
    static void* alg##_##kbits##_##lcmode##_newctx(void* provctx)              \
    {                                                                          \
        ALCP_PROV_CIPHER_CTX* ctx =                                            \
            alcp_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;      \
        if (ctx != NULL) {                                                     \
            ctx->handle.ch_context =                                           \
                OPENSSL_malloc(alcp_cipher_aead_context_size());               \
            if (ctx->handle.ch_context == NULL) {                              \
                printf("\n context allocation failed ");                       \
                return NULL;                                                   \
            }                                                                  \
            alc_error_t err = alcp_cipher_request(                             \
                ALC_AES_MODE_##UCMODE, kbits, &(ctx->handle));                 \
            ctx->prov_cipher_data = ctx->handle.alc_cipher_data;               \
            if (ctx->prov_cipher_data == NULL) {                               \
                OPENSSL_clear_free(ctx, sizeof(*ctx));                         \
            }                                                                  \
                                                                               \
            if (err == ALC_ERROR_NONE) {                                       \
                if (ctx != ((void*)0)) {                                       \
                    ALCP_prov_cipher_generic_initkey(ctx,                      \
                                                     kbits,                    \
                                                     blkbits,                  \
                                                     ivbits,                   \
                                                     EVP_CIPH_##UCMODE##_MODE, \
                                                     flags,                    \
                                                     provctx);                 \
                }                                                              \
            } else {                                                           \
                OPENSSL_clear_free(ctx, sizeof(*ctx));                         \
            }                                                                  \
        }                                                                      \
        return ctx;                                                            \
    }

#define IMPLEMENT_generic_cipher(                                              \
    alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)            \
    IMPLEMENT_generic_cipher_genfn(                                            \
        alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)        \
        IMPLEMENT_generic_cipher_func(                                         \
            alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)

#define IMPLEMENT_var_keylen_cipher(                                           \
    alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)            \
    IMPLEMENT_generic_cipher_genfn(                                            \
        alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)        \
        IMPLEMENT_var_keylen_cipher_func(                                      \
            alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ)

size_t
ALCP_prov_cipher_fillblock(Uint8*        buf,
                           size_t*       buflen,
                           size_t        blocksize,
                           const Uint8** in,
                           size_t*       inlen);
int
ALCP_prov_cipher_trailingdata(Uint8*        buf,
                              size_t*       buflen,
                              size_t        blocksize,
                              const Uint8** in,
                              size_t*       inlen);

void
ALCP_prov_cipher_padblock(Uint8* buf, size_t* buflen, size_t blocksize);

int
ALCP_prov_cipher_unpadblock(Uint8* buf, size_t* buflen, size_t blocksize);

OSSL_LIB_CTX*
ALCP_prov_libctx_of(ALCP_PROV_CIPHER_CTX* ctx);