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

#include "alcp/alcp.h"
#include "alcp_mac_prov.h"
#include "debug.h"

static OSSL_FUNC_mac_newctx_fn              alcp_prov_cmac_new;
static OSSL_FUNC_mac_dupctx_fn              alcp_prov_cmac_dup;
static OSSL_FUNC_mac_freectx_fn             alcp_prov_cmac_free;
static OSSL_FUNC_mac_gettable_ctx_params_fn alcp_prov_cmac_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn      alcp_prov_cmac_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn alcp_prov_cmac_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn      alcp_prov_cmac_set_ctx_params;
static OSSL_FUNC_mac_init_fn                alcp_prov_cmac_init;
static OSSL_FUNC_mac_update_fn              alcp_prov_cmac_update;
static OSSL_FUNC_mac_final_fn               alcp_prov_cmac_final;

struct alcp_cmac_data_st
{
    void*               provctx;
    alc_prov_mac_ctx_t* ctx;
};

typedef struct alcp_cmac_data_st alcp_cmac_data_st_t;

#define ALCP_CMAC_BLOCK_SIZE 16

static void*
alcp_prov_cmac_new(void* provctx)
{
    alcp_cmac_data_st_t* macctx;

    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL
        || (macctx->ctx = alcp_prov_mac_newctx(ALC_MAC_CMAC)) == NULL) {
        OPENSSL_free(macctx);
        macctx = NULL;
    } else {
        macctx->provctx = provctx;
    }

    return macctx;
}

static void
alcp_prov_cmac_free(void* ctx)
{
    alcp_cmac_data_st_t* macctx = ctx;

    if (macctx != NULL) {
        alcp_prov_mac_freectx(macctx->ctx);
        OPENSSL_free(macctx);
    }
}

static void*
alcp_prov_cmac_dup(void* ctx)
{
    alcp_cmac_data_st_t* src = ctx;
    alcp_cmac_data_st_t* dst = OPENSSL_memdup(src, sizeof(*src));

    Uint64 size;
    if (dst != NULL) {
        dst->ctx = OPENSSL_zalloc(sizeof(alc_prov_mac_ctx_t));
        size     = alcp_mac_context_size();
        dst->ctx->handle.ch_context = OPENSSL_zalloc(size);
    } else {
        return NULL;
    }

    alc_error_t err =
        alcp_mac_context_copy(&src->ctx->handle, &dst->ctx->handle);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: cmac copy failed in dupctx\n");
        OPENSSL_clear_free(dst->ctx->handle.ch_context, size);
        OPENSSL_clear_free(dst->ctx, sizeof(*(dst->ctx)));
        OPENSSL_clear_free(dst, sizeof(alcp_cmac_data_st_t));
        return NULL;
    }

    return dst;
}

static int
alcp_cmac_setkey(alc_prov_mac_ctx_t* ctx, const Uint8* key, Uint64 size)
{

    return (ALC_ERROR_NONE == alcp_mac_init(&ctx->handle, key, size, NULL)) ? 1
                                                                            : 0;
}

static int
alcp_prov_cmac_init(void*            ctx,
                    const Uint8*     key,
                    Uint64           size,
                    const OSSL_PARAM params[])
{
    alcp_cmac_data_st_t* macctx = ctx;

    if (!alcp_prov_cmac_set_ctx_params(macctx, params))
        return 0;
    if (key != NULL)
        return alcp_cmac_setkey(macctx->ctx, key, size);

    alc_error_t err = alcp_mac_reset(&macctx->ctx->handle);
    return err == ALC_ERROR_NONE ? 1 : 0;
}

static int
alcp_prov_cmac_update(void* ctx, const Uint8* buff, Uint64 size)
{
    alcp_cmac_data_st_t* macctx = ctx;

    return alcp_prov_mac_update(macctx->ctx, buff, size);
}

static int
alcp_prov_cmac_final(void* ctx, Uint8* out, Uint64* outl, Uint64 size)
{
    alcp_cmac_data_st_t* macctx = ctx;

    return alcp_prov_mac_final(macctx->ctx, out, outl, ALCP_CMAC_BLOCK_SIZE);
}

static const OSSL_PARAM alcp_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_cmac_gettable_ctx_params(void* ctx, void* provctx)
{
    return alcp_known_gettable_ctx_params;
}

static int
alcp_prov_cmac_get_ctx_params(void* ctx, OSSL_PARAM params[])
{
    OSSL_PARAM* p;
    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, ALCP_CMAC_BLOCK_SIZE))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, ALCP_CMAC_BLOCK_SIZE))
        return 0;

    return 1;
}

static const OSSL_PARAM alcp_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_cmac_settable_ctx_params(void* ctx, void* provctx)
{
    return alcp_known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int
alcp_prov_cmac_set_ctx_params(void* ctx, const OSSL_PARAM params[])
{
    alcp_cmac_data_st_t* macctx = ctx;
    const OSSL_PARAM*    p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER)) != NULL) {
        if (strcasecmp(p->data, "AES-128-CBC")
            && strcasecmp(p->data, "AES-192-CBC")
            && strcasecmp(p->data, "AES-256-CBC")
            && strcasecmp(p->data, "AES128") && strcasecmp(p->data, "AES192")
            && strcasecmp(p->data, "AES256")) {
            printf("CMAC Provider: Cipher '%s' not Supported\n",
                   (Uint8*)p->data);
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        return alcp_cmac_setkey(macctx->ctx, p->data, p->data_size);
    }
    return 1;
}

const OSSL_DISPATCH alcp_cmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (fptr_t)alcp_prov_cmac_new },
    { OSSL_FUNC_MAC_DUPCTX, (fptr_t)alcp_prov_cmac_dup },
    { OSSL_FUNC_MAC_FREECTX, (fptr_t)alcp_prov_cmac_free },
    { OSSL_FUNC_MAC_INIT, (fptr_t)alcp_prov_cmac_init },
    { OSSL_FUNC_MAC_UPDATE, (fptr_t)alcp_prov_cmac_update },
    { OSSL_FUNC_MAC_FINAL, (fptr_t)alcp_prov_cmac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (fptr_t)alcp_prov_cmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (fptr_t)alcp_prov_cmac_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (fptr_t)alcp_prov_cmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (fptr_t)alcp_prov_cmac_set_ctx_params },
    { 0, NULL }
};
