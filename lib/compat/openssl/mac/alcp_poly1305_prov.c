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

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_mac_newctx_fn          alcp_prov_poly1305_new;
static OSSL_FUNC_mac_dupctx_fn          alcp_prov_poly1305_dup;
static OSSL_FUNC_mac_freectx_fn         alcp_prov_poly1305_free;
static OSSL_FUNC_mac_gettable_params_fn alcp_prov_poly1305_gettable_params;
static OSSL_FUNC_mac_get_params_fn      alcp_prov_poly1305_get_params;
static OSSL_FUNC_mac_settable_ctx_params_fn
                                       alcp_prov_poly1305_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn alcp_prov_poly1305_set_ctx_params;
static OSSL_FUNC_mac_init_fn           alcp_prov_poly1305_init;
static OSSL_FUNC_mac_update_fn         alcp_prov_poly1305_update;
static OSSL_FUNC_mac_final_fn          alcp_prov_poly1305_final;

#define ALCP_POLY1305_SIZE     16
#define ALCP_POLY1305_KEY_SIZE 32

static void*
alcp_prov_poly1305_new(void* provctx)
{
    alc_prov_mac_ctx_t* ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    return ctx;
}

static void
alcp_prov_poly1305_free(void* ctx)
{
    return alcp_prov_mac_freectx(ctx);
}

static void*
alcp_prov_poly1305_dup(void* ctx)
{
    alc_prov_mac_ctx_t* src = ctx;
    alc_prov_mac_ctx_t* dst = OPENSSL_memdup(src, sizeof(*src));

    Uint64 size;
    if (dst != NULL) {
        size                   = alcp_mac_context_size();
        dst->handle.ch_context = OPENSSL_zalloc(size);
    } else {
        return NULL;
    }

    alc_error_t err =
        alcp_mac_context_copy(&src->ctx->handle, &dst->ctx->handle);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: poly copy failed in dupctx\n");
        OPENSSL_clear_free(dst->ctx->handle.ch_context, size);
        OPENSSL_clear_free(dst->ctx, sizeof(*(dst->ctx)));
        return NULL;
    }

    return dst;
}

static inline int
alcp_poly1305_setkey(alc_prov_mac_ctx_t* ctx, const Uint8* key, Uint64 size)
{
    if (size != ALCP_POLY1305_KEY_SIZE) {
        printf("Provider poly1305: key size not correct\n");
        return 0;
    }
    return alcp_mac_init(ctx->handle, key, size, NULL);
}

static int
alcp_prov_poly1305_init(void*            ctx,
                        const Uint8*     key,
                        Uint64           size,
                        const OSSL_PARAM params[])
{
    alc_prov_mac_ctx_t* poly_ctx = ctx;

    if (!alcp_prov_poly1305_set_ctx_params(poly_ctx, params))
        return 0;
    if (key != NULL)
        return alcp_poly1305_setkey(poly_ctx, key, size);

    return 0;
}

static int
alcp_prov_poly1305_update(void* ctx, const Uint8* buff, Uint64 size)
{
    return alcp_prov_mac_update(ctx, buff, size);
}

static int
alcp_prov_poly1305_final(void* vmacctx, Uint8* out, Uint64* outl, Uint64 size)
{
    return alcp_prov_mac_final(vmacctx, out, outl, size);
}

static const OSSL_PARAM alcp_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL), OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_poly1305_gettable_params(void* provctx)
{
    return alcp_known_gettable_params;
}

static int
alcp_prov_poly1305_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM* p;
    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, ALCP_POLY1305_SIZE);

    return 1;
}

static const OSSL_PARAM alcp_known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0), OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_poly1305_settable_ctx_params(ossl_unused void* ctx,
                                       ossl_unused void* provctx)
{
    return alcp_known_settable_ctx_params;
}

static int
alcp_prov_poly1305_set_ctx_params(void* ctx, const OSSL_PARAM* params)
{
    const OSSL_PARAM* p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL
        && !alcp_poly1305_setkey(ctx, p->buff, p->data_size))
        return 0;
    return 1;
}

const OSSL_DISPATCH alcp_poly1305_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))alcp_prov_poly1305_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))alcp_prov_poly1305_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))alcp_prov_poly1305_free },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))alcp_prov_poly1305_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))alcp_prov_poly1305_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))alcp_prov_poly1305_final },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))alcp_prov_poly1305_gettable_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))alcp_prov_poly1305_get_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))alcp_prov_poly1305_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))alcp_prov_poly1305_set_ctx_params },
    OSSL_DISPATCH_END
};
