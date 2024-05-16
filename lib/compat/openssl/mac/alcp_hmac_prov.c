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
 * Forward declaration for providing assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_mac_newctx_fn              alcp_prov_hmac_new;
static OSSL_FUNC_mac_dupctx_fn              alcp_prov_hmac_dup;
static OSSL_FUNC_mac_freectx_fn             alcp_prov_hmac_free;
static OSSL_FUNC_mac_gettable_ctx_params_fn alcp_prov_hmac_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn      alcp_prov_hmac_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn alcp_prov_hmac_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn      alcp_prov_hmac_set_ctx_params;
static OSSL_FUNC_mac_init_fn                alcp_prov_hmac_init;
static OSSL_FUNC_mac_update_fn              alcp_prov_hmac_update;
static OSSL_FUNC_mac_final_fn               alcp_prov_hmac_final;

struct alcp_hmac_data_st
{
    void*               provctx;
    alc_prov_mac_ctx_t* ctx;
    alc_digest_mode_t   mode;
};
typedef struct alcp_hmac_data_st alcp_hmac_data_st_t;

static void*
alcp_prov_hmac_new(void* provctx)
{
    alcp_hmac_data_st_t* macctx;

    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL
        || (macctx->ctx = alcp_prov_mac_newctx(ALC_MAC_HMAC)) == NULL) {
        OPENSSL_free(macctx);
        return NULL;
    }
    macctx->provctx = provctx;
    return macctx;
}

static void
alcp_prov_hmac_free(void* ctx)
{
    alcp_hmac_data_st_t* macctx = ctx;

    if (macctx != NULL) {
        alcp_prov_mac_freectx(macctx->ctx);
        OPENSSL_free(macctx);
    }
}

static void*
alcp_prov_hmac_dup(void* vsrc)
{
    alcp_hmac_data_st_t* src = vsrc;
    alcp_hmac_data_st_t* dst = OPENSSL_memdup(src, sizeof(*src));

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
        printf("Provider: HMAC copy failed in dupctx\n");
        OPENSSL_clear_free(dst->ctx->handle.ch_context, size);
        OPENSSL_clear_free(dst->ctx, sizeof(*(dst->ctx)));
        return NULL;
    }

    return dst;
}

static inline size_t
alcp_hmac_size(alcp_hmac_data_st_t* macctx)
{
    Uint64 len = 0;
    switch (macctx->mode) {
        case ALC_SHAKE_128:
            len = ALC_DIGEST_LEN_128;
            break;
        case ALC_SHA2_224:
        case ALC_SHA3_224:
        case ALC_SHA2_512_224:
            len = ALC_DIGEST_LEN_224;
            break;
        case ALC_SHA2_256:
        case ALC_SHA3_256:
        case ALC_SHA2_512_256:
        case ALC_SHAKE_256:
            len = ALC_DIGEST_LEN_256;
            break;
        case ALC_SHA2_384:
        case ALC_SHA3_384:
            len = ALC_DIGEST_LEN_384;
            break;
        case ALC_SHA2_512:
        case ALC_SHA3_512:
            len = ALC_DIGEST_LEN_512;
            break;
        default:
            printf("Error: Unsupported mode\n");
    }
    return len / 8;
}

static inline int
alcp_hmac_block_size(alcp_hmac_data_st_t* macctx)
{
    Uint64 len = 0;
    switch (macctx->mode) {
        case ALC_SHA2_224:
        case ALC_SHA2_256:
            len = ALC_DIGEST_BLOCK_SIZE_SHA2_256;
            break;
        case ALC_SHA2_512:
        case ALC_SHA2_384:
        case ALC_SHA2_512_224:
        case ALC_SHA2_512_256:
            len = ALC_DIGEST_BLOCK_SIZE_SHA2_512;
            break;
        case ALC_SHA3_224:
            len = ALC_DIGEST_BLOCK_SIZE_SHA3_224;
            break;
        case ALC_SHA3_256:
            len = ALC_DIGEST_BLOCK_SIZE_SHA3_256;
            break;
        case ALC_SHA3_384:
            len = ALC_DIGEST_BLOCK_SIZE_SHA3_384;
            break;
        case ALC_SHA3_512:
            len = ALC_DIGEST_BLOCK_SIZE_SHA3_512;
            break;
        case ALC_SHAKE_128:
            len = ALC_DIGEST_BLOCK_SIZE_SHAKE_128;
            break;
        case ALC_SHAKE_256:
            len = ALC_DIGEST_BLOCK_SIZE_SHAKE_256;
            break;
        default:
            printf("Error: Unsupported mode\n");
    }
    return len / 8;
}

static inline int
alcp_hmac_get_digest_mode(char* str)
{
    ENTER();
    alc_digest_mode_t digest_mode;
    if (str == NULL) {
        EXIT();
        printf("Error : Digest string is null.Using the default Sha256 mode");
        digest_mode = ALC_SHA2_256;
        return digest_mode;
    }

    if (!strcasecmp(str, "sha256")) {
        digest_mode = ALC_SHA2_256;
    } else if (!strcasecmp(str, "sha224")) {
        digest_mode = ALC_SHA2_224;
    } else if (!strcasecmp(str, "sha384")) {
        digest_mode = ALC_SHA2_384;
    } else if (!strcasecmp(str, "sha512")) {
        digest_mode = ALC_SHA2_512;
    } else if (!strcasecmp(str, "sha512-224")) {
        digest_mode = ALC_SHA2_512_224;
    } else if (!strcasecmp(str, "sha512-256")) {
        digest_mode = ALC_SHA2_512_256;
    } else if (!strcasecmp(str, "sha3-224")) {
        digest_mode = ALC_SHA3_224;
    } else if (!strcasecmp(str, "sha3-256")) {
        digest_mode = ALC_SHA3_256;
    } else if (!strcasecmp(str, "sha3-384")) {
        digest_mode = ALC_SHA3_384;
    } else if (!strcasecmp(str, "sha3-512")) {
        digest_mode = ALC_SHA3_512;
    } else {
        digest_mode = -1;
        printf("HMAC Provider: Digest '%s' not Supported", str);
        EXIT();
    }

    EXIT();
    return digest_mode;
}

static int
alcp_hmac_setkey(alcp_hmac_data_st_t* macctx,
                 const unsigned char* key,
                 size_t               keylen)
{
    alc_mac_info_t info = { { macctx->mode } };
    if (key != NULL)
        return alcp_mac_init(&macctx->ctx->handle, key, keylen, &info);
    return 1;
}

int
alcp_prov_hmac_init(void*                ctx,
                    const unsigned char* key,
                    size_t               keylen,
                    const OSSL_PARAM     params[])
{
    alcp_hmac_data_st_t* macctx = ctx;

    if (!alcp_prov_hmac_set_ctx_params(macctx, params))
        return 0;

    alc_error_t err;
    if (key != NULL) {
        err = alcp_hmac_setkey(macctx, key, keylen);
        return err == ALC_ERROR_NONE ? 1 : 0;
    }
    err = alcp_mac_reset(&macctx->ctx->handle);
    return err == ALC_ERROR_NONE ? 1 : 0;
}

static int
alcp_prov_hmac_update(void* vmacctx, const unsigned char* data, size_t datalen)
{
    alcp_hmac_data_st_t* macctx = vmacctx;

    return alcp_prov_mac_update(macctx->ctx, data, datalen);
}

static int
alcp_prov_hmac_final(void*          cctx,
                     unsigned char* out,
                     size_t*        outl,
                     size_t         outsize)
{
    alcp_hmac_data_st_t* macctx = cctx;
    return alcp_prov_mac_final(macctx->ctx, out, outl, outsize);
}

int
alcp_prov_hmac_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();

    alcp_hmac_data_st_t* macctx = vctx;
    const OSSL_PARAM*    p;

    if (params == NULL) {
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            return 0;
        }
        int ret = alcp_hmac_get_digest_mode(p->data);
        if (ret < 0) {
            return 0;
        }
        macctx->mode = ret;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!alcp_hmac_setkey(macctx, p->data, p->data_size))
            return 0;
    }

    EXIT();
    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_hmac_gettable_ctx_params(ossl_unused void* ctx,
                                   ossl_unused void* provctx)
{
    return known_gettable_ctx_params;
}

static int
alcp_prov_hmac_get_ctx_params(void* vmacctx, OSSL_PARAM params[])
{
    alcp_hmac_data_st_t* macctx = vmacctx;
    OSSL_PARAM*          p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, alcp_hmac_size(macctx)))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, alcp_hmac_block_size(macctx)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {

    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM*

alcp_prov_hmac_settable_ctx_params(ossl_unused void* ctx,
                                   ossl_unused void* provctx)
{
    return known_settable_ctx_params;
}

/* HMAC dispatchers */
const OSSL_DISPATCH alcp_hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (fptr_t)alcp_prov_hmac_new },
    { OSSL_FUNC_MAC_DUPCTX, (fptr_t)alcp_prov_hmac_dup },
    { OSSL_FUNC_MAC_FREECTX, (fptr_t)alcp_prov_hmac_free },
    { OSSL_FUNC_MAC_INIT, (fptr_t)alcp_prov_hmac_init },
    { OSSL_FUNC_MAC_UPDATE, (fptr_t)alcp_prov_hmac_update },
    { OSSL_FUNC_MAC_FINAL, (fptr_t)alcp_prov_hmac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (fptr_t)alcp_prov_hmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (fptr_t)alcp_prov_hmac_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (fptr_t)alcp_prov_hmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (fptr_t)alcp_prov_hmac_set_ctx_params },
    OSSL_DISPATCH_END
};
