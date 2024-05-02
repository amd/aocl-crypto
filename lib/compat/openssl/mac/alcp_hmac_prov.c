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

#include "alcp_hmac_prov.h"

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
    // PROV_DIGEST         digest;
    Uint8*        key;
    size_t        keylen;
    size_t        tls_data_size;
    unsigned char tls_header[13];
    int           tls_header_set;
    unsigned char tls_mac_out[EVP_MAX_MD_SIZE];
    size_t        tls_mac_out_size;
};

static void*
alcp_prov_hmac_new(void* provctx)
{
    struct alcp_hmac_data_st* macctx;

    alc_mac_info_t s_mac_hmac_info = { .mi_type = ALC_MAC_HMAC };
    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL
        || (macctx->ctx = alcp_prov_mac_newctx(&s_mac_hmac_info)) == NULL) {
        OPENSSL_free(macctx);
        return NULL;
    }
    macctx->provctx = provctx;
    return macctx;
}

static void
alcp_prov_hmac_free(void* ctx)
{
    struct alcp_hmac_data_st* macctx = ctx;

    if (macctx != NULL) {
        alcp_prov_mac_freectx(macctx->ctx);
        // TODO : free the digest object if kept inside the alcp_hmac_data_st
        OPENSSL_secure_clear_free(macctx->key, macctx->keylen);
        OPENSSL_free(macctx);
    }
}

static void*
alcp_prov_hmac_dup(void* vsrc)
{
    struct alcp_hmac_data_st* src = vsrc;
    struct alcp_hmac_data_st* dst = OPENSSL_memdup(src, sizeof(*src));

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

    if (src->key != NULL) {
        dst->key = OPENSSL_secure_malloc(src->keylen > 0 ? src->keylen : 1);
        if (dst->key == NULL) {
            alcp_prov_hmac_free(dst);
            return 0;
        }
        memcpy(dst->key, src->key, src->keylen);
    }
    return dst;
}

static inline size_t
alcp_hmac_size(struct alcp_hmac_data_st* macctx)
{
    Uint64 len = 0;
    switch (macctx->ctx->pc_mac_info.mi_algoinfo.hmac.digest_mode) {
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
alcp_hmac_block_size(struct alcp_hmac_data_st* macctx)
{
    Uint64 len = 0;
    switch (macctx->ctx->pc_mac_info.mi_algoinfo.hmac.digest_mode) {
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

static int
alcp_hmac_setkey(struct alcp_hmac_data_st* macctx,
                 const unsigned char*      key,
                 size_t                    keylen)
{
    if (macctx->key != NULL)
        OPENSSL_secure_clear_free(macctx->key, macctx->keylen);
    /* Keep a copy of the key in case we need it for TLS HMAC */
    macctx->key = OPENSSL_secure_malloc(keylen > 0 ? keylen : 1);
    if (macctx->key == NULL)
        return 0;
    memcpy(macctx->key, key, keylen);
    macctx->keylen = keylen;

    if (key != NULL || (macctx->tls_data_size == 0))
        return alcp_mac_init(&macctx->ctx->handle, key, keylen);
    return 1;
}

int
alcp_prov_hmac_init(void*                ctx,
                    const unsigned char* key,
                    size_t               keylen,
                    const OSSL_PARAM     params[])
{
    struct alcp_hmac_data_st* macctx = ctx;

    if (!alcp_prov_hmac_set_ctx_params(macctx, params))
        return 0;

    if (key != NULL)
        return alcp_hmac_setkey(macctx, key, keylen);
    return 0;
}

static int
alcp_prov_hmac_update(void* vmacctx, const unsigned char* data, size_t datalen)
{
    struct alcp_hmac_data_st* macctx = vmacctx;

    if (macctx->tls_data_size > 0) {
        if (!macctx->tls_header_set) {
            if (datalen != sizeof(macctx->tls_header))
                return 0;
            memcpy(macctx->tls_header, data, datalen);
            macctx->tls_header_set = 1;
            return 1;
        }
        /* macctx->tls_data_size is datalen plus the padding length */
        if (macctx->tls_data_size < datalen)
            return 0;

        return 1;
        // ssl3_cbc_digest_record(ossl_prov_digest_md(&macctx->digest),
        //                               macctx->tls_mac_out,
        //                               &macctx->tls_mac_out_size,
        //                               macctx->tls_header,
        //                               data,
        //                               datalen,
        //                               macctx->tls_data_size,
        //                               macctx->key,
        //                               macctx->keylen,
        //                               0);
    }

    return alcp_prov_mac_update(macctx->ctx, data, datalen);
}

static int
alcp_prov_hmac_final(void*          cctx,
                     unsigned char* out,
                     size_t*        outl,
                     size_t         outsize)
{
    struct alcp_hmac_data_st* macctx = cctx;

    if (macctx->tls_data_size > 0) {
        if (macctx->tls_mac_out_size == 0)
            return 0;
        if (outl != NULL)
            *outl = macctx->tls_mac_out_size;
        memcpy(out, macctx->tls_mac_out, macctx->tls_mac_out_size);
        return 1;
    }
    alc_error_t err =
        alcp_mac_finalize(&(macctx->ctx->handle), out, (Uint64)outsize);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Failed to Finalize\n");
        return 0;
    }

    return alcp_prov_mac_final(macctx->ctx, out, outl, outsize);
}

int
alcp_prov_hmac_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();

    struct alcp_hmac_data_st* macctx = vctx;
    // ToDO : check how to implement this
    // OSSL_LIB_CTX*     ctx = macctx->provctx ? macctx->provctx->libctx :
    // NULL;
    const OSSL_PARAM* p;

    if (params == NULL) {
        return 1;
    }

    // ToDO : check how to implement this
    // if (!ossl_prov_digest_load_from_params(&macctx->digest, params, ctx))
    //     return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!alcp_hmac_setkey(macctx, p->data, p->data_size))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_TLS_DATA_SIZE))
        != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &macctx->tls_data_size))
            return 0;
    }
    return 1;

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
    struct alcp_hmac_data_st* macctx = vmacctx;
    OSSL_PARAM*               p;

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
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_hmac_settable_ctx_params(ossl_unused void* ctx,
                                   ossl_unused void* provctx)
{
    return known_settable_ctx_params;
}

/* HMAC dispatchers */
const OSSL_DISPATCH hmac_functions[] = {
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
