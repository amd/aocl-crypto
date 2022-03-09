/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp_digest_prov.h"
#include "names.h"

void
ALCP_prov_digest_freectx(void* vctx)
{
    alc_prov_digest_ctx_p pdctx = vctx;
    ENTER();
    /*
     * pdctx->pc_evp_digest will be  freed in provider teardown,
     */

    EVP_MD_CTX_free(pdctx->pc_evp_digest_ctx);

    OPENSSL_free(vctx);
}

void*
ALCP_prov_digest_newctx(void* vprovctx, const alc_digest_info_p dinfo)
{
    alc_prov_digest_ctx_p dig_ctx;
    alc_prov_ctx_p        pctx = (alc_prov_ctx_p)vprovctx;

    ENTER();

    dig_ctx = OPENSSL_zalloc(sizeof(*dig_ctx));
    if (dig_ctx != NULL) {
        dig_ctx->pc_prov_ctx = pctx;
        // dig_ctx->pc_params         = pparams;
        dig_ctx->pc_libctx      = pctx->ap_libctx;
        dig_ctx->pc_digest_info = *dinfo;
#if 0
        dig_ctx->pc_evp_digest_ctx = EVP_MD_CTX_new();
        if (!dig_ctx->pc_evp_digest_ctx || !dig_ctx->pc_prov_ctx) {
            ALCP_prov_digest_freectx(dig_ctx);
            dig_ctx = NULL;
        }
        // dig_ctx->descriptor = descriptor;
        // dig_ctx->digest     = ALCP_prov_digest_init(descriptor);
#endif
    }

    return dig_ctx;
}

void*
ALCP_prov_digest_dupctx(void* vctx)
{
    alc_prov_digest_ctx_p csrc = vctx;
    ENTER();
#if 0
    alc_prov_digest_ctx_p cdst = ALCP_prov_digest_newctx(
        csrc->pc_evp_digest_ctx, csrc->pc_digest_info, csrc->pc_params);
#endif
    return csrc;
}

/*-
 * Generic digest functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM digest_known_gettable_params[] = {
    // OSSL_PARAM_uint(OSSL_DIGEST_PARAM_MODE, NULL),
    // OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_KEYLEN, NULL),
    // OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
#if 0
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_HAS_RAND_KEY, NULL),
#endif
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_digest_gettable_params(void* provctx)
{
    EXIT();
    return digest_known_gettable_params;
}

int
ALCP_prov_digest_get_params(OSSL_PARAM params[], int mode)
{
    OSSL_PARAM* p;
    int         blkbits = 128;

    ENTER();

    // p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_MODE);
    // if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
    //     ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    //     EXIT();
    //     return 0;
    // }

    // p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_KEYLEN);
    // if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
    //     ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    //     EXIT();
    //     return 0;
    // }

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    // p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_IVLEN);
    // if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
    //     ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    //     EXIT();
    //     return 0;
    // }

    EXIT();
    return 1;
}

const OSSL_PARAM*
ALCP_prov_digest_gettable_ctx_params(void* cctx, void* provctx)
{
    return digest_known_gettable_params;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_digest_settable_ctx_params(void* cctx, void* provctx)
{
    static const OSSL_PARAM table[] = {
        // OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END,
    };
    EXIT();
    return table;
}

int
ALCP_prov_digest_set_params(const OSSL_PARAM params[])
{
    ENTER();
    return 1;
}

int
ALCP_prov_digest_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    // OSSL_PARAM* p;
    // alc_prov_digest_ctx_p cctx = (alc_prov_digest_ctx_p)vctx;
    // size_t                keylen = cctx->pc_digest_info.key_info.len;

    ENTER();

    // if (keylen > 0
    //     && (p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_KEYLEN)) != NULL
    //     && !OSSL_PARAM_set_size_t(p, keylen))
    //     return 0;

    EXIT();
    return 1;
}

int
ALCP_prov_digest_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    // const OSSL_PARAM*     p;
    // alc_prov_digest_ctx_p cctx = (alc_prov_digest_ctx_p)vctx;
    ENTER();

    // p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_KEYLEN);
    // if (p != NULL) {
    //     size_t keylen;
    //     if (!OSSL_PARAM_get_size_t(p, &keylen)) {
    //         ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
    //         HERE();
    //         return 0;
    //     }
    //     cctx->pc_digest_info.key_info.len = keylen;
    // }

    EXIT();
    return 1;
}

int
ALCP_prov_digest_init(void* vctx, const OSSL_PARAM params[])
{
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;
    ENTER();
    // printf("Provider: Pointer->%p\n", cctx);
    alc_digest_info_p dinfo = &cctx->pc_digest_info;
    uint64_t          size  = alcp_digest_context_size(dinfo);
    cctx->handle.context    = OPENSSL_malloc(size);
    err                     = alcp_digest_request(dinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Somehow request failed\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
ALCP_prov_digest_update(void* vctx, const unsigned char* in, size_t inl)
{
    alc_error_t           err;
    alc_prov_digest_ctx_p cctx = vctx;
    ENTER();
    err = alcp_digest_update(&(cctx->handle), in, inl);
    if (alcp_is_error(err)) {
        printf("Provider: Unable to compute SHA2 hash\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
ALCP_prov_digest_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    alc_prov_digest_ctx_p cctx = vctx;
    ENTER();
    alcp_digest_finalize(&(cctx->handle), NULL, 0);
    alcp_digest_copy(&(cctx->handle), out, (uint64_t)outl);
    // Northing to do!
    *outl = outsize;
    return 1;
}

static const char DIGEST_DEF_PROP[] = "provider=alcp,fips=no";

extern const OSSL_DISPATCH sha224_functions[];
extern const OSSL_DISPATCH sha256_functions[];
extern const OSSL_DISPATCH sha384_functions[];
extern const OSSL_DISPATCH sha512_functions[];

const OSSL_ALGORITHM ALC_prov_digests[] = {
    { PROV_NAMES_SHA2_512, DIGEST_DEF_PROP, sha512_functions },
    { PROV_NAMES_SHA2_384, DIGEST_DEF_PROP, sha384_functions },
    { PROV_NAMES_SHA2_256, DIGEST_DEF_PROP, sha256_functions },
    { PROV_NAMES_SHA2_224, DIGEST_DEF_PROP, sha224_functions },
    { NULL, NULL, NULL },
};

// EVP_CIPHER*
// ALCP_prov_digest_init(alc_prov_ctx_p cc)
// {
//     /* FIXME: this could be wrong */
//     alc_prov_digest_ctx_p c = (alc_prov_digest_ctx_p)cc;

//     ENTER();
//     if (c->pc_evp_digest)
//         return c->pc_evp_digest;

//     /* Some sanity checking. */
//     int flags = c->pc_flags;
//     switch (flags & EVP_CIPH_MODE) {
//         case EVP_CIPH_CTR_MODE:
//         case EVP_CIPH_CFB_MODE:
//         case EVP_CIPH_OFB_MODE:
//             break;
//         default:
//             break;
//     }

//     EVP_CIPHER* tmp = NULL;
// #if 0
//     tmp = EVP_CIPHER_meth_new(c->pc_nid, 128 / 8, c->pc_key_info->len);

//     int res = 0;
//     res |= EVP_CIPHER_meth_set_iv_length(tmp, iv_len);
//     res != EVP_CIPHER_meth_set_flags(tmp, flags);
//     res != EVP_CIPHER_meth_set_init(tmp, init);
//     res != EVP_CIPHER_meth_set_do_tmp(tmp, do_tmp);
//     res != EVP_CIPHER_meth_set_cleanup(tmp, cleanup);
//     res != EVP_CIPHER_meth_set_impl_ctx_size(tmp, ctx_size);
//     res != EVP_CIPHER_meth_set_set_asn1_params(tmp, set_asn1_parameters);
//     res != EVP_CIPHER_meth_set_get_asn1_params(tmp, get_asn1_parameters);
//     res != EVP_CIPHER_meth_set_ctrl(tmp, ctrl);
//     if (res) {
//         EVP_CIPHER_meth_free(tmp);
//         tmp = NULL;
//     }

//     c->pc_evp_digest = tmp;
// #endif
//     return tmp;
// }
