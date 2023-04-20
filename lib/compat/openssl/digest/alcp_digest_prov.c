/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "digest/alcp_digest_prov.h"
#include "provider/alcp_names.h"

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
        dig_ctx->pc_prov_ctx    = pctx;
        dig_ctx->pc_libctx      = pctx->ap_libctx;
        dig_ctx->pc_digest_info = *dinfo;
    }

    return dig_ctx;
}

void*
ALCP_prov_digest_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implementation Pending for context copy
    alc_prov_digest_ctx_p csrc = vctx;
    EXIT();
    return csrc;
}

/*-
 * Generic digest functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM digest_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL), OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_digest_gettable_params(void* provctx)
{
    ENTER();
    EXIT();
    return digest_known_gettable_params;
}

int
ALCP_prov_digest_get_params(OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 1;
}

const OSSL_PARAM*
ALCP_prov_digest_gettable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return digest_known_gettable_params;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_digest_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
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
    EXIT();
    return 1;
}

int
ALCP_prov_digest_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 1;
}

int
ALCP_prov_digest_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    const OSSL_PARAM*     p;
    alc_prov_digest_ctx_p pctx = (alc_prov_digest_ctx_p)vctx;

    // SHAKE DIGEST SIZE PARAM
    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL) {
        if (OSSL_PARAM_get_size_t(p, &pctx->shake_digest_size)) {
            alc_error_t err = alcp_digest_set_output_size(
                &pctx->handle, pctx->shake_digest_size);
            if (alcp_is_error(err)) {
                printf("Provider: Failed to set SHAKE Digest Size\n");
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
            }
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    EXIT();
    return 1;
}

int
ALCP_prov_digest_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;

    alc_digest_info_p dinfo = &cctx->pc_digest_info;
    Uint64            size  = alcp_digest_context_size(dinfo);
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
    ENTER();
    alc_error_t           err;
    alc_prov_digest_ctx_p cctx = vctx;
    ENTER();
    err = alcp_digest_update(&(cctx->handle), in, inl);
    if (alcp_is_error(err)) {
        printf("Provider: Unable to Update Digest\n");
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
    ENTER();
    alc_error_t           err  = ALC_ERROR_NONE;
    alc_prov_digest_ctx_p dctx = vctx;

    /**
     * FIXME: EVP_MD_get_size provider need to implemented. Currently it is
     * returning zero in OpenSSL which caused outsize passed as argument to this
     * function to be zero
     * */

    // FIXME: Once EVP_MD_get_size provider is implemented calculate *outl
    // directly from outsize. Below is a temporary fix to get digest size
    if (dctx->pc_digest_info.dt_mode.dm_sha3 == ALC_SHAKE_128
        || dctx->pc_digest_info.dt_mode.dm_sha3 == ALC_SHAKE_256) {
        *outl = outsize;
        err   = alcp_digest_set_output_size(&(dctx->handle), *outl);
        if (alcp_is_error(err)) {
            printf("Provider: Failed to set SHAKE Digest Length");
            return 0;
        }
    } else {
        *outl = dctx->pc_digest_info.dt_len / 8;
    }
    err = alcp_digest_finalize(&(dctx->handle), NULL, 0);
    if (alcp_is_error(err)) {
        printf("Provider: Failed to Finalize\n");
        return 0;
    }
    err = alcp_digest_copy(&(dctx->handle), out, (Uint64)*outl);
    if (alcp_is_error(err)) {
        printf("Provider: Failed to copy Hash\n");
        return 0;
    }
    OPENSSL_free(dctx->handle.context);
    EXIT();
    return 1;
}

static const char DIGEST_DEF_PROP[] = "provider=alcp,fips=no";

const OSSL_ALGORITHM ALC_prov_digests[] = {
    { ALCP_PROV_NAMES_SHA2_224, DIGEST_DEF_PROP, sha224_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_256, DIGEST_DEF_PROP, sha256_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_384, DIGEST_DEF_PROP, sha384_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512, DIGEST_DEF_PROP, sha512_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512_224,
      DIGEST_DEF_PROP,
      sha512_224_sha2_functions },
    { ALCP_PROV_NAMES_SHA2_512_256,
      DIGEST_DEF_PROP,
      sha512_256_sha2_functions },
    { ALCP_PROV_NAMES_SHA3_512, DIGEST_DEF_PROP, sha512_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_384, DIGEST_DEF_PROP, sha384_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_256, DIGEST_DEF_PROP, sha256_sha3_functions },
    { ALCP_PROV_NAMES_SHA3_224, DIGEST_DEF_PROP, sha224_sha3_functions },

    { ALCP_PROV_NAMES_SHAKE_128, DIGEST_DEF_PROP, shake128_sha3_functions },
    { ALCP_PROV_NAMES_SHAKE_256, DIGEST_DEF_PROP, shake256_sha3_functions },

    { NULL, NULL, NULL },
};