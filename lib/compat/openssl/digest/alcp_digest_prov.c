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

#include "digest/alcp_digest_prov.h"
#include "provider/alcp_names.h"

void
alcp_prov_digest_freectx(void* vctx)
{
    alc_prov_digest_ctx_p pdctx = vctx;
    ENTER();

    OPENSSL_free(pdctx->handle.context);
    OPENSSL_clear_free(vctx, sizeof(*pdctx));
}

void*
alcp_prov_digest_newctx(void* vprovctx, const alc_digest_info_p dinfo)
{
    alc_prov_digest_ctx_p dig_ctx;
    alc_prov_ctx_p        pctx = (alc_prov_ctx_p)vprovctx;

    ENTER();

    dig_ctx = OPENSSL_zalloc(sizeof(*dig_ctx));
    if (dig_ctx != NULL) {
        dig_ctx->pc_prov_ctx    = pctx;
        dig_ctx->pc_libctx      = pctx->ap_libctx;
        dig_ctx->pc_digest_info = *dinfo;
        Uint64 size             = alcp_digest_context_size(dinfo);
        dig_ctx->handle.context = OPENSSL_zalloc(size);
    }

    return dig_ctx;
}

void*
alcp_prov_digest_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implementation Pending for context copy
    // This would need the deep copy implementation at the internal classes
    // It would need copy constructors in class and a copy C API
    // alc_prov_digest_ctx_p csrc = vctx;

    alc_prov_digest_ctx_p src_ctx = vctx;

    alc_prov_digest_ctx_p dest_ctx = OPENSSL_zalloc(sizeof(*src_ctx));

    if (dest_ctx != NULL) {
        dest_ctx->pc_prov_ctx    = src_ctx->pc_prov_ctx;
        dest_ctx->pc_libctx      = src_ctx->pc_libctx;
        dest_ctx->pc_digest_info = src_ctx->pc_digest_info;
        Uint64 size = alcp_digest_context_size(&src_ctx->pc_digest_info);
        dest_ctx->handle.context = OPENSSL_zalloc(size);
    } else {
        return NULL;
    }

    alc_error_t err = alcp_digest_context_copy(
        src_ctx->pc_digest_info, &src_ctx->handle, &dest_ctx->handle);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: copy failed in dupctx\n");
        OPENSSL_clear_free(dest_ctx, sizeof(*dest_ctx));
        return NULL;
    }

    EXIT();
    return dest_ctx;
}

/*-
 * Generic digest functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM digest_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
alcp_prov_digest_gettable_params(void* provctx)
{
    ENTER();
    EXIT();
    return digest_known_gettable_params;
}

int
alcp_prov_digest_get_params(OSSL_PARAM    params[],
                            size_t        blockSize,
                            size_t        digestSize,
                            unsigned long flags)
{
    ENTER();
    OSSL_PARAM* param = NULL;
    OSSL_PARAM_LOCATE_SET_SIZE(
        params, OSSL_DIGEST_PARAM_BLOCK_SIZE, param, blockSize);
    OSSL_PARAM_LOCATE_SET_SIZE(
        params, OSSL_DIGEST_PARAM_SIZE, param, digestSize);
    OSSL_PARAM_LOCATE_SET_INT(
        params, OSSL_DIGEST_PARAM_XOF, param, ((flags & ALCP_FLAG_XOF) != 0));
    OSSL_PARAM_LOCATE_SET_INT(params,
                              OSSL_DIGEST_PARAM_ALGID_ABSENT,
                              param,
                              ((flags & ALCP_FLAG_ALGID_ABSENT) != 0));
    EXIT();
    return 1;
}

int
alcp_prov_digest_update(void* vctx, const unsigned char* in, size_t inl)
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
alcp_prov_digest_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    ENTER();
    alc_error_t           err  = ALC_ERROR_NONE;
    alc_prov_digest_ctx_p dctx = vctx;

    /**
     * FIXME: EVP_MD_get_size provider need to implemented. Currently it is
     * returning zero in OpenSSL which caused outsize passed as argument to
     * this function to be zero
     * */

    // FIXME: Once EVP_MD_get_size provider is implemented calculate *outl
    // directly from outsize. Below is a temporary fix to get digest size
    // Fix : outsize is getting set as 17(should be 16) in default len mode with
    // openssl
    // below code may not be required. Its required only in default len mode
    // which can be handled from inside the core library
    if (dctx->pc_digest_info.dt_mode.dm_sha3 == ALC_SHAKE_128
        || dctx->pc_digest_info.dt_mode.dm_sha3 == ALC_SHAKE_256) {
        *outl = outsize;
        err   = alcp_digest_set_shake_length(&(dctx->handle), *outl);
        if (alcp_is_error(err)) {
            printf("Provider: Failed to set SHAKE Digest Length");
            return 0;
        }
    } else {
        *outl = dctx->pc_digest_info.dt_len / 8;
    }
    // ToDO : Merge the finalize and copy call
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
