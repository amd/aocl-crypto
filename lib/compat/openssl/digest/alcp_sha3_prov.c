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

static const OSSL_PARAM digest_known_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL), OSSL_PARAM_END
};

int
alcp_prov_sha3_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;

    alc_digest_info_p dinfo = &cctx->pc_digest_info;
    err                     = alcp_digest_request(dinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Somehow request failed\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
alcp_prov_shake_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;

    alc_digest_info_p dinfo = &cctx->pc_digest_info;
    err                     = alcp_digest_request(dinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Somehow request failed\n");
        return 0;
    }

    const OSSL_PARAM* param =
        OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    Uint64 digest_size = 0;
    if (param && !OSSL_PARAM_get_size_t(param, &digest_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (digest_size) {
        err = alcp_digest_set_shake_length(&(cctx->handle), digest_size);
        if (alcp_is_error(err)) {
            printf("Provider: Failed to set SHAKE Digest Length");
            return 0;
        }
    }

    EXIT();
    return 1;
}

const OSSL_PARAM*
alcp_prov_shake_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return digest_known_gettable_ctx_params;
}

int
alcp_prov_shake_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    const OSSL_PARAM*     p;
    alc_prov_digest_ctx_p pctx = (alc_prov_digest_ctx_p)vctx;

    // SHAKE DIGEST SIZE PARAM
    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL) {
        Uint64 shake_digest_size = 0;
        if (OSSL_PARAM_get_size_t(p, &shake_digest_size)) {
            alc_error_t err =
                alcp_digest_set_shake_length(&pctx->handle, shake_digest_size);
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
// clang-format off
#define CREATE_COMMON_DEFINITIONS(                                             \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
    CREATE_DIGEST_DISPATCHERS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
    const OSSL_DISPATCH name##_##grp##_functions[] = {                         \
        { OSSL_FUNC_DIGEST_GET_PARAMS,                                         \
          (fptr_t)alcp_prov_digest_##name##_##grp##_get_params },              \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                    \
          (fptr_t)alcp_prov_digest_gettable_params },                          \
        { OSSL_FUNC_DIGEST_NEWCTX,                                             \
          (fptr_t)alcp_prov_##name##_##grp##_newctx },                         \
        { OSSL_FUNC_DIGEST_DUPCTX, (fptr_t)alcp_prov_digest_dupctx },          \
        { OSSL_FUNC_DIGEST_FREECTX, (fptr_t)alcp_prov_digest_freectx },        \
        { OSSL_FUNC_DIGEST_UPDATE, (fptr_t)alcp_prov_digest_update },          \
        { OSSL_FUNC_DIGEST_FINAL, (fptr_t)alcp_prov_digest_final },

#define ALCP_CREATE_SHA3_FUNCTIONS(                                            \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
                                                                               \
    CREATE_COMMON_DEFINITIONS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
                                                                               \
    {OSSL_FUNC_DIGEST_INIT, (fptr_t)alcp_prov_sha3_init},                      \
    { 0, NULL}                                                                 \
    }


#define ALCP_CREATE_SHAKE_FUNCTIONS(                                           \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
                                                                               \
    CREATE_COMMON_DEFINITIONS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
                                                                               \
    { OSSL_FUNC_DIGEST_INIT, (fptr_t)alcp_prov_shake_init },                   \
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                    \
          (fptr_t)alcp_prov_shake_settable_ctx_params },                       \
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,                                         \
          (fptr_t)alcp_prov_shake_set_ctx_params },                            \
    { 0, NULL }                                                                \
    }

// clang-format on
ALCP_CREATE_SHA3_FUNCTIONS(sha512,
                           sha3,
                           ALC_DIGEST_LEN_512,
                           ALC_DIGEST_BLOCK_SIZE_SHA3_512,
                           ALC_SHA3_512,
                           SHA3,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA3_FUNCTIONS(sha384,
                           sha3,
                           ALC_DIGEST_LEN_384,
                           ALC_DIGEST_BLOCK_SIZE_SHA3_384,
                           ALC_SHA3_384,
                           SHA3,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA3_FUNCTIONS(sha256,
                           sha3,
                           ALC_DIGEST_LEN_256,
                           ALC_DIGEST_BLOCK_SIZE_SHA3_256,
                           ALC_SHA3_256,
                           SHA3,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA3_FUNCTIONS(sha224,
                           sha3,
                           ALC_DIGEST_LEN_224,
                           ALC_DIGEST_BLOCK_SIZE_SHA3_224,
                           ALC_SHA3_224,
                           SHA3,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHAKE_FUNCTIONS(shake128,
                            sha3,
                            ALC_DIGEST_LEN_CUSTOM,
                            ALC_DIGEST_BLOCK_SIZE_SHAKE_128,
                            ALC_SHAKE_128,
                            SHA3,
                            ALCP_FLAG_XOF);

ALCP_CREATE_SHAKE_FUNCTIONS(shake256,
                            sha3,
                            ALC_DIGEST_LEN_CUSTOM,
                            ALC_DIGEST_BLOCK_SIZE_SHAKE_256,
                            ALC_SHAKE_256,
                            SHA3,
                            ALCP_FLAG_XOF);
