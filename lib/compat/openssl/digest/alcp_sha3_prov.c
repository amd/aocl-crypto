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

static const OSSL_PARAM shake_known_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL), OSSL_PARAM_END
};
static inline int
shake_set_ctx_params(alc_prov_digest_ctx_p cctx, const OSSL_PARAM params[])
{
    ENTER();
    const OSSL_PARAM* param =
        OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    Uint64 digest_size = 0;
    if (param && !OSSL_PARAM_get_size_t(param, &digest_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (digest_size) {
        alc_error_t err =
            alcp_digest_set_shake_length(&(cctx->handle), digest_size);
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Failed to set SHAKE Digest Length");
            return 0;
        }
        cctx->shake_digest_size = digest_size;
    }
    EXIT();
    return 1;
}

int
alcp_prov_sha3_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;
    err = alcp_digest_init(&(cctx->handle));
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Init failed\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
alcp_prov_shake_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p pctx = vctx;
    alc_error_t           err;

    err = alcp_digest_init(&(pctx->handle));
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Init failed\n");
        return 0;
    }
    EXIT();
    return shake_set_ctx_params(pctx, params);
}

const OSSL_PARAM*
alcp_prov_shake_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return shake_known_gettable_ctx_params;
}

int
alcp_prov_shake_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p pctx = (alc_prov_digest_ctx_p)vctx;
    EXIT();
    return shake_set_ctx_params(pctx, params);
}

int
alcp_prov_shake_squeeze(void*          vctx,
                        unsigned char* out,
                        size_t*        outl,
                        size_t         outlen)
{
    ENTER();
    alc_prov_digest_ctx_p pctx = vctx;

    alc_error_t err = alcp_digest_shake_squeeze(&(pctx->handle), out, outlen);
    if (err != ALC_ERROR_NONE) {
        printf("Provider: Init failed\n");
        return 0;
    }
    *outl = outlen;
    return 1;
}

int
alcp_prov_sha3_digest_final(void*          vctx,
                            unsigned char* out,
                            size_t*        outl,
                            size_t         outsize)
{
    if (outsize == 0) {
        return 1;
    }
    *outl = outsize;
    return alcp_prov_digest_final(vctx, out, outsize);
}

int
alcp_prov_shake_digest_final(void*          vctx,
                             unsigned char* out,
                             size_t*        outl,
                             size_t         outsize)
{
    if (outsize == 0) {
        return 1;
    }
    alc_prov_digest_ctx_p dctx = vctx;
    *outl                      = dctx->shake_digest_size;
    return alcp_prov_digest_final(vctx, out, dctx->shake_digest_size);
}

#define CREATE_SHAKE_SPECIFIC_DISPATCHERS(name, len)                           \
    static int alcp_prov_##name##_shake_init(alc_prov_digest_ctx_p pctx,       \
                                             const OSSL_PARAM      params[])   \
    {                                                                          \
        pctx->shake_digest_size = len / 8;                                     \
        return alcp_prov_shake_init(pctx, params);                             \
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
        { OSSL_FUNC_DIGEST_UPDATE, (fptr_t)alcp_prov_digest_update },          

#define ALCP_CREATE_SHA3_FUNCTIONS(                                            \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
                                                                               \
    CREATE_COMMON_DEFINITIONS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
    { OSSL_FUNC_DIGEST_FINAL, (fptr_t)alcp_prov_sha3_digest_final },           \
    {OSSL_FUNC_DIGEST_INIT, (fptr_t)alcp_prov_sha3_init},                      \
    { 0, NULL}                                                                 \
    }


#define ALCP_CREATE_SHAKE_FUNCTIONS(                                           \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
    CREATE_SHAKE_SPECIFIC_DISPATCHERS(name, len)                               \
    CREATE_COMMON_DEFINITIONS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
    { OSSL_FUNC_DIGEST_FINAL, (fptr_t)alcp_prov_shake_digest_final },          \
    { OSSL_FUNC_DIGEST_INIT, (fptr_t)alcp_prov_##name##_shake_init },          \
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                    \
          (fptr_t)alcp_prov_shake_settable_ctx_params },                       \
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,                                         \
          (fptr_t)alcp_prov_shake_set_ctx_params },                            \
    /*{ OSSL_FUNC_DIGEST_SQUEEZE, (fptr_t)alcp_prov_shake_squeeze },*/         \
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
                            ALC_DIGEST_LEN_128,
                            ALC_DIGEST_BLOCK_SIZE_SHAKE_128,
                            ALC_SHAKE_128,
                            SHA3,
                            ALCP_FLAG_XOF);

ALCP_CREATE_SHAKE_FUNCTIONS(shake256,
                            sha3,
                            ALC_DIGEST_LEN_256,
                            ALC_DIGEST_BLOCK_SIZE_SHAKE_256,
                            ALC_SHAKE_256,
                            SHA3,
                            ALCP_FLAG_XOF);
