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

#ifndef _OPENSSL_ALCP_DIGEST_PROV_H
#define _OPENSSL_ALCP_DIGEST_PROV_H 2

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include <alcp/digest.h>
#include <alcp/key.h>

#include "provider/alcp_provider.h"

#include "debug.h"

struct _alc_prov_digest_ctx
{
    /* Must be first */
    alc_prov_ctx_t*     pc_prov_ctx;
    alc_digest_handle_t handle;
    alc_digest_info_t   pc_digest_info;

    OSSL_LIB_CTX* pc_libctx;
};
typedef struct _alc_prov_digest_ctx alc_prov_digest_ctx_t,
    *alc_prov_digest_ctx_p;

extern const OSSL_ALGORITHM ALC_prov_digests[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

extern void*
alcp_prov_digest_newctx(void* vprovctx, const alc_digest_info_p cinfo);

const OSSL_PARAM*
alcp_prov_digest_gettable_params(void* provctx);
int
alcp_prov_digest_get_params(OSSL_PARAM    params[],
                            size_t        blockSize,
                            size_t        digestSize,
                            unsigned long flags);

OSSL_FUNC_digest_dupctx_fn  alcp_prov_digest_dupctx;
OSSL_FUNC_digest_freectx_fn alcp_prov_digest_freectx;
OSSL_FUNC_digest_update_fn  alcp_prov_digest_update;
OSSL_FUNC_digest_final_fn   alcp_prov_digest_final;

/* Internal flags that can be queried */
#define ALCP_FLAG_XOF          0x1
#define ALCP_FLAG_ALGID_ABSENT 0x2

// ToDO : some of the variables will be removed from macro
#define DEFINE_CONTEXT(name, grp, len, alcp_mode, grp_upper_case)              \
    alc_digest_info_t s_digest_##name##_##grp##_##len##_info = {               \
        .dt_type = ALC_DIGEST_TYPE_##grp_upper_case,                           \
        .dt_len = len,                                                         \
        .dt_custom_len = len,                                              \
        .dt_mode = {                                                           \
            .dm_##grp = alcp_mode,                                             \
        },                                                                     \
};

#define OSSL_PARAM_LOCATE_SET_SIZE(params, key, param, value)                  \
    param = OSSL_PARAM_locate(params, key);                                    \
    if (param && !OSSL_PARAM_set_size_t(param, value)) {                       \
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);               \
        return 0;                                                              \
    }

#define OSSL_PARAM_LOCATE_SET_INT(params, key, param, val)                     \
    param = OSSL_PARAM_locate(params, key);                                    \
    if (param && !OSSL_PARAM_set_int(param, val)) {                            \
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);               \
        return 0;                                                              \
    }

#define DEFINE_DIGEST_GET_PARAMS(name, grp, len, blockSize, flags)             \
    static OSSL_FUNC_digest_get_params_fn                                      \
        alcp_prov_digest_##name##_##grp##_get_params;                          \
                                                                               \
    static int alcp_prov_digest_##name##_##grp##_get_params(                   \
        OSSL_PARAM params[])                                                   \
    {                                                                          \
        return alcp_prov_digest_get_params(                                    \
            params, blockSize / 8, len / 8, flags);                            \
    }

#define CREATE_DIGEST_DISPATCHERS(                                             \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
                                                                               \
    DEFINE_CONTEXT(name, grp, len, alcp_mode, grp_upper_case)                  \
                                                                               \
    static OSSL_FUNC_digest_newctx_fn alcp_prov_##name##_##grp##_newctx;       \
    static void* alcp_prov_##name##_##grp##_newctx(void* provctx)              \
    {                                                                          \
        ENTER();                                                               \
        return alcp_prov_digest_newctx(                                        \
            provctx, &s_digest_##name##_##grp##_##len##_info);                 \
    }                                                                          \
    DEFINE_DIGEST_GET_PARAMS(name, grp, len, blockSize, flags)

// ToDO : OSSL_FUNC_DIGEST_DIGEST to
// be added later. Its currently not
// implemented in OSSL provider
/*
 * Dispatchers are created by alcp_digest_sha.c using macro defined
 * above
 */
extern const OSSL_DISPATCH sha224_sha2_functions[];
extern const OSSL_DISPATCH sha256_sha2_functions[];
extern const OSSL_DISPATCH sha384_sha2_functions[];
extern const OSSL_DISPATCH sha512_sha2_functions[];
extern const OSSL_DISPATCH sha512_224_sha2_functions[];
extern const OSSL_DISPATCH sha512_256_sha2_functions[];
extern const OSSL_DISPATCH sha224_sha3_functions[];
extern const OSSL_DISPATCH sha256_sha3_functions[];
extern const OSSL_DISPATCH sha384_sha3_functions[];
extern const OSSL_DISPATCH sha512_sha3_functions[];
extern const OSSL_DISPATCH shake128_sha3_functions[];
extern const OSSL_DISPATCH shake256_sha3_functions[];

#endif /* _OPENSSL_ALCP_DIGEST_PROV_H */
