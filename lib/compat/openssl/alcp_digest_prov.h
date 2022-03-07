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

#ifndef _OPENSSL_ALCP_DIGEST_PROV_H
#define _OPENSSL_ALCP_DIGEST_PROV_H 2

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include <alcp/digest.h>
#include <alcp/key.h>

#include "alcp_provider.h"

#include "debug.h"

struct _alc_prov_digest_ctx
{
    /* Must be first */
    alc_prov_ctx_t*     pc_prov_ctx;
    alc_digest_handle_t handle;
    int                 enc_flag;

    int               pc_nid;
    EVP_MD*           pc_evp_digest;
    EVP_MD_CTX*       pc_evp_digest_ctx;
    const OSSL_PARAM* pc_params;

    alc_digest_info_t pc_digest_info;
    int               pc_ctx_size;
    int               pc_flags;

    OSSL_LIB_CTX* pc_libctx;
};
typedef struct _alc_prov_digest_ctx alc_prov_digest_ctx_t,
    *alc_prov_digest_ctx_p;

EVP_MD*
ALCP_prov_init_digest(alc_prov_digest_ctx_p c);
ALCP_prov_digest_init(void* vctx, const OSSL_PARAM params[]);

extern const OSSL_ALGORITHM ALC_prov_digests[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

extern void*
ALCP_prov_digest_newctx(void* vprovctx, const alc_digest_info_p cinfo);
void
ALCP_prov_digest_freectx(void* vctx);

int
ALCP_prov_digest_get_ctx_params(void* vctx, OSSL_PARAM params[]);
int
ALCP_prov_digest_set_ctx_params(void* vctx, const OSSL_PARAM params[]);
const OSSL_PARAM*
ALCP_prov_digest_gettable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_digest_settable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_digest_gettable_params(void* provctx);
int
ALCP_prov_digest_get_params(OSSL_PARAM params[], int mode);
int
ALCP_prov_digest_set_params(const OSSL_PARAM params[]);

extern OSSL_FUNC_digest_dupctx_fn         ALCP_prov_digest_dupctx;
extern OSSL_FUNC_digest_freectx_fn        ALCP_prov_digest_freectx;
extern OSSL_FUNC_digest_get_ctx_params_fn ALCP_prov_digest_get_ctx_params;
extern OSSL_FUNC_digest_set_ctx_params_fn ALCP_prov_digest_set_ctx_params;
extern OSSL_FUNC_digest_update_fn         ALCP_prov_digest_update;
extern OSSL_FUNC_digest_final_fn          ALCP_prov_digest_final;

#define CREATE_DIGEST_DISPATCHERS(name, grp, mode)                             \
    static OSSL_FUNC_digest_get_params_fn ALCP_prov_##name##_get_params;       \
    static int ALCP_prov_##name##_get_params(OSSL_PARAM* params)               \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_digest_get_params(params, mode);                      \
    }                                                                          \
                                                                               \
    static OSSL_FUNC_digest_newctx_fn ALCP_prov_##name##_newctx;               \
    static void*                      ALCP_prov_##name##_newctx(void* provctx) \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_digest_newctx(provctx, &s_digest_##name##_info);      \
    }                                                                          \
    const OSSL_DISPATCH name##_functions[] = {                                 \
        { OSSL_FUNC_DIGEST_GET_PARAMS,                                         \
          (fptr_t)ALCP_prov_##name##_get_params },                             \
        { OSSL_FUNC_DIGEST_NEWCTX, (fptr_t)ALCP_prov_##name##_newctx },        \
        { OSSL_FUNC_DIGEST_DUPCTX, (fptr_t)ALCP_prov_digest_dupctx },          \
        { OSSL_FUNC_DIGEST_FREECTX, (fptr_t)ALCP_prov_digest_freectx },        \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                    \
          (fptr_t)ALCP_prov_digest_gettable_params },                          \
        { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                \
          (fptr_t)ALCP_prov_digest_gettable_params },                          \
        { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,                                     \
          (fptr_t)ALCP_prov_##grp##_get_ctx_params },                          \
        { OSSL_FUNC_DIGEST_INIT, (fptr_t)ALCP_prov_digest_init },              \
        { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                \
          (fptr_t)ALCP_prov_digest_settable_ctx_params },                      \
        { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,                                     \
          (fptr_t)ALCP_prov_##grp##_set_ctx_params },                          \
        { OSSL_FUNC_DIGEST_UPDATE, (fptr_t)ALCP_prov_digest_update },          \
        { OSSL_FUNC_DIGEST_FINAL, (fptr_t)ALCP_prov_digest_final },            \
    }

#endif /* _OPENSSL_ALCP_prov_DIGEST_PROV_H */
