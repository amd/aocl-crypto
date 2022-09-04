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

#ifndef _OPENSSL_ALCP_RNG_PROV_H
#define _OPENSSL_ALCP_RNG_PROV_H 2

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include <alcp/key.h>
#include <alcp/rng.h>

#include "alcp_provider.h"

#include "debug.h"

struct _alc_prov_rng_ctx
{
    /* Must be first */
    alc_prov_ctx_t*  pc_prov_ctx;
    alc_rng_handle_t handle;
    int              enc_flag;

    int               pc_nid;
    EVP_RAND*         pc_evp_rng;
    EVP_RAND_CTX*     pc_evp_rng_ctx;
    const OSSL_PARAM* pc_params;

    alc_rng_info_t pc_rng_info;
    int            pc_ctx_size;
    int            pc_flags;

    OSSL_LIB_CTX* pc_libctx;
};
typedef struct _alc_prov_rng_ctx alc_prov_rng_ctx_t, *alc_prov_rng_ctx_p;

extern const OSSL_ALGORITHM ALC_prov_rng[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

/* Function prototypes (definitions) */
extern OSSL_FUNC_rand_newctx_fn        ALCP_prov_rng_newctx;
extern OSSL_FUNC_rand_freectx_fn       ALCP_prov_rng_freectx;
extern OSSL_FUNC_rand_instantiate_fn   ALCP_prov_rng_instantiate;
extern OSSL_FUNC_rand_uninstantiate_fn ALCP_prov_rng_uninstantiate;
extern OSSL_FUNC_rand_generate_fn      ALCP_prov_rng_generate;
// extern OSSL_FUNC_rand_reseed_fn              ALCP_prov_rng_reseed;
extern OSSL_FUNC_rand_settable_ctx_params_fn ALCP_prov_rng_settable_ctx_params;
extern OSSL_FUNC_rand_set_ctx_params_fn      ALCP_prov_rng_set_ctx_params;
extern OSSL_FUNC_rand_gettable_ctx_params_fn ALCP_prov_rng_settable_ctx_params;
extern OSSL_FUNC_rand_get_ctx_params_fn      ALCP_prov_rng_get_ctx_params;
// extern OSSL_FUNC_rand_verify_zeroization_fn  ALCP_prov_rng_verzero;
extern OSSL_FUNC_rand_enable_locking_fn ALCP_prov_rng_enable_locking;
extern OSSL_FUNC_rand_lock_fn           ALCP_prov_rng_lock;
extern OSSL_FUNC_rand_unlock_fn         ALCP_prov_rng_unlock;

#define RNG_CONTEXT()                                                          \
    static alc_rng_info_t s_rng_info = { .ri_distrib =                         \
                                             ALC_RNG_DISTRIB_UNIFORM,          \
                                         .ri_source = ALC_RNG_SOURCE_OS,       \
                                         .ri_type   = ALC_RNG_TYPE_DESCRETE }

// TODO: Implement functions which are NULL
#define CREATE_RNG_DISPATCHERS()                                               \
    const OSSL_DISPATCH rng_functions[] = {                                    \
        { OSSL_FUNC_RAND_NEWCTX, (fptr_t)ALCP_prov_rng_newctx },               \
        { OSSL_FUNC_RAND_FREECTX, (fptr_t)ALCP_prov_rng_freectx },             \
        { OSSL_FUNC_RAND_INSTANTIATE, (fptr_t)ALCP_prov_rng_instantiate },     \
        { OSSL_FUNC_RAND_UNINSTANTIATE, (fptr_t)ALCP_prov_rng_uninstantiate }, \
        { OSSL_FUNC_RAND_GENERATE, (fptr_t)ALCP_prov_rng_generate },           \
        { OSSL_FUNC_RAND_RESEED, NULL },                                       \
        { OSSL_FUNC_RAND_ENABLE_LOCKING,                                       \
          (fptr_t)ALCP_prov_rng_enable_locking },                              \
        { OSSL_FUNC_RAND_LOCK, (fptr_t)ALCP_prov_rng_lock },                   \
        { OSSL_FUNC_RAND_UNLOCK, (fptr_t)ALCP_prov_rng_unlock },               \
        { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,                                  \
          (fptr_t)ALCP_prov_rng_settable_ctx_params },                         \
        { OSSL_FUNC_RAND_SET_CTX_PARAMS,                                       \
          (fptr_t)ALCP_prov_rng_set_ctx_params },                              \
        { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,                                  \
          (fptr_t)ALCP_prov_rng_gettable_ctx_params },                         \
        { OSSL_FUNC_RAND_GET_CTX_PARAMS,                                       \
          (fptr_t)ALCP_prov_rng_get_ctx_params },                              \
        { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, NULL },                           \
        { OSSL_FUNC_RAND_GET_SEED, NULL },                                     \
        { OSSL_FUNC_RAND_CLEAR_SEED, NULL },                                   \
        { 0, NULL }                                                            \
    }

#define ALCP_RNG_GETTABLE_CTX_COMMON                                           \
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),                               \
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),                       \
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),                  \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, NULL),               \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, NULL),               \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, NULL),                 \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, NULL),                 \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, NULL),                  \
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, NULL),                  \
        OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, NULL),                 \
        OSSL_PARAM_time_t(OSSL_DRBG_PARAM_RESEED_TIME, NULL),                  \
        OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, NULL),                \
        OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, NULL)

#define ALCP_RNG_SETTABLE_CTX_COMMON                                           \
    OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, NULL),                    \
        OSSL_PARAM_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, NULL)

#endif /* _OPENSSL_ALCP_prov_RNG_PROV_H */