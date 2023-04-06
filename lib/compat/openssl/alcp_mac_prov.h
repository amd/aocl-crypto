/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 notice,
 *    this list of conditions and the following disclaimer in the
 documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS"
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

#ifndef _OPENSSL_ALCP_MAC_PROV_H
#define _OPENSSL_ALCP_MAC_PROV_H 2

// #include <openssl/core.h>
// #include <openssl/core_names.h>
// #include <openssl/engine.h>
// #include <openssl/evp.h>
// #include <openssl/proverr.h>

// #include <alcp/key.h>
#include <alcp/mac.h>

#include "alcp_provider.h"

#include "debug.h"

struct _alc_prov_mac_ctx
{
    /* Must be first */
    alc_prov_ctx_t*  pc_prov_ctx;
    alc_mac_handle_t handle;
    int              enc_flag;

    int               pc_nid;
    EVP_MAC*          pc_evp_mac;
    EVP_MAC_CTX*      pc_evp_mac_ctx;
    const OSSL_PARAM* pc_params;

    alc_mac_info_t pc_mac_info;
    int            pc_ctx_size;
    int            pc_flags;

    OSSL_LIB_CTX* pc_libctx;
};
typedef struct _alc_prov_mac_ctx alc_prov_mac_ctx_t, *alc_prov_mac_ctx_p;

EVP_MAC*
ALCP_prov_init_mac(alc_prov_mac_ctx_p c);
int
ALCP_prov_mac_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const OSSL_PARAM     params[]);

extern const OSSL_ALGORITHM ALC_prov_macs[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

extern void*
ALCP_prov_mac_newctx(void* vprovctx, const alc_mac_info_p cinfo);
void
ALCP_prov_mac_freectx(void* vctx);

int
ALCP_prov_mac_get_ctx_params(void* vctx, OSSL_PARAM params[]);
int
ALCP_prov_mac_set_ctx_params(void* vctx, const OSSL_PARAM params[]);
const OSSL_PARAM*
ALCP_prov_mac_gettable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_mac_settable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_mac_gettable_params(void* provctx);
int
ALCP_prov_mac_get_params(OSSL_PARAM params[], int mode);
int
ALCP_prov_mac_set_params(const OSSL_PARAM params[]);

extern OSSL_FUNC_mac_dupctx_fn         ALCP_prov_mac_dupctx;
extern OSSL_FUNC_mac_freectx_fn        ALCP_prov_mac_freectx;
extern OSSL_FUNC_mac_get_ctx_params_fn ALCP_prov_mac_get_ctx_params;
extern OSSL_FUNC_mac_set_ctx_params_fn ALCP_prov_mac_set_ctx_params;
extern OSSL_FUNC_mac_update_fn         ALCP_prov_mac_update;
extern OSSL_FUNC_mac_final_fn          ALCP_prov_mac_final;

#define CREATE_MAC_DISPATCHERS(mactype, subtype, mode)                         \
    static OSSL_FUNC_mac_get_params_fn ALCP_prov_##mactype##_get_params;       \
    static int ALCP_prov_##mactype##_get_params(OSSL_PARAM* params)            \
    {                                                                          \
        ENTER();                                                               \
        int ret = ALCP_prov_mac_get_params(params, mode);                      \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
                                                                               \
    static OSSL_FUNC_mac_newctx_fn ALCP_prov_##mactype##_newctx;               \
    static void*                   ALCP_prov_##mactype##_newctx(void* provctx) \
    {                                                                          \
        ENTER();                                                               \
        int ret = ALCP_prov_mac_newctx(provctx,                                \
                                       &s_mac_##mactype##_##subtype##_info);   \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
    const OSSL_DISPATCH mac_##mactype##_functions[] = {                        \
        { OSSL_FUNC_MAC_GET_PARAMS,                                            \
          (fptr_t)ALCP_prov_##mactype##_get_params },                          \
        { OSSL_FUNC_MAC_NEWCTX, (fptr_t)ALCP_prov_##mactype##_newctx },        \
        { OSSL_FUNC_MAC_DUPCTX, (fptr_t)ALCP_prov_mac_dupctx },                \
        { OSSL_FUNC_MAC_FREECTX, (fptr_t)ALCP_prov_mac_freectx },              \
        { OSSL_FUNC_MAC_GETTABLE_PARAMS,                                       \
          (fptr_t)ALCP_prov_mac_gettable_params },                             \
        { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                                   \
          (fptr_t)ALCP_prov_mac_gettable_params },                             \
        { OSSL_FUNC_MAC_GET_CTX_PARAMS,                                        \
          (fptr_t)ALCP_prov_##mactype##_get_ctx_params },                      \
        { OSSL_FUNC_MAC_INIT, (fptr_t)ALCP_prov_mac_init },                    \
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                                   \
          (fptr_t)ALCP_prov_mac_settable_ctx_params },                         \
        { OSSL_FUNC_MAC_SET_CTX_PARAMS,                                        \
          (fptr_t)ALCP_prov_##mactype##_set_ctx_params },                      \
        { OSSL_FUNC_MAC_UPDATE, (fptr_t)ALCP_prov_mac_update },                \
        { OSSL_FUNC_MAC_FINAL, (fptr_t)ALCP_prov_mac_final },                  \
    }

#endif /* _OPENSSL_ALCP_prov_MAC_PROV_H */
