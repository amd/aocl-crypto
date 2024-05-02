/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#ifndef _OPENSSL_alcp_MAC_PROV_H
#define _OPENSSL_alcp_MAC_PROV_H 2

#if defined(WIN32) || defined(WIN64)
#define strcasecmp _stricmp
#endif

#include "debug.h"
#include "provider/alcp_provider.h"
#include <alcp/mac.h>
#include <openssl/core_names.h>
#include <string.h>

struct _alc_prov_mac_ctx
{
    alc_mac_handle_t handle;
    alc_mac_info_t   pc_mac_info;
};
typedef struct _alc_prov_mac_ctx alc_prov_mac_ctx_t, *alc_prov_mac_ctx_p;

EVP_MAC*
alcp_prov_init_mac(alc_prov_mac_ctx_p c);
int
alcp_prov_mac_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const OSSL_PARAM     params[]);

extern const OSSL_ALGORITHM ALC_prov_macs[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

extern void*
alcp_prov_mac_newctx(const alc_mac_info_p cinfo);
void
alcp_prov_mac_freectx(void* vctx);

int
alcp_prov_mac_get_ctx_params(void* vctx, OSSL_PARAM params[]);
int
alcp_prov_mac_set_ctx_params(void* vctx, const OSSL_PARAM params[]);
const OSSL_PARAM*
alcp_prov_mac_gettable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
alcp_prov_mac_settable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
alcp_prov_mac_gettable_params(void* provctx);
int
alcp_prov_mac_get_params(OSSL_PARAM params[]);
int
alcp_prov_mac_set_params(const OSSL_PARAM params[]);

extern OSSL_FUNC_mac_dupctx_fn         alcp_prov_mac_dupctx;
extern OSSL_FUNC_mac_freectx_fn        alcp_prov_mac_freectx;
extern OSSL_FUNC_mac_get_ctx_params_fn alcp_prov_mac_get_ctx_params;
extern OSSL_FUNC_mac_set_ctx_params_fn alcp_prov_mac_set_ctx_params;
extern OSSL_FUNC_mac_update_fn         alcp_prov_mac_update;
extern OSSL_FUNC_mac_final_fn          alcp_prov_mac_final;

#define CREATE_MAC_DISPATCHERS(mactype, subtype)                               \
    static OSSL_FUNC_mac_get_params_fn alcp_prov_##mactype##_get_params;       \
    static int alcp_prov_##mactype##_get_params(OSSL_PARAM* params)            \
    {                                                                          \
        ENTER();                                                               \
        int ret = alcp_prov_mac_get_params(params);                            \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
                                                                               \
    static OSSL_FUNC_mac_newctx_fn alcp_prov_##mactype##_newctx;               \
    static void*                   alcp_prov_##mactype##_newctx(void* provctx) \
    {                                                                          \
        ENTER();                                                               \
        void* ret = alcp_prov_mac_newctx(&s_mac_##mactype##_##subtype##_info); \
        EXIT();                                                                \
        return ret;                                                            \
    }                                                                          \
    const OSSL_DISPATCH mac_##mactype##_functions[] = {                        \
        { OSSL_FUNC_MAC_GET_PARAMS,                                            \
          (fptr_t)alcp_prov_##mactype##_get_params },                          \
        { OSSL_FUNC_MAC_NEWCTX, (fptr_t)alcp_prov_##mactype##_newctx },        \
        { OSSL_FUNC_MAC_DUPCTX, (fptr_t)alcp_prov_mac_dupctx },                \
        { OSSL_FUNC_MAC_FREECTX, (fptr_t)alcp_prov_mac_freectx },              \
        { OSSL_FUNC_MAC_GETTABLE_PARAMS,                                       \
          (fptr_t)alcp_prov_mac_gettable_params },                             \
        { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                                   \
          (fptr_t)alcp_prov_mac_gettable_params },                             \
        { OSSL_FUNC_MAC_GET_CTX_PARAMS,                                        \
          (fptr_t)alcp_prov_##mactype##_get_ctx_params },                      \
        { OSSL_FUNC_MAC_INIT, (fptr_t)alcp_prov_mac_init },                    \
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                                   \
          (fptr_t)alcp_prov_mac_settable_ctx_params },                         \
        { OSSL_FUNC_MAC_SET_CTX_PARAMS,                                        \
          (fptr_t)alcp_prov_##mactype##_set_ctx_params },                      \
        { OSSL_FUNC_MAC_UPDATE, (fptr_t)alcp_prov_mac_update },                \
        { OSSL_FUNC_MAC_FINAL, (fptr_t)alcp_prov_mac_final },                  \
    }

#endif /* _OPENSSL_alcp_prov_MAC_PROV_H */
