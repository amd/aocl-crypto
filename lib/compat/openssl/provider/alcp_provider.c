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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "provider/alcp_provider.h"

static void
ALCP_prov_freectx(alc_prov_ctx_t* alcpctx)
{
    if (alcpctx != NULL) {
        if (alcpctx->ap_libctx != NULL) {
            OSSL_LIB_CTX_free(alcpctx->ap_libctx);
        }
        OPENSSL_free(alcpctx);
    }
}

#define LOAD_DEFAULT_PROV 0 // to be explored.

#if LOAD_DEFAULT_PROV
OSSL_PROVIDER* prov_openssl_default;
#endif

static const OSSL_ALGORITHM*
ALCP_query_operation(void* vctx, int operation_id, int* no_cache)
{
    ENTER();
    *no_cache = 0;

#if LOAD_DEFAULT_PROV
    static bool is_alcp_prov_init_done = false;
    prov_openssl_default               = OSSL_PROVIDER_load(NULL, "default");

    if (is_alcp_prov_init_done == false) {
        EVP_set_default_properties(NULL, "provider=alcp,fips=no");
        is_alcp_prov_init_done = true;
    }
#endif
    switch (operation_id) {
        /*FIXME: When Cipher Provider is enabled and MAC provider is
         * disabled, CMAC will fail with OpenSSL Provider as OpenSSL
         * internally tries to use CBC from alcp and multi update is not
         * supported in ALCP as of now.  */
        case OSSL_OP_CIPHER:
            return ALC_prov_ciphers;
            break;
        /*  FIXME: Disabled MAC,Digest and RNG Providers as of now to shift
            focus to Cipher Provider Apps Integration*/
        case OSSL_OP_DIGEST:
            return ALC_prov_digests;
            break;

#if 0
        case OSSL_OP_MAC:
            EXIT();
            return ALC_prov_macs;
            break;
        case OSSL_OP_RAND:
            EXIT();
            return ALC_prov_rng;
            break;
#endif
        default:
            break;
    }

#if LOAD_DEFAULT_PROV
    return OSSL_PROVIDER_query_operation(
        prov_openssl_default, operation_id, no_cache);
#else
    return NULL;
#endif
}

/* The error reasons used here */
#define ALCP_ERROR_NO_KEYLEN_SET     1
#define ALCP_ERROR_ONGOING_OPERATION 2
#define ALCP_ERROR_INCORRECT_KEYLEN  3
static const OSSL_ITEM reason_strings[] = {
    { ALCP_ERROR_NO_KEYLEN_SET, "no key length has been set" },
    { ALCP_ERROR_ONGOING_OPERATION, "an operation is underway" },
    { ALCP_ERROR_INCORRECT_KEYLEN, "incorrect key length" },
    { 0, NULL }
};

static const OSSL_ITEM*
ALCP_get_reason_strings(void* vctx)
{
    ENTER();
    return reason_strings;
}

static int
ALCP_get_params(void* provctx, OSSL_PARAM* params)
{
    OSSL_PARAM* p;
    char static BUILDTYPE[100];

    ENTER();

    if ((p = OSSL_PARAM_locate(params, "version")) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, alcp_get_version()))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "buildinfo")) != NULL
        && BUILDTYPE[0] != '\0' && !OSSL_PARAM_set_utf8_ptr(p, BUILDTYPE))
        return 0;

    EXIT();
    return 1;
}

static void
ALCP_teardown(void* vctx)
{
    ENTER();
    ALCP_prov_freectx(vctx);
}

typedef void (*fptr_t)(void);

static const OSSL_DISPATCH ALC_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (fptr_t)ALCP_query_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (fptr_t)ALCP_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (fptr_t)ALCP_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (fptr_t)ALCP_teardown },
    { 0, NULL }
};

#define ALCP_PROV_AS_LIBRARY 0
#if ALCP_PROV_AS_LIBRARY
/*
 * This allows the prov to be built in library form.  In this case, the
 * application must add it explicitly like this:
 *
 * OSSL_PROV_add_builtin(NULL, "alcp", alcp_prov_init);
 */
#define OSSL_provider_init alcp_prov_init
#endif

OPENSSL_EXPORT
int
OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
                   const OSSL_DISPATCH*    in,
                   const OSSL_DISPATCH**   out,
                   void**                  vprovctx)
{
    alc_prov_ctx_t* alcpctx = NULL;
    *vprovctx               = NULL;

    ENTER();

    alcpctx = OPENSSL_zalloc(sizeof(alc_prov_ctx_t));

    if (alcpctx == NULL) {
        printf("\n alcp provider init failed");
        return 0;
    } else {
#if LOAD_DEFAULT_PROV
        alcpctx->ap_libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
#else
        alcpctx->ap_libctx = OSSL_LIB_CTX_new();
#endif
        if (alcpctx->ap_libctx == NULL) {
            ALCP_teardown((void*)alcpctx);
            return 0;
        }
        alcpctx->ap_core_handle = handle;
    }

    *out      = ALC_dispatch_table;
    *vprovctx = (void*)alcpctx;

    return 1;
}
