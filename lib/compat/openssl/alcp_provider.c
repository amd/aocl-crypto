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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "alcp_provider.h"

static void
ALCP_prov_freectx(alc_prov_ctx_t* ctx)
{
    if (ctx != NULL) {
        // ENGINE_free(ctx->e);
        // proverr_free_handle(ctx->proverr_handle);
        /* Below line commented because of segmentation fault*/
        // OSSL_LIB_CTX_free(ctx->ap_libctx);
    }

    // OPENSSL_free(ctx);
}

static alc_prov_ctx_t*
ALCP_prov_newctx(const OSSL_CORE_HANDLE* core, const OSSL_DISPATCH* in)
{
    alc_prov_ctx_t* ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx) {
        // ctx->proverr_handle = proverr_new_handle(core, in));

        ctx->ap_libctx = OSSL_LIB_CTX_new_child(core, in);

        ctx->ap_core_handle = core;
    } else {
        ctx = NULL;
        goto out;
    }

out:
    ALCP_prov_freectx(ctx);
    return ctx;
}

static const OSSL_ALGORITHM*
ALCP_query_operation(void* vctx, int operation_id, const int* no_cache)
{
    ENTER();
    switch (operation_id) {
        case OSSL_OP_CIPHER:
            EXIT();
            return ALC_prov_ciphers;
            break;
        default:
            break;
    }

    return NULL;
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
    OSSL_PARAM*        p;
    const static char* VERSION = "1.0";
    char static BUILDTYPE[100];

    ENTER();

    if ((p = OSSL_PARAM_locate(params, "version")) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, VERSION))
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
OSSL_provider_init(const OSSL_CORE_HANDLE* core,
                   const OSSL_DISPATCH*    in,
                   const OSSL_DISPATCH**   out,
                   void**                  vprovctx)
{
    alc_prov_ctx_p ctx;
    ENTER();
    ctx = ALCP_prov_newctx(core, in);

    if (!ctx)
        return 0;

    *out      = ALC_dispatch_table;
    *vprovctx = ctx;

    return 1;
}
