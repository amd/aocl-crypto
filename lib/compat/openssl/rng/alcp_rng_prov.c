/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "provider/alcp_names.h"
#include "rng/alcp_rng_prov.h"

static const char CIPHER_DEF_PROP[] = "provider=alcp,fips=no";

void
ALCP_prov_rng_freectx(void* vdrbg)
{
    ENTER();
    alc_prov_rng_ctx_p context = vdrbg;
    if (context->init_flag) {
        ALCP_prov_rng_uninstantiate(vdrbg);
    }
    OPENSSL_free(vdrbg);
    EXIT();
}

void*
ALCP_prov_rng_newctx(void*                provctx,
                     void*                parent,
                     const OSSL_DISPATCH* parent_dispatch)
{
    ENTER();

    alc_prov_rng_ctx_p context = OPENSSL_malloc(sizeof(alc_prov_rng_ctx_t));
    context->init_flag         = false;

    EXIT();
    return context;
}

const OSSL_PARAM*
ALCP_prov_rng_gettable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, NULL),
        ALCP_RNG_GETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    EXIT();
    return known_gettable_ctx_params;
}

const OSSL_PARAM*
ALCP_prov_rng_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, NULL),
        ALCP_RNG_SETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
    EXIT();
}

int
ALCP_prov_rng_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    OSSL_PARAM* p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 1000)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }
    EXIT();
    return 1;
}

int
ALCP_prov_rng_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

int
ALCP_prov_rng_instantiate(void*                vdrbg,
                          unsigned int         strength,
                          int                  prediction_resistance,
                          const unsigned char* pstr,
                          size_t               pstr_len,
                          const OSSL_PARAM     params[])
{
    ENTER();

    // Setup what we want from ALCP
    alc_prov_rng_ctx_p context      = vdrbg;
    context->pc_rng_info.ri_distrib = ALC_RNG_DISTRIB_UNIFORM;
    context->pc_rng_info.ri_source  = ALC_RNG_SOURCE_ARCH; // Use SEC RNG
    context->pc_rng_info.ri_type    = ALC_RNG_TYPE_DISCRETE;

    // Check if that is possible, if not try another way
    if (alcp_is_error(alcp_rng_supported(&(context->pc_rng_info)))) {
        context->pc_rng_info.ri_source = ALC_RNG_SOURCE_OS; // 2nd best OS
        if (alcp_is_error(alcp_rng_supported(&(context->pc_rng_info))))
            return 0; // error
    }

    // Allocate memory for the context
    context->handle.rh_context =
        malloc(alcp_rng_context_size(&(context->pc_rng_info)));

    // Create the session
    if (alcp_is_error(
            alcp_rng_request(&(context->pc_rng_info), &(context->handle)))) {
        return 0; // error
    }

    context->init_flag = true;

    EXIT();
    return 1;
}

int
ALCP_prov_rng_uninstantiate(void* drbg)
{
    ENTER();
    alc_prov_rng_ctx_p context = drbg;
    alcp_rng_finish(&(context->handle)); // Tear down ALCP session

    context->init_flag = false;

    free(context->handle.rh_context); // Release context memory

    EXIT();
    return 1;
}

int
ALCP_prov_rng_generate(void*                vdrbg,
                       unsigned char*       out,
                       size_t               outlen,
                       unsigned int         strength,
                       int                  prediction_resistance,
                       const unsigned char* adin,
                       size_t               adin_len)
{
    ENTER();
    memset(out, 0, outlen);
    alc_prov_rng_ctx_p context = vdrbg;
    if (alcp_is_error(alcp_rng_gen_random(&(context->handle), out, outlen))) {
        return 0; // Error
    }
    EXIT();
    return 1;
}

int
ALCP_prov_rng_enable_locking(void* vctx)
{
    ENTER();
    EXIT();
    return 1;
}
int
ALCP_prov_rng_lock(void* vctx)
{
    ENTER();
    EXIT();
    return 1;
}
void
ALCP_prov_rng_unlock(void* vctx)
{
    ENTER();
    EXIT();
}

CREATE_RNG_DISPATCHERS();

const OSSL_ALGORITHM ALC_prov_rng[] = {
    { ALCP_PROV_NAMES_CTR_DRBG, CIPHER_DEF_PROP, rng_functions },
    { ALCP_PROV_NAMES_HASH_DRBG, CIPHER_DEF_PROP, rng_functions },
    { ALCP_PROV_NAMES_HMAC_DRBG, CIPHER_DEF_PROP, rng_functions },
    { ALCP_PROV_NAMES_TEST_RAND, CIPHER_DEF_PROP, rng_functions },
    { NULL, NULL, NULL },
};
