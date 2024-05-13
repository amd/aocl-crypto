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

#include "alcp_mac_prov.h"
#include "provider/alcp_names.h"

void
alcp_prov_mac_freectx(void* vctx)
{
    ENTER();
    alc_prov_mac_ctx_p mctx = vctx;
    alc_error_t        err  = alcp_mac_finish(&(mctx->handle));
    if (alcp_is_error(err)) {
        printf("MAC Provider: Error in MAC Finish\n");
    }
    OPENSSL_free(mctx->handle.ch_context);
    mctx->handle.ch_context = NULL;
    OPENSSL_free(vctx);
    EXIT();
}

void*
alcp_prov_mac_newctx(alc_mac_type_t mac_type)
{
    ENTER();

    alc_prov_mac_ctx_p mac_ctx;
    mac_ctx = OPENSSL_zalloc(sizeof(*mac_ctx));

    if (mac_ctx != NULL) {
        Uint64 size                = alcp_mac_context_size();
        mac_ctx->handle.ch_context = OPENSSL_malloc(size);
        alc_error_t err = alcp_mac_request(&(mac_ctx->handle), mac_type);
        if (alcp_is_error(err)) {
            printf("MAC Provider: Request Failed\n");
            OPENSSL_clear_free(mac_ctx->handle.ch_context, size);
            OPENSSL_clear_free(mac_ctx, sizeof(*mac_ctx));
            return NULL;
        }
    }

    EXIT();
    return mac_ctx;
}

void*
alcp_prov_mac_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implementation pending for context copy
    alc_prov_mac_ctx_p csrc = vctx;

    EXIT();
    return csrc;
}

/*-
 * Generic mac functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM mac_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_DIGEST, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_CIPHER, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
alcp_prov_mac_gettable_params(void* provctx)
{
    ENTER();

    EXIT();
    return mac_known_gettable_params;
}

int
alcp_prov_mac_get_params(OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

const OSSL_PARAM*
alcp_prov_mac_gettable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return 0;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
alcp_prov_mac_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return 0;
}

int
alcp_prov_mac_set_params(const OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

int
alcp_prov_mac_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

int
alcp_prov_mac_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    int ret = 0;

    const OSSL_PARAM* p_cipher =
        OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p_cipher != NULL) {
        char* cipher = p_cipher->data;
        if (!strcasecmp(cipher, "aes128") || !strcasecmp(cipher, "aes192")
            || !strcasecmp(cipher, "aes256")
            || !strcasecmp(cipher, "aes-128-cbc")
            || !strcasecmp(cipher, "aes-192-cbc")
            || !strcasecmp(cipher, "aes-256-cbc")) {
            return 1;
        } else {
            printf("CMAC Provider: Cipher '%s' not supported\n", cipher);
        }
    }

    EXIT();
    return ret;
}
int
alcp_prov_mac_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const OSSL_PARAM     params[])
{
    ENTER();

    EXIT();
    return 1;
}

int
alcp_prov_mac_update(void* vctx, const unsigned char* in, size_t inl)
{
    ENTER();

    alc_error_t        err;
    alc_prov_mac_ctx_p cctx = vctx;
    err                     = alcp_mac_update(&(cctx->handle), in, inl);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Update Failed\n");
        EXIT();
        return 0;
    }
    EXIT();
    return 1;
}

int
alcp_prov_mac_final(void*          vctx,
                    unsigned char* out,
                    size_t*        outl,
                    size_t         outsize)
{
    ENTER();
    alc_error_t        err  = ALC_ERROR_NONE;
    alc_prov_mac_ctx_p mctx = vctx;
    err = alcp_mac_finalize(&(mctx->handle), out, (Uint64)outsize);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Failed to Finalize\n");
        return 0;
    }

    // alcp_mac_reset(&(mctx->handle));

    *outl = outsize;
    EXIT();
    return 1;
}

static const char MAC_DEF_PROP[] = "provider=alcp,fips=no";

// extern const OSSL_DISPATCH cmac_functions[];
extern const OSSL_DISPATCH hmac_functions[];

const OSSL_ALGORITHM ALC_prov_macs[] = {
    //{ alcp_PROV_NAMES_CMAC, MAC_DEF_PROP, cmac_functions },
    { ALCP_PROV_NAMES_HMAC, MAC_DEF_PROP, hmac_functions },
    { NULL, NULL, NULL },
};
