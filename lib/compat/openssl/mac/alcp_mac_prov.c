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

int
alcp_prov_mac_update(void* vctx, const Uint8* in, Uint64 inl)
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
alcp_prov_mac_final(void* vctx, Uint8* out, Uint64* outl, Uint64 outsize)
{
    ENTER();
    alc_error_t        err  = ALC_ERROR_NONE;
    alc_prov_mac_ctx_p mctx = vctx;
    err = alcp_mac_finalize(&(mctx->handle), out, (Uint64)outsize);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Failed to Finalize\n");
        return 0;
    }

    *outl = outsize;
    EXIT();
    return 1;
}

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_MAC
static const char MAC_DEF_PROP[] = "provider=alcp,fips=no";
#endif

extern const OSSL_DISPATCH alcp_cmac_functions[];
extern const OSSL_DISPATCH alcp_hmac_functions[];
extern const OSSL_DISPATCH alcp_poly1305_functions[];

const OSSL_ALGORITHM ALC_prov_macs[] = {

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC
    { ALCP_PROV_NAMES_CMAC, MAC_DEF_PROP, alcp_cmac_functions },
#endif

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC
    { ALCP_PROV_NAMES_HMAC, MAC_DEF_PROP, alcp_hmac_functions },
#endif

#ifdef ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305
    { ALCP_PROV_NAMES_POLY1305, MAC_DEF_PROP, alcp_poly1305_functions },
#endif

    { NULL, NULL, NULL },
};
