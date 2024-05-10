
/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

#include "alcp_cipher_prov_aead.h"
#include "alcp_cipher_prov_aead_gcm.h"

// done:MMM
static void*
ALCP_prov_alg_gcm_newctx(void* provctx, size_t keybits)
{
    ALCP_PROV_AES_CTX* ctx;
    ENTER();
    // printf("\n ALCP_prov_alg_gcm_newctx %ld \n", keybits);

    // if (!ossl_prov_is_running())
    // return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {

        // allocate context
        ctx->base.handle.ch_context =
            OPENSSL_malloc(alcp_cipher_aead_context_size());

        if (ctx->base.handle.ch_context == NULL) {
            printf("\n context allocation failed ");
            return NULL;
        }

        // Request handle for the cipher
        alc_error_t err = alcp_cipher_aead_request(
            ALC_AES_MODE_GCM, keybits, &(ctx->base.handle));

        if (err == ALC_ERROR_NONE) {
            ALCP_prov_gcm_initctx(provctx, &(ctx->base), keybits);
        } else {
            OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
    }
    return ctx;
}

// WIP:MMM
static void*
ALCP_prov_alg_gcm_dupctx(void* provctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx  = provctx;
    ALCP_PROV_AES_CTX* dctx = NULL;

    if (ctx == NULL)
        return NULL;

    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    if (dctx != NULL && dctx->base.prov_cipher_data.pKey != NULL)
        dctx->base.prov_cipher_data.pKey = (const Uint8*)&dctx->ks;

    return dctx;
}

static OSSL_FUNC_cipher_freectx_fn ALCP_prov_alg_gcm_freectx;

static void
ALCP_prov_alg_gcm_freectx(void* vctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx = (ALCP_PROV_AES_CTX*)vctx;

    // free alcp
    if (ctx->base.handle.ch_context != NULL) {
        alcp_cipher_finish(&(ctx->base.handle));
        OPENSSL_free(ctx->base.handle.ch_context);
        ctx->base.handle.ch_context = NULL;
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

#if 1 // to be removed. kept for understanding.
static OSSL_FUNC_cipher_get_params_fn aes_128_gcm_get_params;
static int
aes_128_gcm_get_params(OSSL_PARAM params[])
{
    ENTER();
    return ALCP_prov_cipher_generic_get_params(
        params, 0x6, (0x0001 | 0x0002), 128, 8, 96);
}
static OSSL_FUNC_cipher_newctx_fn aes128gcm_newctx;
static void*
aes128gcm_newctx(void* provctx)
{
    // printf("\n aes128gcm_newctx");
    return ALCP_prov_alg_gcm_newctx(provctx, 128);
}
static void*
aes128gcm_dupctx(void* src)
{
    return ALCP_prov_alg_gcm_dupctx(src);
}
const OSSL_DISPATCH ALCP_prov_aes128gcm_functions[] = {
    { 1, (void (*)(void))aes128gcm_newctx },
    { 7, (void (*)(void))ALCP_prov_alg_gcm_freectx },
    { 8, (void (*)(void))aes128gcm_dupctx },
    { 2, (void (*)(void))ALCP_prov_gcm_einit },
    { 3, (void (*)(void))ALCP_prov_gcm_dinit },
    { 4, (void (*)(void))ALCP_prov_gcm_stream_update },
    { 5, (void (*)(void))ALCP_prov_gcm_stream_final },
    { 6, (void (*)(void))ALCP_prov_gcm_cipher },
    { 9, (void (*)(void))aes_128_gcm_get_params },
    { 10, (void (*)(void))ALCP_prov_gcm_get_ctx_params },
    { 11, (void (*)(void))ALCP_prov_gcm_set_ctx_params },
    { 0, ((void*)0) }
};

#else

/* ossl_aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);

#endif

/* ossl_aes192gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96);

/* ossl_aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);
