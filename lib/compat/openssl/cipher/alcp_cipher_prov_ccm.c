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

#include "alcp_cipher_prov_aead_ccm.h"
static void*
ALCP_prov_alg_ccm_newctx(void* provctx, size_t keybits)
{
    ALCP_PROV_CCM_CTX* ctx;
    ENTER();

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {

        // allocate context
        ctx->handle.ch_context =
            OPENSSL_malloc(alcp_cipher_aead_context_size());

        if (ctx->handle.ch_context == NULL) {
            printf("\n context allocation failed ");
            return NULL;
        }

        // Request handle for the cipher
        alc_error_t err =
            alcp_cipher_aead_request(ALC_AES_MODE_CCM, keybits, &(ctx->handle));

        ctx->prov_cipher_data = ctx->prov_cipher_data;

        if (ctx->prov_cipher_data == NULL) {
            OPENSSL_clear_free(ctx, sizeof(*ctx));
            return NULL;
        }

        if (err == ALC_ERROR_NONE) {
            ALCP_prov_ccm_initctx(ctx, keybits);
        } else {
            OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
    }
    return ctx;
}

// FIXME: Revisit once ALCP Copy API has been implemented
static void*
ALCP_prov_alg_ccm_dupctx(void* provctx)
{
    ENTER();
    ALCP_PROV_AES_CTX* ctx  = provctx;
    ALCP_PROV_AES_CTX* dctx = NULL;

    if (ctx == NULL)
        return NULL;

    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    if (dctx != NULL && dctx->base.prov_cipher_data->pKey != NULL)
        dctx->base.prov_cipher_data->pKey = (const Uint8*)&dctx->ks;

    return dctx;
}

static void
ALCP_prov_alg_ccm_freectx(void* vctx)
{
    ENTER();
    ALCP_PROV_CCM_CTX* ctx = (ALCP_PROV_CCM_CTX*)vctx;

    // free alcp
    if (ctx->handle.ch_context != NULL) {
        alcp_cipher_finish(&(ctx->handle));
        OPENSSL_free(ctx->handle.ch_context);
        ctx->handle.ch_context = NULL;
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 192, 8, 96);
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 256, 8, 96);
