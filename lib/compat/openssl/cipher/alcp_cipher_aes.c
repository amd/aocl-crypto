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

#include "cipher/alcp_cipher_aes.h"
#include "alcp_cipher_prov_common.h"

// CIPHER_CONTEXT(cfb, ALC_AES_MODE_CFB);
// CIPHER_CONTEXT(cbc, ALC_AES_MODE_CBC);
// CIPHER_CONTEXT(ofb, ALC_AES_MODE_OFB);
// CIPHER_CONTEXT(ctr, ALC_AES_MODE_CTR);
// CIPHER_CONTEXT(xts, ALC_AES_MODE_XTS);
// CIPHER_AEAD_CONTEXT(gcm, ALC_AES_MODE_GCM);
// CIPHER_AEAD_CONTEXT(ccm, ALC_AES_MODE_CCM);
// CIPHER_AEAD_CONTEXT(siv, ALC_AES_MODE_SIV);

#if 0
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 256, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 256, true);
#endif

static OSSL_FUNC_cipher_freectx_fn aes_freectx;
static OSSL_FUNC_cipher_dupctx_fn  aes_dupctx;

static void
aes_freectx(void* vctx)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;

    // free alcp
    if (ctx->handle.ch_context != NULL) {
        alcp_cipher_finish(&(ctx->handle));
        OPENSSL_free(ctx->handle.ch_context);
        ctx->handle.ch_context = NULL;
    }

    ALCP_prov_cipher_generic_reset_ctx((ALCP_PROV_CIPHER_CTX*)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

// FIXME: to be implemented
static void*
aes_dupctx(void* ctx)
{
    // ALCP_PROV_AES_CTX* in = (ALCP_PROV_AES_CTX*)ctx;
    ALCP_PROV_CIPHER_CTX* ret;

    // if (!ossl_prov_is_running())
    //  return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    // in->base->copyctx(&ret->base, &in->base);

    return ret;
}

// dummy function
bool
alcp_prov_is_running(void)
{
    return true;
}

/* ossl_aes256cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
    /* ossl_aes192cbc_functions */
    IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
    /* ossl_aes128cbc_functions */
    IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)

    /* ossl_aes256ofb_functions */
    IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
    /* ossl_aes192ofb_functions */
    IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
    /* ossl_aes128ofb_functions */
    IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)

    /* ossl_aes256ctr_functions */
    IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
    /* ossl_aes192ctr_functions */
    IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
    /* ossl_aes128ctr_functions */
    IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)

    /* ossl_aes256cfb_functions */
    IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 256, 8, 128, stream)
    /* ossl_aes192cfb_functions */
    IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 192, 8, 128, stream)
    /* ossl_aes128cfb_functions */
    IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 128, 8, 128, stream)
