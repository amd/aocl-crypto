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

// CIPHER_CONTEXT(cfb, ALC_AES_MODE_CFB);
// CIPHER_CONTEXT(cbc, ALC_AES_MODE_CBC);
// CIPHER_CONTEXT(ofb, ALC_AES_MODE_OFB);
// CIPHER_CONTEXT(ctr, ALC_AES_MODE_CTR);
// CIPHER_CONTEXT(xts, ALC_AES_MODE_XTS);
// CIPHER_AEAD_CONTEXT(gcm, ALC_AES_MODE_GCM);
// CIPHER_AEAD_CONTEXT(ccm, ALC_AES_MODE_CCM);
// CIPHER_AEAD_CONTEXT(siv, ALC_AES_MODE_SIV);

#if 0

int
ALCP_prov_aes_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    EXIT();
    return ALCP_prov_cipher_get_ctx_params(vctx, params);
}

int
ALCP_prov_aes_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    EXIT();
    return ALCP_prov_cipher_set_ctx_params(vctx, params);
}

void
ALCP_prov_aes_ctxfree(alc_prov_cipher_ctx_t* ciph_ctx)
{
    ALCP_prov_cipher_freectx(ciph_ctx);
}

void*
ALCP_prov_aes_newctx(void* vprovctx, const void* cinfo, bool is_aead)
{
    alc_prov_cipher_ctx_t* ciph_ctx;

    ENTER();
    ciph_ctx = ALCP_prov_cipher_newctx(vprovctx, (const void*)cinfo, is_aead);
    if (!ciph_ctx)
        goto out;

    EXIT();
    return ciph_ctx;

out:
    ALCP_prov_cipher_freectx(ciph_ctx);

    return NULL;
}
#endif

#if 0
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 256, false);

CREATE_CIPHER_DISPATCHERS(xts, aes, EVP_CIPH_XTS_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(xts, aes, EVP_CIPH_XTS_MODE, 256, false);
#endif
#if 0
static OSSL_FUNC_cipher_get_params_fn ALCP_prov_gcm_get_params_128;
static int
ALCP_prov_gcm_get_params_128(OSSL_PARAM* params)
{
    ;
    return ALCP_prov_cipher_get_params(params, 0x6, 128, true);
}
static OSSL_FUNC_cipher_newctx_fn ALCP_prov_gcm_newctx_128;
static void*
ALCP_prov_gcm_newctx_128(void* provctx)
{
    ;
    return ALCP_prov_aes_newctx(provctx, &s_cipher_gcm_info, true);
}
static OSSL_FUNC_cipher_decrypt_init_fn ALCP_prov_gcm_decrypt_init_128;
static int
ALCP_prov_gcm_decrypt_init_128(void*                vctx,
                               const unsigned char* key,
                               size_t               keylen,
                               const unsigned char* iv,
                               size_t               ivlen,
                               const OSSL_PARAM     params[])
{
    ;
    return ALCP_prov_cipher_gcm_decrypt_init(vctx, key, 128, iv, ivlen, params);
}
static int
ALCP_prov_gcm_encrypt_init_128(void*                vctx,
                               const unsigned char* key,
                               size_t               keylen,
                               const unsigned char* iv,
                               size_t               ivlen,
                               const OSSL_PARAM     params[])
{
    ;
    return ALCP_prov_cipher_gcm_encrypt_init(vctx, key, 128, iv, ivlen, params);
}
const OSSL_DISPATCH gcm_functions_128[] = { { 9, (fptr_t)ALCP_prov_gcm_get_params_128 },
                                             { 1, (fptr_t)ALCP_prov_gcm_newctx_128 },
                                              { 8, (fptr_t)ALCP_prov_cipher_dupctx }, 
                                              { 7, (fptr_t)ALCP_prov_cipher_freectx }, 
                                              { 12, (fptr_t)ALCP_prov_cipher_gettable_params }, 
                                              { 13, (fptr_t)ALCP_prov_cipher_gettable_params }, 
                                              { 10, (fptr_t)ALCP_prov_aes_get_ctx_params }, 
                                              { 14, (fptr_t)ALCP_prov_cipher_settable_ctx_params }, 
                                              { 11, (fptr_t)ALCP_prov_aes_set_ctx_params }, 
                                              { 2, (fptr_t)ALCP_prov_gcm_encrypt_init_128 }, 
                                              { 3, (fptr_t)ALCP_prov_gcm_decrypt_init_128 },
                                               { 4, (fptr_t)ALCP_prov_cipher_gcm_update },
                                                { 5, (fptr_t)ALCP_prov_cipher_final }, }
#else
// CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 128, true);
#endif
// CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 192, true);
// CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 256, true);

#if 0
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 256, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 256, true);
#endif