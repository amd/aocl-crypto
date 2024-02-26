/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

CIPHER_CONTEXT(cfb, ALC_AES_MODE_CFB);
CIPHER_CONTEXT(cbc, ALC_AES_MODE_CBC);
CIPHER_CONTEXT(ofb, ALC_AES_MODE_OFB);
CIPHER_CONTEXT(ecb, ALC_AES_MODE_ECB);
CIPHER_CONTEXT(ctr, ALC_AES_MODE_CTR);
CIPHER_CONTEXT(xts, ALC_AES_MODE_XTS);
CIPHER_AEAD_CONTEXT(gcm, ALC_AES_MODE_GCM);
CIPHER_AEAD_CONTEXT(ccm, ALC_AES_MODE_CCM);
CIPHER_AEAD_CONTEXT(siv, ALC_AES_MODE_SIV);

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
ALCP_prov_aes_ctxfree(alc_prov_cipher_ctx_p ciph_ctx)
{
    ALCP_prov_cipher_freectx(ciph_ctx);
}

void*
ALCP_prov_aes_newctx(void* vprovctx, const void* cinfo, bool is_aead)
{
    alc_prov_cipher_ctx_p ciph_ctx;

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

CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(ecb, aes, EVP_CIPH_ECB_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(ecb, aes, EVP_CIPH_ECB_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(ecb, aes, EVP_CIPH_ECB_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 192, false);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(xts, aes, EVP_CIPH_XTS_MODE, 128, false);
CREATE_CIPHER_DISPATCHERS(xts, aes, EVP_CIPH_XTS_MODE, 256, false);
CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(gcm, aes, EVP_CIPH_GCM_MODE, 256, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(ccm, aes, EVP_CIPH_CCM_MODE, 256, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 128, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 192, true);
CREATE_CIPHER_DISPATCHERS(siv, aes, EVP_CIPH_SIV_MODE, 256, true);
