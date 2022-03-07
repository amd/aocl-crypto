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

#include "alcp_cipher_aes.h"

static alc_cipher_info_t s_cipher_cfb_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_CFB,
        }, },
};

static alc_cipher_info_t s_cipher_cbc_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_CBC,
        }, },
};

static alc_cipher_info_t s_cipher_ofb_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_OFB,
        }, },
};

static alc_cipher_info_t s_cipher_ecb_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_ECB,
        }, },
};

static alc_cipher_info_t s_cipher_ctr_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_CTR,
        }, },
};

static alc_cipher_info_t s_cipher_xtr_info = {
    .ci_type = ALC_CIPHER_TYPE_AES,
    .ci_key_info = {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
        128,
    },
    .ci_mode_data = { .cm_aes = {
            .ai_mode =      ALC_AES_MODE_XTR,
        }, },
};

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
ALCP_prov_aes_newctx(void* vprovctx, const alc_cipher_info_p cinfo)
{
    alc_prov_cipher_ctx_p ciph_ctx;

    ENTER();

    ciph_ctx = ALCP_prov_cipher_newctx(vprovctx, cinfo);
    if (!ciph_ctx)
        goto out;

    EXIT();
    return ciph_ctx;

out:
    ALCP_prov_cipher_freectx(ciph_ctx);

    return NULL;
}

/* cfb_functions */
CREATE_CIPHER_DISPATCHERS(cfb, aes, EVP_CIPH_CFB_MODE);
CREATE_CIPHER_DISPATCHERS(cbc, aes, EVP_CIPH_CBC_MODE);
CREATE_CIPHER_DISPATCHERS(ofb, aes, EVP_CIPH_OFB_MODE);
CREATE_CIPHER_DISPATCHERS(ecb, aes, EVP_CIPH_ECB_MODE);
CREATE_CIPHER_DISPATCHERS(ctr, aes, EVP_CIPH_CTR_MODE);
// EVP_CIPH_XTR_MODE not defined..
CREATE_CIPHER_DISPATCHERS(xtr, aes, EVP_CIPH_CTR_MODE);