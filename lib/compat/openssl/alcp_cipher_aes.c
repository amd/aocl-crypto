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

const OSSL_PARAM*        s_cipher_cfb_params;
static alc_cipher_info_t s_cipher_cfb_info = {
    ALC_CIPHER_TYPE_AES,
    {
        ALC_KEY_TYPE_SYMMETRIC,
        ALC_KEY_FMT_RAW,
        ALC_KEY_ALG_SYMMETRIC,
        ALC_KEY_LEN_128,
    },
    { {
        ALC_AES_MODE_CFB,
    } },
};

int
ALCP_prov_aes_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    return 1;
}

int
ALCP_prov_aes_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    return 1;
}

void*
ALCP_prov_aes_newctx(void*                    vprovctx,
                     const alc_cipher_info_t* p_cipher_info,
                     const OSSL_PARAM         params[])
{
    alc_prov_aes_ctx_p ctx      = OPENSSL_zalloc(sizeof(*ctx));
    alc_prov_ctx_p     prov_ctx = vprovctx;
    ENTER();
    if (!ctx) {
        alc_prov_cipher_ctx_p cipher_ctx = ctx->aa_prov_cipher_ctx;
        ctx->aa_prov_ctx                 = prov_ctx;
        cipher_ctx->pc_cipher_info       = p_cipher_info;
    } else {
        ctx = NULL;
    }

    return ctx;
}

/* cfb_functions */
CREATE_CIPHER_DISPATCHERS(cfb, aes);
