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

#include "alcp_cipher_prov.h"
#include "names.h"

void
ALCP_prov_cipher_freectx(void* vctx)
{
    alc_prov_cipher_ctx_p pcctx = vctx;

    /*
     * pcctx->pc_evp_cipher will be  freed in provider teardown,
     */
    EVP_CIPHER_CTX_free(pcctx->pc_evp_cipher_ctx);
    ENTER();
    OPENSSL_free(vctx);
}

void*
ALCP_prov_cipher_newctx(void*                vprovctx,
                        const alc_prov_ctx_p pprov_ctx,
                        const OSSL_PARAM*    pparams)
{
    alc_prov_cipher_ctx_p gctx;
    alc_prov_ctx_p        pctx = pprov_ctx;

    ENTER();
    gctx = OPENSSL_zalloc(sizeof(*gctx));

    if (gctx != NULL) {
        gctx->pc_prov_ctx       = pprov_ctx;
        gctx->pc_params         = pparams;
        gctx->pc_libctx         = pctx->ap_libctx;
        gctx->pc_evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (!gctx->pc_evp_cipher_ctx || !gctx->pc_prov_ctx) {
            ALCP_prov_cipher_freectx(gctx);
            gctx = NULL;
        }
#if 0
        // gctx->descriptor = descriptor;
        // gctx->cipher     = ALCP_prov_cipher_init(descriptor);
#endif
    }

    return gctx;
}

void*
ALCP_prov_cipher_dupctx(void* vctx)
{
    alc_prov_cipher_ctx_p csrc = vctx;
    ENTER();
#if 0
    alc_prov_cipher_ctx_p cdst = ALCP_prov_cipher_newctx(
        csrc->pc_evp_cipher_ctx, csrc->pc_cipher_info, csrc->pc_params);
#endif
    return csrc;
}

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
#if 0
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
#endif
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_cipher_gettable_params(void* provctx)
{
    return cipher_known_gettable_params;
}

int
ALCP_prov_cipher_get_params(OSSL_PARAM params[])
{
    ENTER();
    return 0;
}

int
ALCP_prov_cipher_set_params(const OSSL_PARAM params[])
{
    ENTER();

    return 0;
}

int
ALCP_prov_cipher_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    alc_prov_cipher_ctx_p cctx = (alc_prov_cipher_ctx_p)vctx;

    OSSL_PARAM*        p;
    const static char* VERSION = "1.0";
    char static BUILDTYPE[100];
    /* FIXME: */
    cctx = cctx;
    ENTER();

    if ((p = OSSL_PARAM_locate(params, "version")) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, VERSION))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "buildinfo")) != NULL
        && BUILDTYPE[0] != '\0' && !OSSL_PARAM_set_utf8_ptr(p, BUILDTYPE))
        return 0;

    return 1;
}

int
ALCP_prov_cipher_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();

    return 1;
}

int
ALCP_prov_cipher_encrypt_init(void*                vctx,
                              const unsigned char* key,
                              size_t               keylen,
                              const unsigned char* iv,
                              size_t               ivlen,
                              const OSSL_PARAM     params[])
{
    alc_prov_cipher_ctx_p cctx = vctx;
    ENTER();
    cctx = cctx;
    return 0;
}

int
ALCP_prov_cipher_decrypt_init(void*                vctx,
                              const unsigned char* key,
                              size_t               keylen,
                              const unsigned char* iv,
                              size_t               ivlen,
                              const OSSL_PARAM     params[])
{
    alc_prov_cipher_ctx_p cctx = vctx;
    ENTER();
    cctx = cctx;
    return 0;
}

int
ALCP_prov_cipher_update(void*                vctx,
                        unsigned char*       out,
                        size_t*              outl,
                        size_t               outsize,
                        const unsigned char* in,
                        size_t               inl)
{
    alc_prov_cipher_ctx_p cctx = vctx;
    ENTER();
    cctx = cctx;
    return 0;
}

int
ALCP_prov_cipher_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    alc_prov_cipher_ctx_p cctx = vctx;
    ENTER();
    cctx = cctx;
    return 0;
}

static const char          CIPHER_DEF_PROP[] = "provider=alcp,fips=no";
extern const OSSL_DISPATCH cfb_functions[];
const OSSL_ALGORITHM       ALC_prov_ciphers[] = {
    { PROV_NAMES_AES_256_CFB, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_192_CFB, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_128_CFB, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_256_CFB1, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_192_CFB1, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_128_CFB1, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_256_CFB8, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_192_CFB8, CIPHER_DEF_PROP, cfb_functions },
    { PROV_NAMES_AES_128_CFB8, CIPHER_DEF_PROP, cfb_functions },
    { NULL, NULL, NULL },
};

EVP_CIPHER*
ALCP_prov_cipher_init(alc_prov_ctx_p cc)
{
    /* FIXME: this could be wrong */
    alc_prov_cipher_ctx_p c = (alc_prov_cipher_ctx_p)cc;

    ENTER();
    if (c->pc_evp_cipher)
        return c->pc_evp_cipher;

    /* Some sanity checking. */
    int flags = c->pc_flags;
    switch (flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CTR_MODE:
        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:
            break;
        default:
            break;
    }

    EVP_CIPHER* tmp = NULL;
#if 0
    tmp = EVP_CIPHER_meth_new(c->pc_nid, 128 / 8, c->pc_key_info->len);

    int res = 0;
    res |= EVP_CIPHER_meth_set_iv_length(tmp, iv_len);
    res != EVP_CIPHER_meth_set_flags(tmp, flags);
    res != EVP_CIPHER_meth_set_init(tmp, init);
    res != EVP_CIPHER_meth_set_do_tmp(tmp, do_tmp);
    res != EVP_CIPHER_meth_set_cleanup(tmp, cleanup);
    res != EVP_CIPHER_meth_set_impl_ctx_size(tmp, ctx_size);
    res != EVP_CIPHER_meth_set_set_asn1_params(tmp, set_asn1_parameters);
    res != EVP_CIPHER_meth_set_get_asn1_params(tmp, get_asn1_parameters);
    res != EVP_CIPHER_meth_set_ctrl(tmp, ctrl);
    if (res) {
        EVP_CIPHER_meth_free(tmp);
        tmp = NULL;
    }

    c->pc_evp_cipher = tmp;
#endif
    return tmp;
}
