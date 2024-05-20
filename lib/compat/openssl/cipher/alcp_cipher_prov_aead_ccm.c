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

static size_t
ccm_get_ivlen(ALCP_PROV_CIPHER_CTX* ctx)
{
    return 15 - ctx->prov_cipher_data.ccm.l;
}

int
ALCP_prov_ccm_get_ctx_params(void* vctx, OSSL_PARAM params[])
{

    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ccm_get_ivlen(ctx))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t m = cipherctx->ccm.m;

        if (!OSSL_PARAM_set_size_t(p, m)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (ccm_get_ivlen(ctx) > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, cipherctx->iv_buff, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(
                p, &cipherctx->iv_buff, p->data_size)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ccm_get_ivlen(ctx) > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, cipherctx->iv_buff, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(
                p, &cipherctx->iv_buff, p->data_size)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->keyLen_in_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (!cipherctx->enc || !cipherctx->ccm.isTagSet) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }

        if (alcp_cipher_aead_get_tag(&(ctx->handle), p->data, p->data_size)) {
            return 0;
        }

        cipherctx->ccm.isTagSet = 0;
        cipherctx->ivState      = 0;
        cipherctx->ccm.isLenSet = 0;
    }
    return 1;
}
static int
ccm_tls_init(ALCP_PROV_CIPHER_CTX* ctx, unsigned char* aad, size_t alen)
{
    size_t                  len;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    ENTER();

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(cipherctx->buf, aad, alen);
    (cipherctx)->tls_aad_len = alen;

    len = cipherctx->buf[alen - 2] << 8 | cipherctx->buf[alen - 1];
    if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
        return 0;

    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

    if (!cipherctx->enc) {
        if (len < cipherctx->ccm.m)
            return 0;

        len -= cipherctx->ccm.m;
    }
    cipherctx->buf[alen - 2] = (unsigned char)(len >> 8);
    cipherctx->buf[alen - 1] = (unsigned char)(len & 0xff);
    EXIT();

    return cipherctx->ccm.m;
}

static int
ccm_tls_iv_set_fixed(ALCP_PROV_CIPHER_CTX* ctx,
                     unsigned char*        fixed,
                     size_t                flen)
{
    if (flen != EVP_CCM_TLS_FIXED_IV_LEN)
        return 0;

    memcpy(ctx->prov_cipher_data.iv_buff, fixed, flen);
    return 1;
}

int
ALCP_prov_ccm_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    const OSSL_PARAM* p;
    size_t            sz;
    ENTER();

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if ((p->data_size & 1) || (p->data_size < 4) || p->data_size > 16) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }

        if (p->data != NULL) {
            if (cipherctx->enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(cipherctx->buf, p->data, p->data_size);
            cipherctx->ccm.isTagSet = 1;
        }
        cipherctx->ccm.m = p->data_size;
        if (cipherctx->ccm.m != 0) {
            if (alcp_cipher_aead_set_tag_length(&(ctx->handle),
                                                cipherctx->ccm.m)) {
                return 0;
            }
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        size_t ivlen;

        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ivlen = 15 - sz;
        if (ivlen < 2 || ivlen > 8) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        cipherctx->ccm.l = ivlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        sz = ccm_tls_init(ctx, p->data, p->data_size);
        if (sz == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        cipherctx->tls_aad_pad_sz = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (ccm_tls_iv_set_fixed(
                (ALCP_PROV_CIPHER_CTX*)ctx, p->data, p->data_size)
            == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    EXIT();
    return 1;
}

int
ALCP_prov_ccm_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const unsigned char* iv,
                   size_t               ivlen,
                   const OSSL_PARAM     params[],
                   int                  enc)
{
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);

    cipherctx->enc = enc;

    if (iv != NULL) {
        if (ivlen != ccm_get_ivlen((ALCP_PROV_CIPHER_CTX*)ctx)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(cipherctx->iv_buff, iv, ivlen);
        cipherctx->ivState = IV_STATE_BUFFERED;

        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), NULL, 0, cipherctx->iv_buff, ivlen);
        if (alcp_is_error(err)) {
            return 0;
        }
    }
    if (key != NULL) {
        if (keylen != cipherctx->keyLen_in_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), key, cipherctx->keyLen_in_bytes * 8, NULL, 0);

        if (alcp_is_error(err)) {
            return 0;
        }
        cipherctx->isKeySet        = 1;
        cipherctx->tls_enc_records = 0;
    }
    return ALCP_prov_ccm_set_ctx_params(ctx, params);
}
int
ALCP_prov_ccm_einit(void*                vctx,
                    const unsigned char* key,
                    size_t               keylen,
                    const unsigned char* iv,
                    size_t               ivlen,
                    const OSSL_PARAM     params[])
{
    return ALCP_prov_ccm_init(vctx, key, keylen, iv, ivlen, params, 1);
}
int
ALCP_prov_ccm_dinit(void*                vctx,
                    const unsigned char* key,
                    size_t               keylen,
                    const unsigned char* iv,
                    size_t               ivlen,
                    const OSSL_PARAM     params[])
{
    return ALCP_prov_ccm_init(vctx, key, keylen, iv, ivlen, params, 0);
}
static int
ccm_tls_cipher(ALCP_PROV_CIPHER_CTX* ctx,
               Uint8*                out,
               size_t*               padlen,
               const Uint8*          in,
               size_t                len)
{
    int                     rv        = 0;
    size_t                  olen      = 0;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    ENTER();

    if (in == NULL || out != in
        || len < EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherctx->ccm.m)
        goto err;

    if (cipherctx->enc)
        memcpy(out, cipherctx->buf, EVP_CCM_TLS_EXPLICIT_IV_LEN);

    memcpy(cipherctx->iv_buff + EVP_CCM_TLS_FIXED_IV_LEN,
           in,
           EVP_CCM_TLS_EXPLICIT_IV_LEN);

    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherctx->ccm.m;

    if (alcp_cipher_aead_init(&(ctx->handle),
                              NULL,
                              0,
                              cipherctx->buf,
                              ccm_get_ivlen((ALCP_PROV_CIPHER_CTX*)ctx))) {
        goto err;
    }
    cipherctx->ccm.isLenSet = 1;

    if (alcp_cipher_aead_set_aad(
            &(ctx->handle), cipherctx->buf, cipherctx->tls_aad_len))
        goto err;

    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;

    if (cipherctx->enc) {

        if (alcp_cipher_aead_encrypt(&(ctx->handle), in, out, len)) {
            goto err;
        }
        olen = len + EVP_CCM_TLS_EXPLICIT_IV_LEN + cipherctx->ccm.m;
    } else {

        if (alcp_cipher_aead_decrypt(&(ctx->handle), in, out, len)) {
            goto err;
        }
        olen = len;
    }

    rv = 1;

err:
    *padlen = olen;
    return rv;
}

int
ccm_set_iv_mlen(ALCP_PROV_CIPHER_CTX* ctx, size_t mlen)
{
    if (alcp_cipher_aead_init(&(ctx->handle),
                              NULL,
                              0,
                              ctx->prov_cipher_data.iv_buff,
                              ccm_get_ivlen(ctx))) {
        printf("Provider:CCM: Error in Setting IV\n");
        return 0;
    }
    if (alcp_cipher_aead_set_plaintext_length(&(ctx->handle), mlen)) {
        printf("Provider:CCM: Error in Setting Plaintext Length\n");
        return 0;
    }
    ctx->prov_cipher_data.ccm.isLenSet = 1;
    return 1;
}
static int
alcp_prov_ccm_cipher_internal(ALCP_PROV_CIPHER_CTX* ctx,
                              Uint8*                out,
                              size_t*               padlen,
                              const Uint8*          in,
                              size_t                len)
{
    size_t                  olen      = 0;
    int                     rv        = 0;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    ENTER();
    if (!cipherctx->isKeySet) {
        return 0;
    }
    if (cipherctx->tls_aad_len != UNINITIALISED_SIZET) {
        return ccm_tls_cipher(ctx, out, padlen, in, len);
    }

    if (in == NULL && out != NULL)
        goto finish;

    if (!cipherctx->ivState)
        goto err;

    if (out == NULL) {
        if (in == NULL) {
            if (!ccm_set_iv_mlen(ctx, len))
                goto err;

        } else {

            if (!cipherctx->ccm.isLenSet && len)
                goto err;
            if (alcp_cipher_aead_set_aad(&(ctx->handle), in, len))
                goto err;
        }
    } else {
        if (!cipherctx->ccm.isLenSet && !ccm_set_iv_mlen(ctx, len)) {
            goto err;
        }

        if (cipherctx->enc) {
            if (alcp_cipher_aead_encrypt(&(ctx->handle), in, out, len)) {
                goto err;
            }
            cipherctx->ccm.isTagSet = 1;
        } else {

            if (!cipherctx->ccm.isTagSet)
                goto err;

            if (alcp_cipher_aead_decrypt(&(ctx->handle), in, out, len)) {
                goto err;
            }

            // TODO: Tag verification
            if (alcp_cipher_aead_get_tag(
                    &(ctx->handle), cipherctx->buf, cipherctx->ccm.m)) {
                printf("Error getting the tag\n");
                goto err;
            }

            cipherctx->ivState      = 0;
            cipherctx->ccm.isTagSet = 0;
            cipherctx->ccm.isLenSet = 0;
        }
    }
    olen = len;
finish:
    rv = 1;
err:
    *padlen = olen;
    EXIT();
    return rv;
}
int
ALCP_prov_ccm_stream_final(void*          vctx,
                           unsigned char* out,
                           size_t*        outl,
                           size_t         outsize)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    int                   i;

    i = alcp_prov_ccm_cipher_internal(ctx, out, outl, NULL, 0);
    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}
int
ALCP_prov_ccm_stream_update(void*        vctx,
                            Uint8*       out,
                            size_t*      outl,
                            size_t       outsize,
                            const Uint8* in,
                            size_t       inl)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!alcp_prov_ccm_cipher_internal(ctx, out, outl, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    return 1;
}

int
ALCP_prov_ccm_cipher(void*                vctx,
                     unsigned char*       out,
                     size_t*              outl,
                     size_t               outsize,
                     const unsigned char* in,
                     size_t               inl)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (alcp_prov_ccm_cipher_internal(ctx, out, outl, in, inl) <= 0)
        return 0;

    *outl = inl;
    return 1;
}
