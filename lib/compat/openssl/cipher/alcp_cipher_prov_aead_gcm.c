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
#include "alcp_cipher_prov_common.h"

#define PROV_GCM_DEBUG 0

static int
gcm_tls_init(ALCP_PROV_CIPHER_CTX* dat, Uint8* aad, size_t aad_len);
static int
gcm_tls_iv_set_fixed(ALCP_PROV_CIPHER_CTX* ctx, Uint8* iv, size_t len);
static int
gcm_tls_cipher(ALCP_PROV_CIPHER_CTX* ctx,
               Uint8*                out,
               size_t*               padlen,
               const Uint8*          in,
               size_t                len);
static int
gcm_cipher_internal(ALCP_PROV_CIPHER_CTX* ctx,
                    Uint8*                out,
                    size_t*               padlen,
                    const Uint8*          in,
                    size_t                len);

/*
 * Called from EVP_CipherInit when there is currently no context via
 * the new_ctx() function
 */
void
ALCP_prov_gcm_initctx(void* provctx, ALCP_PROV_CIPHER_CTX* ctx, size_t keybits)
{
    ENTER();
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    cipherctx->pad         = 1; // not used internally
    cipherctx->mode        = ALC_AES_MODE_GCM;
    cipherctx->tagLength   = UNINITIALISED_SIZET;
    cipherctx->tls_aad_len = UNINITIALISED_SIZET;
    cipherctx->ivLen = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    cipherctx->keyLen_in_bytes = keybits / 8;
    // ctx->libctx                = ALCP_prov_libctx_of(provctx); //this creates
    // mem leaks, to be investigated.

    /* printf("\n ALCP_prov_gcm_initctx ivLen %ld keyLen %d \n",
        cipherctx->ivLen,
       cipherctx->keyLen_in_bytes); */
}

/*
 * Called by EVP_CipherInit via the _einit and _dinit functions
 */
static int
gcm_init(void*            vctx,
         const Uint8*     key,
         size_t           keylen, // key len in bytes
         const Uint8*     iv,
         size_t           ivlen,
         const OSSL_PARAM params[],
         int              enc)
{
    ALCP_PROV_CIPHER_CTX* ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*    cipherctx = ctx->prov_cipher_data;

    ENTER();

    // if (!ossl_prov_is_running())
    // return 0;

    cipherctx->enc = enc;

    // copy iv
    if (iv != NULL) {
        if (ivlen == 0 || ivlen > sizeof(cipherctx->iv_buff)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        cipherctx->ivLen = ivlen;
        memcpy(cipherctx->iv_buff, iv, ivlen);
        cipherctx->ivState = IV_STATE_BUFFERED;
#if DEBUG_PROV_GCM_INIT
        printf("\n setIV");
#endif
        // setIv, this maynot be necessary since iv is buffered.
        // this can be removed after verification.
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), NULL, 0, cipherctx->iv_buff, ivlen);
        if (alcp_is_error(err)) {
            return 0;
        }
    }
#if DEBUG_PROV_GCM_INIT
    alc_cipher_data_t* cipherctxTemp = ctx->handle.alc_cipher_data;
    printf("\n gcm_init enc value %d", cipherctxTemp->enc);
#endif
    // set key
    if (key != NULL) {
        if (keylen != cipherctx->keyLen_in_bytes) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
#if DEBUG_PROV_GCM_INIT
        // setKey only
        printf("\n setKey");
#endif
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), key, cipherctx->keyLen_in_bytes * 8, NULL, 0);

        if (alcp_is_error(err)) {
            return 0;
        }
        cipherctx->isKeySet        = 1;
        cipherctx->tls_enc_records = 0;
    }
#if DEBUG_PROV_GCM_INIT
    printf("\n call setctx\n");
#endif
    return ALCP_prov_gcm_set_ctx_params(ctx, params);
}

int
ALCP_prov_gcm_einit(void*            vctx,
                    const Uint8*     key,
                    size_t           keylen,
                    const Uint8*     iv,
                    size_t           ivlen,
                    const OSSL_PARAM params[])
{
    // ENTER();

#if DEBUG_PROV_GCM_INIT
    printf("\n ALCP_prov_gcm_einit key %p keyLen %ld iv %p ivLen %ld\n",
           key,
           keylen,
           iv,
           ivlen);
#endif

    // exit(0);
    return gcm_init(vctx, key, keylen, iv, ivlen, params, 1);
}

int
ALCP_prov_gcm_dinit(void*            vctx,
                    const Uint8*     key,
                    size_t           keylen,
                    const Uint8*     iv,
                    size_t           ivlen,
                    const OSSL_PARAM params[])
{
    // ENTER();

#if DEBUG_PROV_GCM_INIT
    printf("\n ALCP_prov_gcm_dinit key %p keyLen %ld iv %p ivLen %ld\n",
           key,
           keylen,
           iv,
           ivlen);
#endif
    return gcm_init(vctx, key, keylen, iv, ivlen, params, 0);
}

/* increment counter (64-bit int) by 1 */
static void
ctr64_inc(Uint8* counter)
{
    int   n = 8;
    Uint8 c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c > 0)
            return;
    } while (n > 0);
}

static int
getivgen(ALCP_PROV_CIPHER_CTX* ctx, Uint8* out, size_t olen)
{
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    // setIV
    alc_error_t err = alcp_cipher_aead_init(
        &(ctx->handle), NULL, 0, cipherctx->iv_buff, cipherctx->ivLen);
    if (alcp_is_error(err)) {
        return 0;
    }

    if (!cipherctx->iv_gen || !cipherctx->isKeySet) {
        return 0;
    }
    if (olen == 0 || olen > cipherctx->ivLen)
        olen = cipherctx->ivLen;
    memcpy(out, cipherctx->iv_buff + cipherctx->ivLen - olen, olen);
    /*
     * Invocation field will be at least 8 bytes in size and so no need
     * to check wrap around or increment more than last 8 bytes.
     */
    ctr64_inc(cipherctx->iv_buff + cipherctx->ivLen - 8);
    cipherctx->ivState = IV_STATE_COPIED;
    return 1;
}

static int
setivinv(ALCP_PROV_CIPHER_CTX* ctx, Uint8* in, size_t inl)
{
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    if (!cipherctx->iv_gen || !cipherctx->isKeySet || cipherctx->enc)
        return 0;

    memcpy(cipherctx->iv_buff + cipherctx->ivLen - inl, in, inl);

    // setIV
    alc_error_t err = alcp_cipher_aead_init(
        &(ctx->handle), NULL, 0, cipherctx->iv_buff, cipherctx->ivLen);
    if (alcp_is_error(err)) {
        return 0;
    }
    cipherctx->ivState = IV_STATE_COPIED;
    return 1;
}

// static int tmp_dbg_counter = 0;

int
ALCP_prov_gcm_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX* ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*    cipherctx = ctx->prov_cipher_data;

    OSSL_PARAM* p;
    size_t      sz;
    ENTER();

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->keyLen_in_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t taglen = (cipherctx->tagLength != UNINITIALISED_SIZET)
                            ? cipherctx->tagLength
                            : GCM_TAG_MAX_SIZE;
        // printf(
        //    "\n get ctx tagLength %ld taglen %ld", cipherctx->tagLength,
        //    taglen);
        if (!OSSL_PARAM_set_size_t(p, taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (cipherctx->ivState == IV_STATE_UNINITIALISED)
            return 0;
        if (cipherctx->ivLen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(
                p, cipherctx->iv_buff, cipherctx->ivLen)
            && !OSSL_PARAM_set_octet_ptr(
                p, &cipherctx->iv_buff, cipherctx->ivLen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (cipherctx->ivState == IV_STATE_UNINITIALISED)
            return 0;
        if (cipherctx->ivLen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(
                p, cipherctx->iv_buff, cipherctx->ivLen)
            && !OSSL_PARAM_set_octet_ptr(
                p, &cipherctx->iv_buff, cipherctx->ivLen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        sz = p->data_size;
        if (sz == 0 || sz > EVP_GCM_TLS_TAG_LEN || !cipherctx->enc
            || cipherctx->tagLength == UNINITIALISED_SIZET) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }

        if (!OSSL_PARAM_set_octet_string(p, cipherctx->buf, sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING
            || !getivgen(ctx, p->data, p->data_size))
            return 0;
    }
    return 1;
}

int
ALCP_prov_gcm_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX* ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*    cipherctx = ctx->prov_cipher_data;

    const OSSL_PARAM* p;
    size_t            sz;
    void*             vp;

    ENTER();

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        vp = cipherctx->buf;
        if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || cipherctx->enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }
        cipherctx->tagLength = sz;
#if PROV_GCM_DEBUG
        printf("taglen set %lu ", cipherctx->tagLength);
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || sz > sizeof(cipherctx->iv_buff)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (cipherctx->ivLen != sz) {
            /* If the iv was already set or autogenerated, it is invalid. */
            if (cipherctx->ivState != IV_STATE_UNINITIALISED)
                cipherctx->ivState = IV_STATE_FINISHED;
            cipherctx->ivLen = sz;
        }
#if PROV_GCM_DEBUG
        printf("ivlen set %lu ", cipherctx->ivLen);
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        sz = gcm_tls_init(ctx, p->data, p->data_size);
        if (sz == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
            return 0;
        }
        cipherctx->tls_aad_pad_sz = sz;
#if PROV_GCM_DEBUG
        printf("add_pad set %u ", cipherctx->tls_aad_pad_sz);
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (gcm_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
#if PROV_GCM_DEBUG
        printf("OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED ");
#endif
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING
            || !setivinv(ctx, p->data, p->data_size)) {
#if PROV_GCM_DEBUG
            printf("OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV failed ");
#endif
            return 0;
        }
    }

    EXIT();
    return 1;
}

int
ALCP_prov_gcm_stream_update(void*        vctx,
                            Uint8*       out,
                            size_t*      outl,
                            size_t       outsize,
                            const Uint8* in,
                            size_t       inl)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    ENTER();
    // printf("inl %lu outl %lu \n", inl, (*outl));

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (gcm_cipher_internal(ctx, out, outl, in, inl) <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    return 1;
}

int
ALCP_prov_gcm_stream_final(void* vctx, Uint8* out, size_t* outl, size_t outsize)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    int                   i;
    ENTER();
    // printf("outl %lu \n", (*outl));

    // if (!ossl_prov_is_running())
    // return 0;

    i = gcm_cipher_internal(ctx, out, outl, NULL, 0);
    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}

int
ALCP_prov_gcm_cipher(void*        vctx,
                     Uint8*       out,
                     size_t*      outl,
                     size_t       outsize,
                     const Uint8* in,
                     size_t       inl)
{
    ALCP_PROV_CIPHER_CTX* ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    ENTER();

    // if (!ossl_prov_is_running())
    // return 0;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (gcm_cipher_internal(ctx, out, outl, in, inl) <= 0)
        return 0;

    *outl = inl;
    return 1;
}

/*
 * See SP800-38D (GCM) Section 8 "Uniqueness requirement on IVS and keys"
 *
 * See also 8.2.2 RBG-based construction.
 * Random construction consists of a free field (which can be NULL) and a
 * random field which will use a DRBG that can return at least 96 bits of
 * entropy strength. (The DRBG must be seeded by the FIPS module).
 */
static int
gcm_iv_generate(ALCP_PROV_CIPHER_CTX* ctx, int offset)
{
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    int sz = cipherctx->ivLen - offset;

    /* Must be at least 96 bits */
    if (sz <= 0 || cipherctx->ivLen < GCM_IV_DEFAULT_SIZE)
        return 0;

    /* Use DRBG to generate random iv */
    if (RAND_bytes_ex(ctx->libctx, cipherctx->iv_buff + offset, sz, 0) <= 0)
        return 0;

    cipherctx->ivState     = IV_STATE_BUFFERED;
    cipherctx->iv_gen_rand = 1;
    return 1;
}

#if PROV_GCM_DEBUG
static int dec_counter = 0;
#endif

static int
gcm_cipher_internal(ALCP_PROV_CIPHER_CTX* ctx,
                    Uint8*                out,
                    size_t*               padlen,
                    const Uint8*          in,
                    size_t                len)
{
    size_t             olen      = 0;
    int                rv        = 0;
    alc_error_t        err       = ALC_ERROR_NONE;
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;
    ENTER();

    if (cipherctx->tls_aad_len != UNINITIALISED_SIZET) {
#if PROV_GCM_DEBUG
        printf(" tlscipher len %lu padlen %lu", len, *padlen);
#endif
        return gcm_tls_cipher(ctx, out, padlen, in, len);
    }

    if (!cipherctx->isKeySet || cipherctx->ivState == IV_STATE_FINISHED)
        goto err;

    /*
     * FIPS requires generation of AES-GCM IV's inside the FIPS module.
     * The IV can still be set externally (the security policy will state that
     * this is not FIPS compliant). There are some applications
     * where setting the IV externally is the only option available.
     */
    if (cipherctx->ivState == IV_STATE_UNINITIALISED) {
        if (!cipherctx->enc || !gcm_iv_generate(ctx, 0))
            goto err;
    }

    if (cipherctx->ivState == IV_STATE_BUFFERED) {
        // setIV
        err = alcp_cipher_aead_init(
            &(ctx->handle), NULL, 0, cipherctx->iv_buff, cipherctx->ivLen);
        if (alcp_is_error(err)) {
            goto err;
        }
        cipherctx->ivState = IV_STATE_COPIED;
    }

    if (in != NULL) {
        /*  The input is AAD if out is NULL */
        if (out == NULL) {
#if PROV_GCM_DEBUG
            printf(" aead %lu ", len);
#endif
            err = alcp_cipher_aead_set_aad(&(ctx->handle), in, len);
            if (alcp_is_error(err)) {
                printf("Error: unable gcm add data processing \n");
                goto err;
            }

        } else {
            // printf("\nGCM crypt");
            /* The input is ciphertext OR plaintext */
            if (cipherctx->enc) {
#if PROV_GCM_DEBUG
                printf(" enc %lu ", len);
#endif
                err = alcp_cipher_aead_encrypt_update(
                    &(ctx->handle), in, out, len);
            } else {
#if PROV_GCM_DEBUG
                printf("\n");
                printf(" dec %lu dec_counter %d ", len, dec_counter);
                dec_counter++;
#endif
                err = alcp_cipher_aead_decrypt_update(
                    &(ctx->handle), in, out, len);
            }

            if (alcp_is_error(err)) {
                printf("Error: gcm cipherUpdate \n");
                goto err;
            }
        }
    } else {
        if (cipherctx->enc) {
            cipherctx->tagLength =
                EVP_GCM_TLS_TAG_LEN; // this is not done alcp side.
        }
        /* The tag must be set before actually decrypting data */
        if (!cipherctx->enc && cipherctx->tagLength == UNINITIALISED_SIZET)
            goto err;
#if PROV_GCM_DEBUG
        printf(" tag %lu ", cipherctx->tagLength);
#endif
        err = alcp_cipher_aead_get_tag(
            &(ctx->handle), cipherctx->buf, cipherctx->tagLength);

        if (alcp_is_error(err)) {
            printf("Error: gcm getTag failed \n");
            goto err;
        }

        cipherctx->ivState = IV_STATE_FINISHED; /* Don't reuse the IV */
        goto finish;
    }
    olen = len;
finish:
    rv = 1;
err:
    *padlen = olen;
    EXIT();
    return rv;
}

static int
gcm_tls_init(ALCP_PROV_CIPHER_CTX* dat, Uint8* aad, size_t aad_len)
{
    Uint8* buf;
    size_t len;
    ENTER();

    // if (!ossl_prov_is_running() || aad_len != EVP_AEAD_TLS1_AAD_LEN)
    if (aad_len != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    /* Save the aad for later use. */
    buf = dat->prov_cipher_data->buf;
    memcpy(buf, aad, aad_len);
    dat->prov_cipher_data->tls_aad_len = aad_len;

    len = buf[aad_len - 2] << 8 | buf[aad_len - 1];
    /* Correct length for explicit iv. */
    if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
        return 0;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

    /* If decrypting correct for tag too. */
    if (!dat->prov_cipher_data->enc) {
        if (len < EVP_GCM_TLS_TAG_LEN)
            return 0;
        len -= EVP_GCM_TLS_TAG_LEN;
    }
    buf[aad_len - 2] = (Uint8)(len >> 8);
    buf[aad_len - 1] = (Uint8)(len & 0xff);
    /* Extra padding: tag appended to record. */
    return EVP_GCM_TLS_TAG_LEN;
}

static int
gcm_tls_iv_set_fixed(ALCP_PROV_CIPHER_CTX* ctx, Uint8* iv, size_t len)
{
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    /* Special case: -1 length restores whole IV */
    if (len == (size_t)-1) {
        memcpy(cipherctx->iv_buff, iv, cipherctx->ivLen);
        cipherctx->iv_gen  = 1;
        cipherctx->ivState = IV_STATE_BUFFERED;
        return 1;
    }
    /* Fixed field must be at least 4 bytes and invocation field at least 8 */
    if ((len < EVP_GCM_TLS_FIXED_IV_LEN)
        || (cipherctx->ivLen - (int)len) < EVP_GCM_TLS_EXPLICIT_IV_LEN)
        return 0;
    if (len > 0)
        memcpy(cipherctx->iv_buff, iv, len);
    if (cipherctx->enc
        && RAND_bytes_ex(
               ctx->libctx, cipherctx->iv_buff + len, cipherctx->ivLen - len, 0)
               <= 0)
        return 0;
    cipherctx->iv_gen  = 1;
    cipherctx->ivState = IV_STATE_BUFFERED;
    return 1;
}

int
alcp_gcm_one_shot(ALCP_PROV_CIPHER_CTX* ctx,
                  Uint8*                aad,
                  size_t                aad_len,
                  const Uint8*          in,
                  size_t                in_len,
                  Uint8*                out,
                  Uint8*                tag,
                  size_t                tag_len)
{
    int                ret       = 0;
    alc_error_t        err       = ALC_ERROR_NONE;
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;

    if (alcp_cipher_aead_set_aad(&(ctx->handle), aad, aad_len)
        != ALC_ERROR_NONE) {
        printf("Error: unable gcm add data processing \n");
        goto err;
    }

    if (cipherctx->enc) {
        err = alcp_cipher_aead_encrypt_update(&(ctx->handle), in, out, in_len);
    } else {
        err = alcp_cipher_aead_decrypt_update(&(ctx->handle), in, out, in_len);
    }
    if (alcp_is_error(err)) {
        printf("Error: gcm cipherUpdate \n");
        goto err;
    }

    cipherctx->tagLength = GCM_TAG_MAX_SIZE;
    err = alcp_cipher_aead_get_tag(&(ctx->handle), tag, cipherctx->tagLength);
    if (alcp_is_error(err)) {
        printf("Error: gcm getTag failed \n");
        goto err;
    }

    ret = 1;

err:
    return ret;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */
static int
gcm_tls_cipher(ALCP_PROV_CIPHER_CTX* ctx,
               Uint8*                out,
               size_t*               padlen,
               const Uint8*          in,
               size_t                len)
{
    int                rv        = 0;
    size_t             arg       = EVP_GCM_TLS_EXPLICIT_IV_LEN;
    size_t             plen      = 0;
    Uint8*             tag       = NULL;
    alc_cipher_data_t* cipherctx = ctx->prov_cipher_data;
    ENTER();
    // printf("\n alcp tls_cipher %ld padlen, %ld len", *padlen, len);

    // if (!ossl_prov_is_running() || !cipherctx->isKeySet)
    if (!cipherctx->isKeySet)
        goto err;

    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        goto err;

    /*
     * Check for too many keys as per FIPS 140-2 IG A.5 "Key/IV Pair Uniqueness
     * Requirements from SP 800-38D".  The requirements is for one party to the
     * communication to fail after 2^64 - 1 keys.  We do this on the encrypting
     * side only.
     */
    if (cipherctx->enc && ++cipherctx->tls_enc_records == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_TOO_MANY_RECORDS);
        goto err;
    }

    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (cipherctx->enc) {
        if (!getivgen(ctx, out, arg))
            goto err;
    } else {
        if (!setivinv(ctx, out, arg))
            goto err;
    }

    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

    tag = cipherctx->enc ? out + len : (Uint8*)in + len;

    if (!alcp_gcm_one_shot(ctx,
                           cipherctx->buf,
                           cipherctx->tls_aad_len,
                           in,
                           len,
                           out,
                           tag,
                           EVP_GCM_TLS_TAG_LEN)) {

        if (!cipherctx->enc)
            OPENSSL_cleanse(out, len);
        goto err;
    }

    if (cipherctx->enc)
        plen = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    else
        plen = len;

    rv = 1;
err:
    cipherctx->ivState     = IV_STATE_FINISHED;
    cipherctx->tls_aad_len = UNINITIALISED_SIZET;
    *padlen                = plen;
    return rv;
}