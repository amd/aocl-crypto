/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

#include <openssl/proverr.h>
#include <openssl/crypto.h>
#include <string.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"
#include "alcp_cipher_prov_common.h"
#include "alcp_cipher_prov_aead_chacha20_poly1305.h"

/* Defined in alcp_cipher_aes.c */
extern bool alcp_prov_is_running(void);

/* ---- Forward declarations ---- */
static int
chacha20_poly1305_aead_cipher(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                              unsigned char*                   out,
                              size_t*                          outl,
                              const unsigned char*             in,
                              size_t                           inl);
static int
chacha20_poly1305_tls_init(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                           unsigned char*                   aad,
                           size_t                           alen);
static int
chacha20_poly1305_tls_iv_set_fixed(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                                   unsigned char*                   fixed,
                                   size_t                           flen);
/* ---- Allocation helpers ---- */
static inline size_t
chacha20_poly1305_ctx_alloc_size(void)
{
    return sizeof(ALCP_PROV_CHACHA20_POLY1305_CTX)
           + alcp_cipher_aead_context_size();
}

static inline void*
chacha20_poly1305_ctx_get_ch_context(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx)
{
    return (void*)((unsigned char*)ctx
                   + sizeof(ALCP_PROV_CHACHA20_POLY1305_CTX));
}

/* ---- newctx / dupctx / freectx ---- */
static void*
chacha20_poly1305_newctx(void* provctx)
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx;

    if (!alcp_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(chacha20_poly1305_ctx_alloc_size());
    if (ctx != NULL) {
        ctx->handle.ch_context = chacha20_poly1305_ctx_get_ch_context(ctx);

        alc_error_t err = alcp_cipher_aead_request(
            ALC_CHACHA20_POLY1305, CHACHA20_POLY1305_KEYLEN * 8,
            &(ctx->handle));
        if (err != ALC_ERROR_NONE) {
            OPENSSL_clear_free(ctx, chacha20_poly1305_ctx_alloc_size());
            return NULL;
        }

        ctx->keylen             = CHACHA20_POLY1305_KEYLEN;
        ctx->ivlen              = CHACHA20_POLY1305_IVLEN;
        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    }
    return ctx;
}

static void*
chacha20_poly1305_dupctx(void* provctx)
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx = provctx;
    ALCP_PROV_CHACHA20_POLY1305_CTX* dctx = NULL;

    if (ctx == NULL)
        return NULL;

    dctx = OPENSSL_zalloc(chacha20_poly1305_ctx_alloc_size());
    if (dctx == NULL)
        return NULL;

    /* Copy all struct fields */
    memcpy(dctx, ctx, sizeof(*ctx));

    /* Fix ch_context pointer to embedded memory */
    dctx->handle.ch_context = chacha20_poly1305_ctx_get_ch_context(dctx);

    /* Create a fresh cipher object for the duplicate */
    alc_error_t err = alcp_cipher_aead_request(
        ALC_CHACHA20_POLY1305, dctx->keylen * 8, &(dctx->handle));
    if (err != ALC_ERROR_NONE) {
        OPENSSL_clear_free(dctx, chacha20_poly1305_ctx_alloc_size());
        return NULL;
    }

    /*
     * TODO: Replace with alcp_cipher_aead_context_copy() once a proper CAPI
     * copy API is available for AEAD ciphers. This re-init workaround matches
     * the GCM provider pattern (alcp_cipher_prov_gcm.c) where the key is
     * stored in the provider struct and replayed on the duplicate.
     */
    if (ctx->key_set) {
        err = alcp_cipher_aead_init(
            &(dctx->handle), dctx->key, dctx->keylen * 8, NULL, 0);
        if (alcp_is_error(err)) {
            OPENSSL_clear_free(dctx, chacha20_poly1305_ctx_alloc_size());
            return NULL;
        }
    }

    return dctx;
}

static void
chacha20_poly1305_freectx(void* vctx)
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;

    if (ctx != NULL) {
        if (ctx->handle.ch_context != NULL) {
            alcp_cipher_aead_finish(&(ctx->handle));
            ctx->handle.ch_context = NULL;
        }
        OPENSSL_clear_free(ctx, chacha20_poly1305_ctx_alloc_size());
    }
}

/* ---- get_params ---- */
static int
chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    return ALCP_prov_cipher_generic_get_params(params,
                                               CHACHA20_POLY1305_MODE,
                                               CHACHA20_POLY1305_FLAGS,
                                               CHACHA20_POLY1305_KEYLEN * 8,
                                               CHACHA20_POLY1305_BLKLEN * 8,
                                               CHACHA20_POLY1305_IVLEN * 8);
}

/* ---- get_ctx_params ---- */
static int
chacha20_poly1305_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_IVLEN)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > CHACHA20_POLY1305_TAGLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
    }

    return 1;
}

static const OSSL_PARAM chacha20_poly1305_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM*
chacha20_poly1305_gettable_ctx_params(ossl_unused void* cctx,
                                      ossl_unused void* provctx)
{
    return chacha20_poly1305_known_gettable_ctx_params;
}

/* ---- set_ctx_params ---- */
static int
chacha20_poly1305_set_ctx_params(void*            vctx,
                                 const OSSL_PARAM params[])
{
    const OSSL_PARAM*                p;
    size_t                           len;
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > CHACHA20_POLY1305_TAGLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
        ctx->tag_len = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = chacha20_poly1305_tls_init(ctx, p->data, p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (chacha20_poly1305_tls_iv_set_fixed(ctx, p->data, p->data_size)
            == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

/* ---- einit / dinit ---- */

/*
 * AEAD encrypt init: store key and IV, defer Poly1305 key derivation
 * to aead_cipher. ALCP CAPI supports separate key-only and IV-only calls:
 *   init(key, keyLen, NULL, 0) - key only
 *   init(NULL, 0, iv, ivLen)   - IV only (regenerates Poly1305 key)
 */
static int
chacha20_poly1305_einit(void*            vctx,
                        const Uint8*     key,
                        size_t           keylen,
                        const Uint8*     iv,
                        size_t           ivlen,
                        const OSSL_PARAM params[])
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;
    int ret = 1;

    ctx->enc = 1;

    /* Validate and set key if provided; store for dupctx re-init */
    if (key != NULL) {
        if (keylen != CHACHA20_POLY1305_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        memcpy(ctx->key, key, CHACHA20_POLY1305_KEYLEN);
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), key, keylen * 8, NULL, 0);
        if (alcp_is_error(err))
            return 0;
        ctx->key_set = 1;
    }

    /* Store IV but do NOT call CAPI init with it yet.
     * Poly1305 key derivation is deferred to aead_cipher (when !mac_inited)
     * so that dupctx can copy key state before derivation occurs. */
    if (ret && iv != NULL) {
        if (ivlen != CHACHA20_POLY1305_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->oiv, iv, CHACHA20_POLY1305_IVLEN);
        memcpy(ctx->nonce, ctx->oiv, CHACHA20_POLY1305_IVLEN);
        ctx->iv_set = 1;
    }

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    ctx->mac_inited         = 0;
    ctx->aad                = 0;

    if (ret && !chacha20_poly1305_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int
chacha20_poly1305_dinit(void*            vctx,
                        const Uint8*     key,
                        size_t           keylen,
                        const Uint8*     iv,
                        size_t           ivlen,
                        const OSSL_PARAM params[])
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;
    int ret = 1;

    ctx->enc = 0;

    if (key != NULL) {
        if (keylen != CHACHA20_POLY1305_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        memcpy(ctx->key, key, CHACHA20_POLY1305_KEYLEN);
        alc_error_t err = alcp_cipher_aead_init(
            &(ctx->handle), key, keylen * 8, NULL, 0);
        if (alcp_is_error(err))
            return 0;
        ctx->key_set = 1;
    }

    /* Store IV only - defer CAPI init to aead_cipher */
    if (ret && iv != NULL) {
        if (ivlen != CHACHA20_POLY1305_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->oiv, iv, CHACHA20_POLY1305_IVLEN);
        memcpy(ctx->nonce, ctx->oiv, CHACHA20_POLY1305_IVLEN);
        ctx->iv_set = 1;
    }

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    ctx->mac_inited         = 0;
    ctx->aad                = 0;

    if (ret && !chacha20_poly1305_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

/* ---- cipher / update / final ---- */

#define chacha20_poly1305_update chacha20_poly1305_cipher

static int
chacha20_poly1305_cipher(void*        vctx,
                         Uint8*       out,
                         size_t*      outl,
                         size_t       outsize,
                         const Uint8* in,
                         size_t       inl)
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;

    if (!alcp_prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!chacha20_poly1305_aead_cipher(ctx, out, outl, in, inl))
        return 0;

    return 1;
}

static int
chacha20_poly1305_final(void* vctx, Uint8* out, size_t* outl, size_t outsize)
{
    ALCP_PROV_CHACHA20_POLY1305_CTX* ctx =
        (ALCP_PROV_CHACHA20_POLY1305_CTX*)vctx;

    if (!alcp_prov_is_running())
        return 0;

    if (chacha20_poly1305_aead_cipher(ctx, out, outl, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}

/*
 * tls_init: Process TLS AAD.
 * Stores AAD, computes payload length, prepares IV XOR with sequence number.
 */
static int
chacha20_poly1305_tls_init(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                           unsigned char*                   aad,
                           size_t                           alen)
{
    unsigned int len;

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN);
    len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8
          | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
    aad = ctx->tls_aad;
    if (!ctx->enc) {
        if (len < CHACHA20_POLY1305_TAGLEN)
            return 0;
        len -= CHACHA20_POLY1305_TAGLEN; /* discount attached tag */
        aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
        aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
    }
    ctx->tls_payload_length = len;
    ctx->mac_inited         = 0;

    return CHACHA20_POLY1305_TAGLEN; /* tag length */
}

/* tls_iv_set_fixed: Store fixed IV for TLS. */
static int
chacha20_poly1305_tls_iv_set_fixed(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                                   unsigned char*                   fixed,
                                   size_t                           flen)
{
    if (flen != CHACHA20_POLY1305_IVLEN)
        return 0;
    memcpy(ctx->oiv, fixed, CHACHA20_POLY1305_IVLEN);
    memcpy(ctx->nonce, fixed, CHACHA20_POLY1305_IVLEN);
    return 1;
}

/*
 * TLS cipher path: handles a complete TLS record as a single AEAD
 * operation via the ALCP CAPI.
 */
static int
chacha20_poly1305_tls_cipher(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                             unsigned char*                   out,
                             size_t*                          out_padlen,
                             const unsigned char*             in,
                             size_t                           len)
{
    size_t      plen = ctx->tls_payload_length;
    alc_error_t err;

    /*
     * Construct nonce: XOR stored nonce with record sequence number
     * from tls_aad (first 8 bytes) per RFC 7905.
     */
    unsigned char nonce[CHACHA20_POLY1305_IVLEN];
    int           i;

    memcpy(nonce, ctx->nonce, CHACHA20_POLY1305_IVLEN);
    for (i = 0; i < 8; i++)
        nonce[CHACHA20_POLY1305_IVLEN - 8 + i] ^= ctx->tls_aad[i];

    /* Re-init CAPI with the per-record nonce */
    err = alcp_cipher_aead_init(
        &(ctx->handle), NULL, 0, nonce, CHACHA20_POLY1305_IVLEN);
    if (alcp_is_error(err))
        return 0;

    /* Set AAD */
    err = alcp_cipher_aead_set_aad(
        &(ctx->handle), ctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
    if (alcp_is_error(err))
        return 0;

    /* Encrypt or decrypt payload */
    if (ctx->enc) {
        Uint64 outlen = 0;
        err = alcp_cipher_aead_encrypt(&(ctx->handle), in, out, plen, &outlen);
    } else {
        Uint64 outlen = 0;
        err = alcp_cipher_aead_decrypt(&(ctx->handle), in, out, plen, &outlen);
    }
    if (alcp_is_error(err)) {
        if (!ctx->enc && len > CHACHA20_POLY1305_TAGLEN)
            memset(out, 0, plen);
        return 0;
    }

    /* Handle tag */
    if (ctx->enc) {
        /* Get computed tag and append after ciphertext */
        err = alcp_cipher_aead_get_tag(
            &(ctx->handle), out + plen, CHACHA20_POLY1305_TAGLEN);
        if (alcp_is_error(err))
            return 0;
        *out_padlen = plen + CHACHA20_POLY1305_TAGLEN;
    } else {
        /* Verify tag: get computed tag, compare with received tag */
        unsigned char computed_tag[CHACHA20_POLY1305_TAGLEN];
        err = alcp_cipher_aead_get_tag(
            &(ctx->handle), computed_tag, CHACHA20_POLY1305_TAGLEN);
        if (alcp_is_error(err)) {
            memset(out, 0, plen);
            return 0;
        }
        if (CRYPTO_memcmp(computed_tag, in + plen, CHACHA20_POLY1305_TAGLEN)) {
            memset(out, 0, plen);
            return 0;
        }
        *out_padlen = plen;
    }

    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    return 1;
}

/*
 * Main AEAD cipher state machine:
 *   - First call with no data: init (set up CAPI, process any TLS AAD)
 *   - Call with out==NULL: AAD processing
 *   - Call with out!=NULL: encrypt/decrypt
 *   - Call with in==NULL (or final): finalize, get/verify tag
 */
static int
chacha20_poly1305_aead_cipher(ALCP_PROV_CHACHA20_POLY1305_CTX* ctx,
                              unsigned char*                   out,
                              size_t*                          outl,
                              const unsigned char*             in,
                              size_t                           inl)
{
    size_t      plen = ctx->tls_payload_length;
    size_t      olen = 0;
    int         rv   = 0;
    alc_error_t err;

    if (!ctx->mac_inited) {
        if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL) {
            if (inl != plen + CHACHA20_POLY1305_TAGLEN)
                return 0;
            return chacha20_poly1305_tls_cipher(ctx, out, outl, in, inl);
        }

        /*
         * Re-initialize the CAPI with the stored IV. This regenerates
         * the Poly1305 one-time key and resets counters for the new
         * AEAD operation.
         */
        if (ctx->iv_set) {
            err = alcp_cipher_aead_init(
                &(ctx->handle), NULL, 0, ctx->oiv, CHACHA20_POLY1305_IVLEN);
            if (alcp_is_error(err))
                return 0;
        }
        ctx->mac_inited = 1;

        if (plen != NO_TLS_PAYLOAD_LENGTH) {
            /* TLS mode but not one-shot: set AAD */
            err = alcp_cipher_aead_set_aad(
                &(ctx->handle), ctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
            if (alcp_is_error(err))
                return 0;
            ctx->aad = 1;
        }
    }

    if (in != NULL) {      /* aad or text */
        if (out == NULL) { /* aad */
            err = alcp_cipher_aead_set_aad(&(ctx->handle), in, inl);
            if (alcp_is_error(err))
                return 0;
            ctx->aad = 1;
            goto finish;
        } else { /* plain- or ciphertext */
            ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            if (plen == NO_TLS_PAYLOAD_LENGTH)
                plen = inl;
            else if (inl != plen + CHACHA20_POLY1305_TAGLEN)
                goto err;

            if (ctx->enc) { /* plaintext */
                Uint64 outlen = 0;
                err = alcp_cipher_aead_encrypt(
                    &(ctx->handle), in, out, plen, &outlen);
            } else { /* ciphertext */
                Uint64 outlen = 0;
                err = alcp_cipher_aead_decrypt(
                    &(ctx->handle), in, out, plen, &outlen);
            }
            if (alcp_is_error(err))
                goto err;

            in += plen;
            out += plen;
        }
    }
    /* explicit final, or tls mode */
    if (in == NULL || inl != plen) {
        unsigned char temp[CHACHA20_POLY1305_TAGLEN];

        ctx->mac_inited = 0;

        if (ctx->enc) {
            err = alcp_cipher_aead_get_tag(
                &(ctx->handle), ctx->tag, CHACHA20_POLY1305_TAGLEN);
        } else {
            err = alcp_cipher_aead_get_tag(
                &(ctx->handle), temp, CHACHA20_POLY1305_TAGLEN);
        }
        if (alcp_is_error(err))
            goto err;

        if (in != NULL && inl != plen) {
            if (ctx->enc) {
                memcpy(out, ctx->tag, CHACHA20_POLY1305_TAGLEN);
            } else {
                if (CRYPTO_memcmp(temp, in, CHACHA20_POLY1305_TAGLEN)) {
                    memset(out - plen, 0, plen);
                    goto err;
                }
                /* Strip the tag */
                inl -= CHACHA20_POLY1305_TAGLEN;
            }
        } else if (!ctx->enc) {
            if (CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len))
                goto err;
        }
    }
finish:
    olen = inl;
    rv   = 1;
err:
    *outl = olen;
    return rv;
}

/* ---- Dispatch table ---- */

#define chacha20_poly1305_gettable_params                                      \
    ALCP_prov_cipher_generic_gettable_params
#define chacha20_poly1305_settable_ctx_params                                  \
    ALCP_prov_cipher_aead_settable_ctx_params

const OSSL_DISPATCH ALCP_prov_chacha20poly1305_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void))chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,
      (void (*)(void))chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,
      (void (*)(void))chacha20_poly1305_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,
      (void (*)(void))chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,
      (void (*)(void))chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE,
      (void (*)(void))chacha20_poly1305_update },
    { OSSL_FUNC_CIPHER_FINAL,
      (void (*)(void))chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER,
      (void (*)(void))chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
      (void (*)(void))chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
      (void (*)(void))chacha20_poly1305_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))chacha20_poly1305_settable_ctx_params },
    { 0, NULL }
};
