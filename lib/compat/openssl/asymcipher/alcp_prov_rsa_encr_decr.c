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
#include "alcp_prov_rsa.h"
#include "debug.h"
#include "provider/alcp_provider.h"
#include <openssl/core_names.h>
#include <openssl/types.h>

static OSSL_FUNC_asym_cipher_newctx_fn         alcp_prov_rsa_new;
static OSSL_FUNC_asym_cipher_encrypt_init_fn   alcp_prov_rsa_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn        alcp_prov_rsa_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn   alcp_prov_rsa_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn        alcp_prov_rsa_decrypt;
static OSSL_FUNC_asym_cipher_freectx_fn        alcp_prov_rsa_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn         alcp_prov_rsa_dupctx;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn alcp_prov_rsa_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
    alcp_prov_rsa_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn alcp_rsa_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
    alcp_rsa_settable_ctx_params;

// Structures taken from OpenSSL to redirect unimplemented functions
struct evp_asym_cipher_st
{
    int            name_id;
    char*          type_name;
    const char*    description;
    OSSL_PROVIDER* prov;
    int            refcnt;
#if OPENSSL_API_LEVEL < 30200
    void* lock;
#endif

    OSSL_FUNC_asym_cipher_newctx_fn*              newctx;
    OSSL_FUNC_asym_cipher_encrypt_init_fn*        encrypt_init;
    OSSL_FUNC_asym_cipher_encrypt_fn*             encrypt;
    OSSL_FUNC_asym_cipher_decrypt_init_fn*        decrypt_init;
    OSSL_FUNC_asym_cipher_decrypt_fn*             decrypt;
    OSSL_FUNC_asym_cipher_freectx_fn*             freectx;
    OSSL_FUNC_asym_cipher_dupctx_fn*              dupctx;
    OSSL_FUNC_asym_cipher_get_ctx_params_fn*      get_ctx_params;
    OSSL_FUNC_asym_cipher_gettable_ctx_params_fn* gettable_ctx_params;
    OSSL_FUNC_asym_cipher_set_ctx_params_fn*      set_ctx_params;
    OSSL_FUNC_asym_cipher_settable_ctx_params_fn* settable_ctx_params;
} /* EVP_ASYM_CIPHER */;

typedef struct
{
    OSSL_LIB_CTX* libctx;
    Rsa*          rsa;
    int           pad_mode;
    int           operation;
    /* OAEP message digest */
    EVP_MD* oaep_md;
    /* message digest for MGF1 */
    EVP_MD* mgf1_md;
    /* OAEP label */
    unsigned char* oaep_label;
    size_t         oaep_labellen;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
#if OPENSSL_API_LEVEL >= 30200
    /* PKCS#1 v1.5 decryption mode */
    unsigned int implicit_rejection;
#endif
} PROV_RSA_CTX;

typedef struct
{
    // For supporting unimplemented functionality by default provider
    PROV_RSA_CTX*    ossl_rsa_ctx;
    char             oaep_md[ALCP_MAX_NAME_SIZE];
    char             oaep_mgf1[ALCP_MAX_NAME_SIZE];
    unsigned int     seed_size;
    unsigned int     rsa_size;
    int32_t          version;
    alc_rsa_handle_t handle;
} alc_prov_rsa_ctx;

static inline EVP_ASYM_CIPHER
get_default_rsa_cipher(void)
{
    static EVP_ASYM_CIPHER enc_static;
    static int             initilazed = 0;
    if (!initilazed) {
        EVP_ASYM_CIPHER* enc = (EVP_ASYM_CIPHER*)EVP_ASYM_CIPHER_fetch(
            NULL, "RSA", "provider=default");
        if (enc) {
            enc_static = *enc;
            EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER*)enc);
            initilazed = 1;
        } else {
            printf("EVP_SIGNATURE_fetch failed");
        }
    }
    return enc_static;
}

static inline Uint32
IsZero(Uint32 num)
{
    return (0 - ((Uint32)((~num & (num - 1))) >> 31));
}

static inline Uint32
Select(Uint32 mask, Uint32 first, Uint32 second)
{
    return (mask & first) | (~mask & second);
}

static void*
alcp_prov_rsa_new(void* provctx)
{
    alc_prov_rsa_ctx* prsactx;
    prsactx = OPENSSL_zalloc(sizeof(alc_prov_rsa_ctx));
    ENTER();
    if (prsactx == NULL)
        return NULL;

    Uint64 size             = alcp_rsa_context_size();
    prsactx->handle.context = OPENSSL_zalloc(size);
    alc_error_t err         = alcp_rsa_request(&(prsactx->handle));

    typedef void* (*fun_ptr)(void* provctx);
    fun_ptr fun;
    fun = get_default_rsa_cipher().newctx;

    if (fun) {
        prsactx->ossl_rsa_ctx = fun(provctx);
    } else {
        prsactx->ossl_rsa_ctx = NULL;
    }

    if (err != ALC_ERROR_NONE || !prsactx->ossl_rsa_ctx) {
        printf("Rsa Provider: Request failed %llu\n", (unsigned long long)err);
        OPENSSL_clear_free(prsactx->handle.context, size);
        OPENSSL_clear_free(prsactx, sizeof(*prsactx));
        return 0;
    }
    EXIT();
    return prsactx;
}
static int
alcp_rsa_set_ctx_params(void* vprsactx, const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    ENTER();
    if (prsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    typedef int (*fun_ptr)(void* provctx, const OSSL_PARAM params[]);
    fun_ptr fun;
    fun = get_default_rsa_cipher().set_ctx_params;

    int ret = 0;
    if (fun) {
        ret = fun(prsactx->ossl_rsa_ctx, params);
    }

    // add oaep condition
    if (prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {

        int mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        prsactx->seed_size = alcp_rsa_get_digest_size(mode);
        alc_error_t err    = alcp_rsa_add_digest(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: digest addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }

        // add mgf condition
        mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        err = alcp_rsa_add_mgf(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: mgf addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }
    }
    EXIT();
    return ret;
}

static int
alcp_prov_rsa_encrypt_init(void*            vprsactx,
                           void*            vrsa,
                           const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    ENTER();
    if (prsactx == NULL || vrsa == NULL)
        return 0;
    prsactx->version  = ((Rsa*)vrsa)->version;
    prsactx->rsa_size = alcp_rsa_size(vrsa);

    typedef int (*fun_ptr)(
        void* vprsactx, void* vrsa, const OSSL_PARAM params[]);
    fun_ptr fun;
    fun = get_default_rsa_cipher().encrypt_init;

    if (!fun)
        return 0;

    int ret = fun(prsactx->ossl_rsa_ctx, vrsa, params);
    if (prsactx->version == RSA_ASN1_VERSION_MULTI
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        || prsactx->rsa_size != 256) {
        return ret;
    }
    // add oaep condition
    if (prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        int mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        prsactx->seed_size = alcp_rsa_get_digest_size(mode);
        alc_error_t err    = alcp_rsa_add_digest(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: digest addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }

        // add mgf condition
        mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        err = alcp_rsa_add_mgf(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: mgf addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }
    }
    Rsa*        rsa      = vrsa;
    BigNum      exponent = { rsa->e->d, rsa->e->top };
    BigNum      modulus  = { rsa->n->d, rsa->n->top };
    alc_error_t err      = alcp_rsa_set_public_key_as_bignum(
        &prsactx->handle, &exponent, &modulus);
    if (err != ALC_ERROR_NONE) {
        printf("Rsa Provider: rsa init failed %llu\n", (unsigned long long)err);
        return 0;
    }
    EXIT();
    return ret;
}
static int
alcp_prov_rsa_decrypt_init(void*            vprsactx,
                           void*            vrsa,
                           const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    ENTER();
    if (prsactx == NULL || vrsa == NULL)
        return 0;
    prsactx->version  = ((Rsa*)vrsa)->version;
    prsactx->rsa_size = alcp_rsa_size(vrsa);
    typedef int (*fun_ptr)(
        void* vprsactx, void* vrsa, const OSSL_PARAM params[]);
    fun_ptr fun;
    fun = get_default_rsa_cipher().decrypt_init;

    if (!fun)
        return 0;

    int ret = fun(prsactx->ossl_rsa_ctx, vrsa, params);

    if (prsactx->version == RSA_ASN1_VERSION_MULTI
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        || prsactx->rsa_size != 256) {
        EXIT();
        return ret;
    }

    // add oaep condition
    if (prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        int mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        prsactx->seed_size = alcp_rsa_get_digest_size(mode);
        alc_error_t err    = alcp_rsa_add_digest(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: digest addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }

        // add mgf condition
        mode = alcp_rsa_get_digest_mode(
            EVP_MD_get0_name(prsactx->ossl_rsa_ctx->oaep_md));
        err = alcp_rsa_add_mgf(&prsactx->handle, mode);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: mgf addition failed = %llu\n",
                   (unsigned long long)err);
            return 0;
        }
    }
    Rsa*        rsa  = vrsa;
    BigNum      dp   = { rsa->dmp1->d, rsa->dmp1->top };
    BigNum      dq   = { rsa->dmq1->d, rsa->dmq1->top };
    BigNum      p    = { rsa->p->d, rsa->p->top };
    BigNum      q    = { rsa->q->d, rsa->q->top };
    BigNum      qinv = { rsa->iqmp->d, rsa->iqmp->top };
    BigNum      mod  = { rsa->n->d, rsa->n->top };
    alc_error_t err  = alcp_rsa_set_private_key_as_bignum(
        &prsactx->handle, &dp, &dq, &p, &q, &qinv, &mod);
    if (err != ALC_ERROR_NONE) {
        printf("Rsa Provider: rsa decrypt init failed %llu\n",
               (unsigned long long)err);
        return 0;
    }
    EXIT();
    return ret;
}

static int
alcp_prov_rsa_encrypt(void*                vprsactx,
                      unsigned char*       out,
                      size_t*              outlen,
                      size_t               outsize,
                      const unsigned char* in,
                      size_t               inlen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    size_t            len     = prsactx->rsa_size;

    ENTER();
    if (prsactx == NULL)
        return 0;
    if (out == NULL) {
        if (len == 0) {
            printf("Rsa Provider: Invalid key size");
            return 0;
        }
        EXIT();
        *outlen = len;
        return 1;
    }

    if (prsactx->version == RSA_ASN1_VERSION_MULTI
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        || prsactx->rsa_size != 256) {
        typedef int (*fun_ptr)(void*                vprsactx,
                               unsigned char*       out,
                               size_t*              outlen,
                               size_t               outsize,
                               const unsigned char* in,
                               size_t               inlen);
        fun_ptr fun;
        fun = get_default_rsa_cipher().encrypt;

        if (!fun)
            return 0;
        EXIT();
        return fun(prsactx->ossl_rsa_ctx, out, outlen, outsize, in, inlen);
    }

    alc_error_t err = ALC_ERROR_NONE;
    if (prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        Uint8 seed[64] = { 0 };
        if (RAND_bytes_ex(NULL, seed, prsactx->seed_size, 0) <= 0)
            return 0;
        err = alcp_rsa_publickey_encrypt_oaep(
            &prsactx->handle,
            in,
            inlen,
            prsactx->ossl_rsa_ctx->oaep_label,
            prsactx->ossl_rsa_ctx->oaep_labellen,
            seed,
            out);

    } else if (RSA_PKCS1_PADDING == prsactx->ossl_rsa_ctx->pad_mode) {
        int    random_pad_len = len - 3 - inlen;
        Uint8* random_pad     = malloc(random_pad_len);
        if (RAND_bytes_ex(NULL, random_pad, random_pad_len, 0) <= 0)
            return 0;
        for (int i = 0; i < random_pad_len; i++) {
            if (!random_pad[i])
                do {
                    if (RAND_bytes_ex(NULL, &random_pad[i], 1, 0) <= 0)
                        return 0;
                } while (random_pad[i] == '\0');
        }
        err = alcp_rsa_publickey_encrypt_pkcs1v15(
            &prsactx->handle, in, inlen, out, random_pad);
        free(random_pad);
    } else if (RSA_NO_PADDING == prsactx->ossl_rsa_ctx->pad_mode) {
        err = alcp_rsa_publickey_encrypt(&prsactx->handle, in, inlen, out);
    } else {
        printf("RSA Provider : Padding mode not supported");
        return 0;
    }

    if (err != ALC_ERROR_NONE) {
        if (err == ALC_ERROR_INVALID_DATA)
            ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        return 0;
    }
    *outlen = inlen;
    EXIT();
    return 1;
}
static int
alcp_prov_rsa_decrypt(void*                vprsactx,
                      unsigned char*       out,
                      size_t*              outlen,
                      size_t               outsize,
                      const unsigned char* in,
                      size_t               inlen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    size_t            len     = prsactx->rsa_size;

    ENTER();
    if (prsactx->version == RSA_ASN1_VERSION_MULTI
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        || prsactx->rsa_size != 256) {
        typedef int (*fun_ptr)(void*                vprsactx,
                               unsigned char*       out,
                               size_t*              outlen,
                               size_t               outsize,
                               const unsigned char* in,
                               size_t               inlen);
        fun_ptr fun;
        fun = get_default_rsa_cipher().decrypt;

        if (!fun)
            return 0;

        EXIT();
        return fun(prsactx->ossl_rsa_ctx, out, outlen, outsize, in, inlen);
    }

    if (out == NULL) {
        if (len == 0) {
            printf("Rsa Provider: Invalid key size");
            return 0;
        }
        *outlen = len;
        EXIT();
        return 1;
    }

    if (outsize < len) {
        printf("Rsa Provider: Invalid outsize");
        return 0;
    }

    alc_error_t err = ALC_ERROR_NONE;

    if (prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        err = alcp_rsa_privatekey_decrypt_oaep(
            &prsactx->handle,
            in,
            inlen,
            prsactx->ossl_rsa_ctx->oaep_label,
            prsactx->ossl_rsa_ctx->oaep_labellen,
            out,
            outlen);
    } else if (RSA_PKCS1_PADDING == prsactx->ossl_rsa_ctx->pad_mode) {
        err = alcp_rsa_privatekey_decrypt_pkcs1v15(
            &prsactx->handle, in, out, outlen);
    } else if (prsactx->ossl_rsa_ctx->pad_mode == RSA_NO_PADDING) {
        err = alcp_rsa_privatekey_decrypt(
            &prsactx->handle, ALCP_RSA_PADDING_NONE, in, inlen, out);
        *outlen = len;
    }
    EXIT();
    return Select(IsZero(err), 1, 0);
}
static void
alcp_prov_rsa_freectx(void* vprsactx)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    typedef void (*fun_ptr)(void* vprsactx);
    fun_ptr fun;
    fun = get_default_rsa_cipher().freectx;

    ENTER();
    if (fun)
        fun(prsactx->ossl_rsa_ctx);

    alcp_rsa_finish(&prsactx->handle);
    OPENSSL_free(prsactx->handle.context);
    OPENSSL_free(prsactx);
    EXIT();
}

static void*
alcp_prov_rsa_dupctx(void* vprsactx)
{
    alc_prov_rsa_ctx* prsactx  = (alc_prov_rsa_ctx*)vprsactx;
    alc_prov_rsa_ctx* dest_ctx = OPENSSL_memdup(prsactx, sizeof(*prsactx));
    ENTER();
    if (dest_ctx == NULL) {
        return NULL;
    }

    Uint64 size              = alcp_rsa_context_size();
    dest_ctx->handle.context = OPENSSL_zalloc(size);

    typedef void* (*fun_ptr)(void* vprsactx);
    fun_ptr fun;

    fun = get_default_rsa_cipher().dupctx;

    if (fun)
        dest_ctx->ossl_rsa_ctx = fun(prsactx->ossl_rsa_ctx);

    if (prsactx->version == RSA_ASN1_VERSION_MULTI
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        || prsactx->rsa_size != 256) {
        EXIT();
        return dest_ctx;
    }

    alc_error_t err =
        alcp_rsa_context_copy(&prsactx->handle, &dest_ctx->handle);
    if (err != ALC_ERROR_NONE) {
        goto err_label;
    }
    EXIT();
    return dest_ctx;

err_label:
    printf("Provider: RSA copy failed in dupctx\n");
    OPENSSL_clear_free(dest_ctx->handle.context, size);
    OPENSSL_clear_free(dest_ctx, sizeof(*(dest_ctx)));
    return NULL;
}
static int
alcp_prov_rsa_get_ctx_params(void* vprsactx, OSSL_PARAM* params)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    ENTER();
    if (prsactx == NULL)
        return 0;

    typedef int (*fun_ptr)(void* vprsactx, OSSL_PARAM* params);
    fun_ptr fun;
    fun = get_default_rsa_cipher().get_ctx_params;
    if (!fun)
        return 0;
    EXIT();
    return fun(prsactx->ossl_rsa_ctx, params);
}

static const OSSL_PARAM alcp_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_DEFN(
        OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
#if OPENSSL_API_LEVEL >= 30200
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
#endif
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_prov_rsa_gettable_ctx_params(ossl_unused void* vprsactx,
                                  ossl_unused void* provctx)
{
    ENTER();
    EXIT();
    return alcp_known_gettable_ctx_params;
}
static const OSSL_PARAM alcp_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
#if OPENSSL_API_LEVEL >= 30200
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
#endif
    OSSL_PARAM_END
};
static const OSSL_PARAM*
alcp_rsa_settable_ctx_params(ossl_unused void* vprsactx,
                             ossl_unused void* provctx)
{
    ENTER();
    EXIT();
    return alcp_known_settable_ctx_params;
}
const OSSL_DISPATCH alcp_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))alcp_prov_rsa_new },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
      (void (*)(void))alcp_prov_rsa_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))alcp_prov_rsa_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
      (void (*)(void))alcp_prov_rsa_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))alcp_prov_rsa_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))alcp_prov_rsa_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))alcp_prov_rsa_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))alcp_rsa_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))alcp_rsa_settable_ctx_params },
    { 0, NULL }
};
static const char    ASYM_CIPHERS_DEF_PROP[] = "provider=alcp,fips=no";
const OSSL_ALGORITHM alc_prov_asym_ciphers[] = {
    { ALCP_PROV_NAMES_RSA,
      ASYM_CIPHERS_DEF_PROP,
      alcp_rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};
