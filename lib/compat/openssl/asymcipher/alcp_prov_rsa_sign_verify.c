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

#include "alcp/alcp.h"
#include "alcp/rsa.h"
#include "alcp_prov_rsa.h"
#include "debug.h"
#include "provider/alcp_provider.h"
#include <openssl/core_names.h>
#include <openssl/macros.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#define RSA_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1
// Structure taken from OpenSSL to support unimplemented functions
struct evp_signature_st
{
    int            name_id;
    char*          type_name;
    const char*    description;
    OSSL_PROVIDER* prov;
    int            refcnt;
#if OPENSSL_API_LEVEL < 30200
    void* lock;
#endif

    OSSL_FUNC_signature_newctx_fn*                 newctx;
    OSSL_FUNC_signature_sign_init_fn*              sign_init;
    OSSL_FUNC_signature_sign_fn*                   sign;
    OSSL_FUNC_signature_verify_init_fn*            verify_init;
    OSSL_FUNC_signature_verify_fn*                 verify;
    OSSL_FUNC_signature_verify_recover_init_fn*    verify_recover_init;
    OSSL_FUNC_signature_verify_recover_fn*         verify_recover;
    OSSL_FUNC_signature_digest_sign_init_fn*       digest_sign_init;
    OSSL_FUNC_signature_digest_sign_update_fn*     digest_sign_update;
    OSSL_FUNC_signature_digest_sign_final_fn*      digest_sign_final;
    OSSL_FUNC_signature_digest_sign_fn*            digest_sign;
    OSSL_FUNC_signature_digest_verify_init_fn*     digest_verify_init;
    OSSL_FUNC_signature_digest_verify_update_fn*   digest_verify_update;
    OSSL_FUNC_signature_digest_verify_final_fn*    digest_verify_final;
    OSSL_FUNC_signature_digest_verify_fn*          digest_verify;
    OSSL_FUNC_signature_freectx_fn*                freectx;
    OSSL_FUNC_signature_dupctx_fn*                 dupctx;
    OSSL_FUNC_signature_get_ctx_params_fn*         get_ctx_params;
    OSSL_FUNC_signature_gettable_ctx_params_fn*    gettable_ctx_params;
    OSSL_FUNC_signature_set_ctx_params_fn*         set_ctx_params;
    OSSL_FUNC_signature_settable_ctx_params_fn*    settable_ctx_params;
    OSSL_FUNC_signature_get_ctx_md_params_fn*      get_ctx_md_params;
    OSSL_FUNC_signature_gettable_ctx_md_params_fn* gettable_ctx_md_params;
    OSSL_FUNC_signature_set_ctx_md_params_fn*      set_ctx_md_params;
    OSSL_FUNC_signature_settable_ctx_md_params_fn* settable_ctx_md_params;
} /* EVP_SIGNATURE */;

// clang-format off
//ToDo : Add DigestInfo for sha3
static const Uint8 DigestInfo[SHA_UNKNOWN][19] = 
                    {
                     {0x00},   
                     {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
                      0x00, 0x04, 0x10},
                     {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
                     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
                      0x05, 0x00, 0x04, 0x1c},
                     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                      0x05, 0x00, 0x04, 0x20},
                     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                      0x05, 0x00, 0x04, 0x30},
                     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                      0x05, 0x00, 0x04, 0x40},
                     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
                      0x05, 0x00, 0x04, 0x1c},
                     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
                      0x05, 0x00, 0x04, 0x20}
                    };
// clang-format on

// Structure taken from OpenSSL to support unimplemented functions
typedef struct
{
    OSSL_LIB_CTX* libctx;
    char*         propq;
    Rsa*          rsa;
    int           operation;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;
    unsigned int mgf1_md_set   : 1;

    /* main digest */
    EVP_MD*     md;
    EVP_MD_CTX* mdctx;
    int         mdnid;
    char        mdname[ALCP_MAX_NAME_SIZE]; /* Purely informational */

    /* RSA padding mode */
    int pad_mode;
    /* message digest for MGF1 */
    EVP_MD* mgf1_md;
    int     mgf1_mdnid;
    char    mgf1_mdname[ALCP_MAX_NAME_SIZE]; /* Purely informational */
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;

    /* Temp buffer */
    unsigned char* tbuf;

} PROV_RSA_CTX;

typedef struct
{
    PROV_RSA_CTX*    ossl_rsa_ctx;
    alc_rsa_handle_t handle;
    int              mode;
    int              mdsize;
    int              rsa_size;
    int              digest_info_index;
    int              digest_info_size;
    int              crt_disabled;
} alc_prov_rsa_ctx;

#define alcp_rsa_pss_restricted(prsactx)                                       \
    (prsactx->ossl_rsa_ctx->min_saltlen != -1)

static inline EVP_SIGNATURE
get_default_rsa_signature(void)
{
    static EVP_SIGNATURE signature_static;
    static int           initilazed = 0;
    if (!initilazed) {
        EVP_SIGNATURE* signature = (EVP_SIGNATURE*)EVP_SIGNATURE_fetch(
            NULL, "RSA", "provider=default");
        if (signature) {
            signature_static = *signature;
            EVP_SIGNATURE_free((EVP_SIGNATURE*)signature);
            initilazed = 1;
        } else {
            printf("EVP_SIGNATURE_fetch failed");
        }
    }
    return signature_static;
}

static void*
alcp_prov_rsa_new(void* provctx, const char* propq)
{
    alc_prov_rsa_ctx* prsactx = NULL;

    if ((prsactx = OPENSSL_zalloc(sizeof(alc_prov_rsa_ctx))) == NULL) {
        return NULL;
    }

    Uint64 size             = alcp_rsa_context_size();
    prsactx->handle.context = OPENSSL_zalloc(size);
    alc_error_t err         = alcp_rsa_request(&(prsactx->handle));

    typedef void* (*fun_ptr)(void* provctx, const char* propq);
    fun_ptr fun;
    fun = get_default_rsa_signature().newctx;

    if (fun) {
        prsactx->ossl_rsa_ctx = fun(provctx, propq);
    } else {
        prsactx->ossl_rsa_ctx = NULL;
    }

    if (err != ALC_ERROR_NONE || !prsactx->ossl_rsa_ctx) {
        printf("Rsa Provider: Request failed %llu\n", (unsigned long long)err);
        OPENSSL_clear_free(prsactx->handle.context, size);
        OPENSSL_clear_free(prsactx, sizeof(*prsactx));
        return 0;
    }
    return prsactx;
}

static int
alcp_prov_rsa_set_ctx_params(void* vprsactx, const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    typedef int (*fun_ptr)(void* provctx, const OSSL_PARAM params[]);
    fun_ptr fun;
    fun = get_default_rsa_signature().set_ctx_params;

    int ret = 0;
    if (fun) {
        ret = fun(prsactx->ossl_rsa_ctx, params);
    }
    if (!ret || prsactx->rsa_size != 256) {
        return ret;
    }

    if (prsactx->ossl_rsa_ctx->mgf1_mdname[0] != 0) {
        int mode_mgf =
            alcp_rsa_get_digest_mode(prsactx->ossl_rsa_ctx->mgf1_mdname);
        alc_error_t err = alcp_rsa_add_mgf(&prsactx->handle, mode_mgf);
        if (err != ALC_ERROR_NONE) {
            return 0;
        }
    }

    if (prsactx->ossl_rsa_ctx->mdname[0] != 0) {
        prsactx->mode = alcp_rsa_get_digest_mode(prsactx->ossl_rsa_ctx->mdname);
        prsactx->digest_info_index =
            alcp_rsa_get_digest_info_index(prsactx->mode);
        prsactx->digest_info_size =
            alcp_rsa_get_digest_info_size(prsactx->mode);
        alc_error_t err = alcp_rsa_add_digest(&prsactx->handle, prsactx->mode);
        if (err != ALC_ERROR_NONE) {
            return 0;
        }
    }

    return 1;
}

static int
alcp_rsa_signverify_init(void*            vprsactx,
                         void*            vrsa,
                         const OSSL_PARAM params[],
                         int              operation)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    if (prsactx == NULL)
        return 0;

    if (vrsa == NULL && prsactx->ossl_rsa_ctx->rsa == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    prsactx->mode     = -1;
    prsactx->rsa_size = alcp_rsa_size(vrsa ? vrsa : prsactx->ossl_rsa_ctx->rsa);

    int ret = 0;
    typedef int (*fun_ptr)(
        void* vprsactx, void* vrsa, const OSSL_PARAM params[]);
    fun_ptr fun;
    if (EVP_PKEY_OP_SIGN == operation) {
        fun = get_default_rsa_signature().sign_init;
    } else {
        fun = get_default_rsa_signature().verify_init;
    }
    if (!fun)
        return 0;

    ret = fun(prsactx->ossl_rsa_ctx, vrsa, params);

    Rsa* rsa = prsactx->ossl_rsa_ctx->rsa;
    if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
        prsactx->crt_disabled = 1;
    } else {
        prsactx->crt_disabled = 0;
    }

    if (prsactx->rsa_size != 256 || prsactx->crt_disabled) {
        return ret;
    }

    if (EVP_PKEY_OP_SIGN == operation) {
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
    } else {
        BigNum      exponent = { rsa->e->d, rsa->e->top };
        BigNum      modulus  = { rsa->n->d, rsa->n->top };
        alc_error_t err      = alcp_rsa_set_public_key_as_bignum(
            &prsactx->handle, &exponent, &modulus);
        if (err != ALC_ERROR_NONE) {
            printf("Rsa Provider: rsa init failed %llu\n",
                   (unsigned long long)err);
            return 0;
        }
    }

    if (prsactx->ossl_rsa_ctx->mdname[0] != 0) {
        prsactx->mode = alcp_rsa_get_digest_mode(prsactx->ossl_rsa_ctx->mdname);
        prsactx->mdsize = alcp_rsa_get_digest_size(prsactx->mode);
        prsactx->digest_info_index =
            alcp_rsa_get_digest_info_index(prsactx->mode);
        prsactx->digest_info_size =
            alcp_rsa_get_digest_info_size(prsactx->mode);
    }

    return 1;
}

static int
alcp_prov_rsa_sign_init(void* vprsactx, void* vrsa, const OSSL_PARAM params[])
{
    return alcp_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static int
alcp_prov_rsa_sign(void*                vprsactx,
                   unsigned char*       sig,
                   size_t*              siglen,
                   size_t               sigsize,
                   const unsigned char* tbs,
                   size_t               tbslen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    size_t            rsasize = prsactx->rsa_size;

    if (rsasize != 256 || prsactx->crt_disabled
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_X931_PADDING) {
        typedef int (*fun_ptr)(void*                vprsactx,
                               unsigned char*       sig,
                               size_t*              siglen,
                               size_t               sigsize,
                               const unsigned char* tbs,
                               size_t               tbslen);
        fun_ptr fun;

        fun = get_default_rsa_signature().sign;

        if (!fun)
            return 0;

        return fun(prsactx->ossl_rsa_ctx, sig, siglen, sigsize, tbs, tbslen);
    }

    if (sig == NULL) {
        *siglen = rsasize;
        return 1;
    }

    if (sigsize < rsasize) {
        ERR_raise_data(ERR_LIB_PROV,
                       PROV_R_INVALID_SIGNATURE_SIZE,
                       "is %zu, should be at least %zu",
                       sigsize,
                       rsasize);
        return 0;
    }
    alc_error_t err    = ALC_ERROR_NONE;
    int         mdsize = prsactx->mdsize;
    if (mdsize != 0) {
        if (tbslen != mdsize) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
            return 0;
        }

        switch (prsactx->ossl_rsa_ctx->pad_mode) {
            case RSA_PKCS1_PADDING: {
                int    index          = prsactx->digest_info_index;
                int    size           = prsactx->digest_info_size;
                Uint8* hash_with_info = malloc(size + tbslen);
                memcpy(hash_with_info, DigestInfo[index], size);
                memcpy(hash_with_info + size, tbs, tbslen);
                err = alcp_rsa_privatekey_sign_pkcs1v15_without_hash(
                    &prsactx->handle, hash_with_info, tbslen + size, sig);
                free(hash_with_info);
                if (err != ALC_ERROR_NONE) {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
            } break;

            case RSA_PKCS1_PSS_PADDING:
                /* Check PSS restrictions */
                if (alcp_rsa_pss_restricted(prsactx)) {
                    switch (prsactx->ossl_rsa_ctx->saltlen) {
                        case RSA_PSS_SALTLEN_DIGEST:
                            if (prsactx->ossl_rsa_ctx->min_saltlen > mdsize) {
                                ERR_raise_data(
                                    ERR_LIB_PROV,
                                    PROV_R_PSS_SALTLEN_TOO_SMALL,
                                    "minimum salt length set to %d, "
                                    "but the digest only gives %d",
                                    prsactx->ossl_rsa_ctx->min_saltlen,
                                    mdsize);
                                return 0;
                            }
                            /* FALLTHRU */
                        default:
                            if (prsactx->ossl_rsa_ctx->saltlen >= 0
                                && prsactx->ossl_rsa_ctx->saltlen
                                       < prsactx->ossl_rsa_ctx->min_saltlen) {
                                ERR_raise_data(
                                    ERR_LIB_PROV,
                                    PROV_R_PSS_SALTLEN_TOO_SMALL,
                                    "minimum salt length set to %d, but the"
                                    "actual salt length is only set to %d",
                                    prsactx->ossl_rsa_ctx->min_saltlen,
                                    prsactx->ossl_rsa_ctx->saltlen);
                                return 0;
                            }
                            break;
                    }
                }
                int    sLenMax = -1;
                Uint8* salt    = NULL;
                int    sLen    = prsactx->ossl_rsa_ctx->saltlen;
                if (sLen == RSA_PSS_SALTLEN_DIGEST) {
                    sLen = mdsize;
                } else if (sLen == RSA_PSS_SALTLEN_MAX_SIGN
                           || sLen == RSA_PSS_SALTLEN_AUTO) {
                    sLen = RSA_PSS_SALTLEN_MAX;
                } else if (sLen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
                    sLen    = RSA_PSS_SALTLEN_MAX;
                    sLenMax = mdsize;
                } else if (sLen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
                    ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
                    return 0;
                }
                if (sLen == RSA_PSS_SALTLEN_MAX) {
                    sLen = rsasize - mdsize - 2;
                    if (sLenMax >= 0 && sLen > sLenMax)
                        sLen = sLenMax;
                }
                if (sLen > 0) {
                    salt = OPENSSL_malloc(sLen);
                    if (salt == NULL)
                        return 0;
                    if (RAND_bytes_ex(NULL, salt, sLen, 0) <= 0)
                        return 0;
                }
                err = alcp_rsa_privatekey_sign_pss_without_hash(
                    &prsactx->handle, tbs, tbslen, salt, sLen, sig);
                if (err != ALC_ERROR_NONE) {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
                break;

            default:
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_INVALID_PADDING_MODE,
                               "PKCS#1 v1.5 or PSS padding allowed");
                return 0;
        }
    } else {
        switch (prsactx->ossl_rsa_ctx->pad_mode) {
            case RSA_PKCS1_PADDING: {
                err = alcp_rsa_privatekey_sign_pkcs1v15_without_hash(
                    &prsactx->handle, tbs, tbslen, sig);
                break;
            }
            case RSA_NO_PADDING: {
                err = alcp_rsa_privatekey_decrypt(
                    &prsactx->handle, ALCP_RSA_PADDING_NONE, tbs, tbslen, sig);
                break;
            }
            default: {
                err = ALC_ERROR_GENERIC;
                break;
            }
        }
        if (err != ALC_ERROR_NONE) {
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            return 0;
        }
    }
    *siglen = rsasize;
    return 1;
}

static int
alcp_prov_rsa_verify_recover_init(void*            vprsactx,
                                  void*            vrsa,
                                  const OSSL_PARAM params[])
{
    return alcp_rsa_signverify_init(
        vprsactx, vrsa, params, EVP_PKEY_OP_VERIFYRECOVER);
}

static int
alcp_prov_rsa_verify_recover(void*                vprsactx,
                             unsigned char*       rout,
                             size_t*              routlen,
                             size_t               routsize,
                             const unsigned char* sig,
                             size_t               siglen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    int               ret;

    if (rout == NULL) {
        *routlen = prsactx->rsa_size;
        return 1;
    }

    if (prsactx->ossl_rsa_ctx->mdname[0] != '\0') {
        switch (prsactx->ossl_rsa_ctx->pad_mode) {
            case RSA_PKCS1_PADDING: {
                // ToDo : Implement the recover operation
                ret = 0;
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
            } break;

            default:
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_INVALID_PADDING_MODE,
                               "Only PKCS#1 v1.5 padding allowed");
                return 0;
        }
    } else {
        alc_error_t err =
            alcp_rsa_publickey_encrypt(&prsactx->handle, sig, siglen, rout);
        if (err != ALC_ERROR_NONE) {
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            return 0;
        }
    }
    *routlen = siglen;
    return 1;
}

static int
alcp_prov_rsa_verify_init(void* vprsactx, void* vrsa, const OSSL_PARAM params[])
{
    return alcp_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

static int
alcp_prov_rsa_verify(void*                vprsactx,
                     const unsigned char* sig,
                     size_t               siglen,
                     const unsigned char* tbs,
                     size_t               tbslen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    alc_error_t err = ALC_ERROR_NONE;

    size_t rsasize = prsactx->rsa_size;

    if (rsasize != 256 || prsactx->crt_disabled
        || prsactx->ossl_rsa_ctx->pad_mode == RSA_X931_PADDING) {
        typedef int (*fun_ptr)(void*                vprsactx,
                               const unsigned char* sig,
                               size_t               siglen,
                               const unsigned char* tbs,
                               size_t               tbslen);
        fun_ptr fun;

        fun = get_default_rsa_signature().verify;

        if (!fun)
            return 0;

        return fun(prsactx->ossl_rsa_ctx, sig, siglen, tbs, tbslen);
    }

    switch (prsactx->ossl_rsa_ctx->pad_mode) {
        case RSA_PKCS1_PADDING:
            if (prsactx->mode >= 0) {
                int index = prsactx->digest_info_index;
                int size  = prsactx->digest_info_size;

                Uint8* hash_with_info = malloc(size + tbslen);
                memcpy(hash_with_info, DigestInfo[index], size);
                memcpy(hash_with_info + size, tbs, tbslen);
                err = alcp_rsa_publickey_verify_pkcs1v15_without_hash(
                    &prsactx->handle, hash_with_info, tbslen + size, sig);
                free(hash_with_info);
            } else {
                err = alcp_rsa_publickey_verify_pkcs1v15_without_hash(
                    &prsactx->handle, tbs, tbslen, sig);
            }
            if (err != ALC_ERROR_NONE) {
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }
            break;
        case RSA_PKCS1_PSS_PADDING: {
            size_t mdsize = alcp_rsa_get_digest_size(prsactx->mode);
            if (tbslen != mdsize) {
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_INVALID_DIGEST_LENGTH,
                               "Should be %d, but got %d",
                               mdsize,
                               tbslen);
                return 0;
            }
            err = alcp_rsa_publickey_verify_pss_without_hash(
                &prsactx->handle, tbs, tbslen, sig);

            if (err != ALC_ERROR_NONE) {
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }
            break;
        }
        case RSA_NO_PADDING: {
            Uint8*      text = malloc(siglen);
            alc_error_t err =
                alcp_rsa_publickey_encrypt(&prsactx->handle, sig, siglen, text);
            if (err != ALC_ERROR_NONE || CRYPTO_memcmp(text, tbs, tbslen)) {
                free(text);
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }

            break;
        }
        default:
            ERR_raise_data(ERR_LIB_PROV,
                           PROV_R_INVALID_PADDING_MODE,
                           "Non padding or PKCS#1 v1.5 or PSS padding allowed");
            return 0;
    }

    return 1;
}

// static int
// alcp_rsa_digest_signverify_init(void*            vprsactx,
//                                 const char*      mdname,
//                                 void*            vrsa,
//                                 const OSSL_PARAM params[],
//                                 int              operation)
// {
//     alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

//     if (!alcp_rsa_signverify_init(vprsactx, vrsa, params, operation))
//         return 0;

//     // ToDO : check if this can be further cleaned up
//     if (mdname != NULL
//         && (mdname[0] == '\0'
//             || OPENSSL_strcasecmp(prsactx->ossl_rsa_ctx->mdname, mdname)
//                    != 0)) {
//         int mode_digest = alcp_rsa_get_digest_mode(mdname);
//         prsactx->mode   = mode_digest;
//         prsactx->mdsize = alcp_rsa_get_digest_size(mode_digest);
//         // Add mdnid
//         prsactx->ossl_rsa_ctx->mdnid = alcp_rsa_get_nid(mode_digest);

//         alc_error_t err = alcp_rsa_add_digest(&prsactx->handle, mode_digest);
//         if (err != ALC_ERROR_NONE) {
//             return 0;
//         }
//     }

//     prsactx->ossl_rsa_ctx->flag_allow_md = 0;

//     if (prsactx->ossl_rsa_ctx->mdctx == NULL) {
//         prsactx->ossl_rsa_ctx->mdctx = EVP_MD_CTX_new();
//         if (prsactx->ossl_rsa_ctx->mdctx == NULL)
//             goto error;
//     }

//     if (!EVP_DigestInit_ex2(
//             prsactx->ossl_rsa_ctx->mdctx, EVP_get_digestbyname(mdname),
//             params))
//         goto error;

//     return 1;

// error:
//     EVP_MD_CTX_free(prsactx->ossl_rsa_ctx->mdctx);
//     prsactx->ossl_rsa_ctx->mdctx = NULL;
//     return 0;
// }

static int
alcp_prov_rsa_digest_sign_update(void*                vprsactx,
                                 const unsigned char* data,
                                 size_t               datalen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    typedef int (*fun_ptr)(
        void* vprsactx, const unsigned char* data, size_t datalen);
    fun_ptr fun;

    fun = get_default_rsa_signature().digest_sign_update;

    if (!fun)
        return 0;
    return fun(prsactx->ossl_rsa_ctx, data, datalen);
}

static int
alcp_prov_rsa_digest_verify_update(void*                vprsactx,
                                   const unsigned char* data,
                                   size_t               datalen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    typedef int (*fun_ptr)(
        void* vprsactx, const unsigned char* data, size_t datalen);
    fun_ptr fun;

    fun = get_default_rsa_signature().digest_verify_update;

    if (!fun)
        return 0;
    return fun(prsactx->ossl_rsa_ctx, data, datalen);
}

static int
alcp_prov_rsa_digest_sign_init(void*            vprsactx,
                               const char*      mdname,
                               void*            vrsa,
                               const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    typedef int (*fun_ptr)(void*            vprsactx,
                           const char*      mdname,
                           void*            vrsa,
                           const OSSL_PARAM params[]);
    fun_ptr fun;

    fun = get_default_rsa_signature().digest_sign_init;

    if (!fun)
        return 0;

    int ret = fun(prsactx->ossl_rsa_ctx, mdname, vrsa, params);

    Rsa* rsa          = prsactx->ossl_rsa_ctx->rsa;
    prsactx->rsa_size = alcp_rsa_size(rsa);

    if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
        prsactx->crt_disabled = 1;
    } else {
        prsactx->crt_disabled = 0;
    }

    if (prsactx->rsa_size != 256 || prsactx->crt_disabled) {
        return ret;
    }

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

    prsactx->mode              = alcp_rsa_get_digest_mode(mdname);
    prsactx->mdsize            = alcp_rsa_get_digest_size(prsactx->mode);
    prsactx->digest_info_index = alcp_rsa_get_digest_info_index(prsactx->mode);
    prsactx->digest_info_size  = alcp_rsa_get_digest_info_size(prsactx->mode);

    err = alcp_rsa_add_digest(&prsactx->handle, prsactx->mode);
    if (err != ALC_ERROR_NONE) {
        return 0;
    }

    return ret;
}

static int
alcp_prov_rsa_digest_sign_final(void*          vprsactx,
                                unsigned char* sig,
                                size_t*        siglen,
                                size_t         sigsize)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    unsigned char     digest[EVP_MAX_MD_SIZE];
    unsigned int      dlen = 0;

    if (prsactx == NULL)
        return 0;
    int rsasize = prsactx->rsa_size;
    if (rsasize != 256) {
        typedef int (*fun_ptr)(
            void* vprsactx, unsigned char* sig, size_t* siglen, size_t sigsize);
        fun_ptr fun;

        fun = get_default_rsa_signature().digest_sign_final;

        if (!fun)
            return 0;

        int ret = fun(prsactx->ossl_rsa_ctx, sig, siglen, sigsize);

        return ret;
    }

    prsactx->ossl_rsa_ctx->flag_allow_md = 1;
    if (prsactx->ossl_rsa_ctx->mdctx == NULL)
        return 0;

    if (sig != NULL) {
        /*
         * The digests used here are all known (see rsa_get_md_nid()), so
         * they should not exceed the internal buffer size of
         * EVP_MAX_MD_SIZE.
         */
        if (!EVP_DigestFinal_ex(prsactx->ossl_rsa_ctx->mdctx, digest, &dlen))
            return 0;
    }

    int ret = alcp_prov_rsa_sign(
        vprsactx, sig, siglen, sigsize, digest, (size_t)dlen);

    return ret;
}

static int
alcp_prov_rsa_digest_verify_init(void*            vprsactx,
                                 const char*      mdname,
                                 void*            vrsa,
                                 const OSSL_PARAM params[])
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    typedef int (*fun_ptr)(void*            vprsactx,
                           const char*      mdname,
                           void*            vrsa,
                           const OSSL_PARAM params[]);
    fun_ptr fun;

    fun = get_default_rsa_signature().digest_verify_init;

    if (!fun)
        return 0;

    int ret = fun(prsactx->ossl_rsa_ctx, mdname, vrsa, params);

    prsactx->rsa_size = alcp_rsa_size(prsactx->ossl_rsa_ctx->rsa);

    if (prsactx->rsa_size != 256) {
        return ret;
    }

    Rsa*        rsa      = prsactx->ossl_rsa_ctx->rsa;
    BigNum      exponent = { rsa->e->d, rsa->e->top };
    BigNum      modulus  = { rsa->n->d, rsa->n->top };
    alc_error_t err      = alcp_rsa_set_public_key_as_bignum(
        &prsactx->handle, &exponent, &modulus);
    if (err != ALC_ERROR_NONE) {
        printf("Rsa Provider: rsa init failed %llu\n", (unsigned long long)err);
        return 0;
    }

    int mode_digest            = alcp_rsa_get_digest_mode(mdname);
    prsactx->mode              = mode_digest;
    prsactx->mdsize            = alcp_rsa_get_digest_size(mode_digest);
    prsactx->digest_info_index = alcp_rsa_get_digest_info_index(prsactx->mode);
    prsactx->digest_info_size  = alcp_rsa_get_digest_info_size(prsactx->mode);

    err = alcp_rsa_add_digest(&prsactx->handle, mode_digest);
    if (err != ALC_ERROR_NONE) {
        return 0;
    }
    return ret;
    // return alcp_rsa_digest_signverify_init(
    //     vprsactx, mdname, vrsa, params, EVP_PKEY_OP_VERIFY);
}

int
alcp_prov_rsa_digest_verify_final(void*                vprsactx,
                                  const unsigned char* sig,
                                  size_t               siglen)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    unsigned char     digest[EVP_MAX_MD_SIZE];
    unsigned int      dlen = 0;

    if (prsactx == NULL)
        return 0;

    size_t rsasize = prsactx->rsa_size;
    if (rsasize != 256) {
        typedef int (*fun_ptr)(
            void* vprsactx, const unsigned char* sig, size_t siglen);
        fun_ptr fun;

        fun = get_default_rsa_signature().digest_verify_final;

        if (!fun)
            return 0;

        return fun(prsactx->ossl_rsa_ctx, sig, siglen);
    }

    prsactx->ossl_rsa_ctx->flag_allow_md = 1;
    if (prsactx->ossl_rsa_ctx->mdctx == NULL)
        return 0;

    if (!EVP_DigestFinal_ex(prsactx->ossl_rsa_ctx->mdctx, digest, &dlen))
        return 0;

    int ret = alcp_prov_rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
    return ret;
}

static void
alcp_prov_rsa_freectx(void* vprsactx)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    if (prsactx == NULL)
        return;

    typedef void (*fun_ptr)(void* vprsactx);
    fun_ptr fun;

    fun = get_default_rsa_signature().freectx;

    if (fun)
        fun(prsactx->ossl_rsa_ctx);

    alcp_rsa_finish(&prsactx->handle);
    OPENSSL_free(prsactx->handle.context);
    OPENSSL_clear_free(prsactx, sizeof(alc_prov_rsa_ctx));
}

static void*
alcp_prov_rsa_dupctx(void* vprsactx)
{
    alc_prov_rsa_ctx* prsactx  = (alc_prov_rsa_ctx*)vprsactx;
    alc_prov_rsa_ctx* dest_ctx = OPENSSL_memdup(prsactx, sizeof(*prsactx));
    if (dest_ctx == NULL) {
        return NULL;
    }

    Uint64 size              = alcp_rsa_context_size();
    dest_ctx->handle.context = OPENSSL_zalloc(size);

    typedef void* (*fun_ptr)(void* vprsactx);
    fun_ptr fun;

    fun = get_default_rsa_signature().dupctx;

    if (fun)
        dest_ctx->ossl_rsa_ctx = fun(prsactx->ossl_rsa_ctx);

    if (prsactx->rsa_size != 256) {
        return dest_ctx;
    }

    alc_error_t err =
        alcp_rsa_context_copy(&prsactx->handle, &dest_ctx->handle);
    if (err != ALC_ERROR_NONE) {
        goto err_label;
    }

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
    typedef int (*fun_ptr)(void* vprsactx, OSSL_PARAM* params);
    fun_ptr fun = get_default_rsa_signature().get_ctx_params;
    if (!fun)
        return 0;

    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    return fun(prsactx->ossl_rsa_ctx, params);
}

static const OSSL_PARAM alcp_known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM*
alcp_prov_rsa_gettable_ctx_params(ossl_unused void* vprsactx,
                                  ossl_unused void* provctx)
{
    return alcp_known_gettable_ctx_params;
}

static const OSSL_PARAM alcp_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM alcp_settable_ctx_params_no_digest[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM*
alcp_prov_rsa_settable_ctx_params(void* vprsactx, ossl_unused void* provctx)
{
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;

    if (prsactx != NULL && !prsactx->ossl_rsa_ctx->flag_allow_md)
        return alcp_settable_ctx_params_no_digest;
    return alcp_settable_ctx_params;
}

static int
alcp_prov_rsa_get_ctx_md_params(void* vprsactx, OSSL_PARAM* params)
{
    typedef int (*fun_ptr)(void* vprsactx, OSSL_PARAM* params);
    fun_ptr fun = get_default_rsa_signature().get_ctx_md_params;
    if (!fun)
        return 0;
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    return fun(prsactx->ossl_rsa_ctx, params);
}

static const OSSL_PARAM*
alcp_prov_rsa_gettable_ctx_md_params(void* vprsactx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void* vprsactx);
    fun_ptr fun = get_default_rsa_signature().gettable_ctx_md_params;
    if (!fun)
        return NULL;
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    return fun(prsactx->ossl_rsa_ctx);
}

static int
alcp_prov_rsa_set_ctx_md_params(void* vprsactx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void* vprsactx, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_rsa_signature().set_ctx_md_params;
    if (!fun)
        return 0;
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    return fun(prsactx->ossl_rsa_ctx, params);
}

static const OSSL_PARAM*
alcp_prov_rsa_settable_ctx_md_params(void* vprsactx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void* vprsactx);
    fun_ptr fun = get_default_rsa_signature().settable_ctx_md_params;
    if (!fun)
        return NULL;
    alc_prov_rsa_ctx* prsactx = (alc_prov_rsa_ctx*)vprsactx;
    return fun(prsactx->ossl_rsa_ctx);
}

const OSSL_DISPATCH alcp_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))alcp_prov_rsa_new },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))alcp_prov_rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))alcp_prov_rsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))alcp_prov_rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))alcp_prov_rsa_verify },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
      (void (*)(void))alcp_prov_rsa_verify_recover_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
      (void (*)(void))alcp_prov_rsa_verify_recover },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))alcp_prov_rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))alcp_prov_rsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))alcp_prov_rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))alcp_prov_rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))alcp_prov_rsa_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))alcp_prov_rsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))alcp_prov_rsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))alcp_prov_rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))alcp_prov_rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))alcp_prov_rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))alcp_prov_rsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))alcp_prov_rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))alcp_prov_rsa_settable_ctx_md_params },
    { 0, NULL }
};

static const char    ASYM_CIPHERS_DEF_PROP[] = "provider=alcp,fips=no";
const OSSL_ALGORITHM alc_prov_signature[]    = { { ALCP_PROV_NAMES_RSA,
                                                ASYM_CIPHERS_DEF_PROP,
                                                alcp_rsa_signature_functions },
                                              { NULL, NULL, NULL } };
