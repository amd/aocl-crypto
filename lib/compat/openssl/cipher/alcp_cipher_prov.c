/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

void
ALCP_prov_cipher_freectx(void* vctx)
{
    alc_prov_cipher_ctx_p pcctx = vctx;
    ENTER();

    if (pcctx->handle.ch_context != NULL) {
        OPENSSL_free(pcctx->handle.ch_context);
        pcctx->handle.ch_context = NULL;
    }
    /*
     * pcctx->pc_evp_cipher will be  freed in provider teardown,
     */
    EVP_CIPHER_CTX_free(pcctx->pc_evp_cipher_ctx);
    pcctx->pc_evp_cipher_ctx = NULL;

    OPENSSL_free(vctx);
    vctx = NULL;
}

void*
ALCP_prov_cipher_newctx(void* vprovctx, const alc_cipher_info_p cinfo)
{
    alc_prov_cipher_ctx_p ciph_ctx;
    alc_prov_ctx_p        pctx = (alc_prov_ctx_p)vprovctx;

    ENTER();
    ciph_ctx = OPENSSL_zalloc(sizeof(*ciph_ctx));

    if (ciph_ctx != NULL) {
        ciph_ctx->pc_prov_ctx = pctx;
        // ciph_ctx->pc_params         = pparams;
        ciph_ctx->pc_libctx         = pctx->ap_libctx;
        ciph_ctx->pc_cipher_info    = *cinfo;
        ciph_ctx->ivlen             = -1;
        ciph_ctx->pc_evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (!ciph_ctx->pc_evp_cipher_ctx || !ciph_ctx->pc_prov_ctx) {
            ALCP_prov_cipher_freectx(ciph_ctx);
            ciph_ctx = NULL;
        }
    }

    return ciph_ctx;
}

void*
ALCP_prov_cipher_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implement
    alc_prov_cipher_ctx_p csrc = vctx;
    EXIT();
    return csrc;
}

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_cipher_gettable_params(void* provctx)
{
    EXIT();
    return cipher_known_gettable_params;
}

int
ALCP_prov_cipher_get_params(OSSL_PARAM params[], int mode, int key_size)
{
    OSSL_PARAM* p;
    int         kbits   = key_size;
    int         blkbits = 128;
    int         ivbits  = 128;

    ENTER();

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    EXIT();
    return 1;
}

const OSSL_PARAM*
ALCP_prov_cipher_gettable_ctx_params(void* cctx, void* provctx)
{
    return cipher_known_gettable_params;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_cipher_settable_ctx_params(void* cctx, void* provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END,
    };
    EXIT();
    return table;
}

int
ALCP_prov_cipher_set_params(const OSSL_PARAM params[])
{
    ENTER();
    return 1;
}

int
ALCP_prov_cipher_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    OSSL_PARAM*           p;
    alc_prov_cipher_ctx_p cctx   = (alc_prov_cipher_ctx_p)vctx;
    size_t                keylen = cctx->pc_cipher_info.ci_key_info.len;

    ENTER();

    if (keylen > 0
        && (p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "tag")) != NULL) {
        const void* tag;
        size_t      used_length;
        if (!OSSL_PARAM_get_octet_string_ptr(params, &tag, &used_length)) {
            printf("Provider: An error has occurred\n");
        }
#ifdef DEBUG
        printf("Provider: Size is %ld and tag is %p\n", used_length, tag);
#endif
        cctx->taglen = used_length;
        if (!cctx->add_inititalized
            && (cctx->pc_cipher_info.ci_algo_info.ai_mode
                == ALC_AES_MODE_CCM)) {
            Uint8 a;
            alcp_cipher_set_tag_length(&(cctx->handle), cctx->taglen);
            alcp_cipher_set_iv(&(cctx->handle),
                               cctx->ivlen,
                               cctx->pc_cipher_info.ci_algo_info.ai_iv);
            if (cctx->aadlen != 0)
                alcp_cipher_set_aad(&(cctx->handle), cctx->aad, cctx->aadlen);
            cctx->add_inititalized = true;
            alcp_cipher_encrypt_update(&(cctx->handle),
                                       &a,
                                       &a,
                                       0,
                                       cctx->pc_cipher_info.ci_algo_info.ai_iv);
        }
        alcp_cipher_get_tag(&(cctx->handle), (Uint8*)tag, used_length);
    }

    EXIT();
    return 1;
}

int
ALCP_prov_cipher_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM*     p;
    alc_prov_cipher_ctx_p cctx = (alc_prov_cipher_ctx_p)vctx;
    ENTER();

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;
        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
        cctx->pc_cipher_info.ci_key_info.len = keylen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen;
        if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
#ifdef DEBUG
        printf("Provider: IVLEN Length is %ld \n", ivlen);
#endif
        cctx->ivlen = ivlen;
    }

    // Getting the Tag for AEAD including SIV
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            printf("Provider: TAG is in wrong format!\n");
            return 0;
        }
        cctx->tagbuff = p->data;
        cctx->taglen  = p->data_size;
    }

#ifdef DEBUG
    printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif

    EXIT();
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
    ENTER();
    const OSSL_PARAM*     p;
    alc_prov_cipher_ctx_p cctx            = vctx;
    alc_cipher_info_p     cinfo           = &cctx->pc_cipher_info;
    alc_key_info_p        kinfo_tweak_key = &cctx->kinfo_tweak_key;
    alc_key_info_p        kinfo_siv_ctr_key = &cctx->kinfo_siv_ctr_key;
    alc_error_t           err;

    // Locate TAG
    if (params) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->tagbuff = p->data;
            cctx->taglen  = p->data_size;
#ifdef DEBUG
            printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif
        }
        // Locate IV
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->ivlen = *((int*)(p->data));
#ifdef DEBUG
            printf("Provider: Got IVLen as :%ld bytes\n", cctx->ivlen);
#endif
        }
        return 1;
    }

    assert(cinfo->ci_type == ALC_CIPHER_TYPE_AES);

    switch (cinfo->ci_algo_info.ai_mode) {
        case ALC_AES_MODE_CFB:
            PRINT("Provider: CFB\n");
            break;
        case ALC_AES_MODE_CBC:
            PRINT("Provider: CBC\n");
            break;
        case ALC_AES_MODE_OFB:
            PRINT("Provider: OFB\n");
            break;
        case ALC_AES_MODE_CTR:
            PRINT("Provider: CTR\n");
            break;
        case ALC_AES_MODE_ECB:
            PRINT("Provider: ECB\n");
            break;
        case ALC_AES_MODE_XTS:
            PRINT("Provider: XTS\n");
            break;
        case ALC_AES_MODE_GCM:
            PRINT("Provider: GCM\n");
            break;
        case ALC_AES_MODE_CCM:
            PRINT("Provider: CCM\n");
            break;
        case ALC_AES_MODE_SIV:
            PRINT("Provider: SIV\n");
            break;
        default:
            return 0;
    }
    cctx->pc_cipher_info.ci_type = ALC_CIPHER_TYPE_AES;
    // Mode Already set
    if (iv != NULL) {
        cctx->pc_cipher_info.ci_algo_info.ai_iv = iv;
    }
    cctx->pc_cipher_info.ci_key_info.key  = key;
    cctx->pc_cipher_info.ci_key_info.fmt  = ALC_KEY_FMT_RAW;
    cctx->pc_cipher_info.ci_key_info.type = ALC_KEY_TYPE_SYMMETRIC;

    // OpenSSL Speed likes to keep keylen 0
    if (keylen != 0) {
        cctx->pc_cipher_info.ci_key_info.len = keylen;
    } else {
        cctx->pc_cipher_info.ci_key_info.len = 128;
        cctx->pc_cipher_info.ci_key_info.key = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n",
           cinfo->ci_key_info.len,
           keylen,
           key);
#endif
    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_XTS) {
        const Uint8* tweak_key     = NULL;
        int          tweak_key_len = 128;
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        if (keylen == 128) {
            tweak_key     = key + 16;
            tweak_key_len = 128;

        } else if (keylen == 256) {
            tweak_key     = key + 32;
            tweak_key_len = 256;
        } else {
#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with error
            return 0;
        }
        kinfo_tweak_key->type                   = ALC_KEY_TYPE_SYMMETRIC;
        kinfo_tweak_key->fmt                    = ALC_KEY_FMT_RAW;
        kinfo_tweak_key->key                    = tweak_key;
        kinfo_tweak_key->len                    = tweak_key_len;
        cinfo->ci_algo_info.ai_xts.xi_tweak_key = kinfo_tweak_key;
    }

    // Check for support
    err = alcp_cipher_supported(cinfo);
    if (alcp_is_error(err)) {
        printf("Provider: Not supported algorithm!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Support success!\n");
    }
#endif


    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size(cinfo));
    // For SIV, Authentication Key assumed to be same length as Decryption Key
    // Hence not modifying cinfo->ci_key_info.key or cinfo->ci_key_info.len
    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_SIV) {
        // For openSSL SIV encryption and authentication key needs to be in continous memory location. 
        // Second part of the key is authentication key
        kinfo_siv_ctr_key->len = keylen;
        kinfo_siv_ctr_key->key = key+(keylen/8);
        cinfo->ci_algo_info.ai_siv.xi_ctr_key = kinfo_siv_ctr_key;
     }

    // Request handle for the cipher
    err = alcp_cipher_request(cinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif
    // Enable Encryption Mode
    cctx->enc_flag = true;

    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_GCM) {
#ifdef DEBUG
        printf("Provider: cctx->ivlen : %lu\n", cctx->ivlen);
#endif
        if (key != NULL && iv != NULL) {
            if (cctx->ivlen != -1) {
                err =
                    alcp_cipher_set_iv(&(cctx->handle),
                                       cctx->ivlen,
                                       cctx->pc_cipher_info.ci_algo_info.ai_iv);
                if (alcp_is_error(err)) {
                    printf("Provider: Error While Setting the IVLength\n");
                }
            } else {
                printf("Provider: Error IV Len is not initialized!\n");
            }
        }
    }

#ifdef DEBUG
    printf("Provider: cctx->taglen: %d\n", cctx->taglen);
#endif
    cctx->add_inititalized = false;
    EXIT();

    return 1;
}

int
ALCP_prov_cipher_decrypt_init(void*                vctx,
                              const unsigned char* key,
                              size_t               keylen,
                              const unsigned char* iv,
                              size_t               ivlen,
                              const OSSL_PARAM     params[])
{
    const OSSL_PARAM*     p;
    alc_prov_cipher_ctx_p cctx            = vctx;
    alc_key_info_p        kinfo_tweak_key = &cctx->kinfo_tweak_key;
    alc_cipher_info_p     cinfo           = &cctx->pc_cipher_info;
    alc_error_t           err;
    // const int             err_size = 256;
    // Uint8               err_buf[err_size];
    ENTER();

    // Locate TAG
    if (params) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->tagbuff = p->data;
            cctx->taglen  = p->data_size;
#ifdef DEBUG
            printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif
        }
        // Locate IV
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
                printf("Provider: TAG is in wrong format!\n");
                return 0;
            }
            cctx->ivlen = *((int*)(p->data));
#ifdef DEBUG
            printf("Provider: Got IVLen as :%ld bytes\n", cctx->ivlen);
#endif
        }
        return 1;
    }

    assert(cinfo->ci_type == ALC_CIPHER_TYPE_AES);
    switch (cinfo->ci_algo_info.ai_mode) {
        case ALC_AES_MODE_CFB:
            PRINT("Provider: CFB\n");
            break;
        case ALC_AES_MODE_CBC:
            PRINT("Provider: CBC\n");
            break;
        case ALC_AES_MODE_OFB:
            PRINT("Provider: OFB\n");
            break;
        case ALC_AES_MODE_CTR:
            PRINT("Provider: CTR\n");
            break;
        case ALC_AES_MODE_ECB:
            PRINT("Provider: ECB\n");
            break;
        case ALC_AES_MODE_XTS:
            PRINT("Provider: XTS\n");
            break;
        case ALC_AES_MODE_GCM:
            PRINT("Provider: GCM\n");
            break;
        case ALC_AES_MODE_CCM:
            PRINT("Provider: CCM\n");
            break;
        case ALC_AES_MODE_SIV:
            PRINT("Provider: SIV\n");
            break;
        default:
            return 0;
    }
    cctx->pc_cipher_info.ci_type = ALC_CIPHER_TYPE_AES;
    // Mode Already set
    if (iv != NULL) {
        cctx->pc_cipher_info.ci_algo_info.ai_iv = iv;
    } else {
        // iv = OPENSSL_malloc(128); // Don't make sense
    }
    cctx->pc_cipher_info.ci_key_info.key  = key;
    cctx->pc_cipher_info.ci_key_info.fmt  = ALC_KEY_FMT_RAW;
    cctx->pc_cipher_info.ci_key_info.type = ALC_KEY_TYPE_SYMMETRIC;

    // Special handling for XTS Keylen is required if the below code is ever
    // commented out OpenSSL Speed likes to keep keylen 0
    if (keylen != 0) {
        cctx->pc_cipher_info.ci_key_info.len = keylen;
    } else {
        cctx->pc_cipher_info.ci_key_info.len = 128;
        cctx->pc_cipher_info.ci_key_info.key = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n",
           cinfo->ci_key_info.len,
           keylen,
           iv);
#endif

    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_XTS) {
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        const Uint8* tweak_key     = NULL;
        int          tweak_key_len = 128;
        if (keylen == 128) {
            tweak_key     = key + 16;
            tweak_key_len = 128;
        } else if (keylen == 256) {
            tweak_key     = key + 32;
            tweak_key_len = 256;
        } else {
#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with Error
            return 0;
        }
        kinfo_tweak_key->type                   = ALC_KEY_TYPE_SYMMETRIC;
        kinfo_tweak_key->fmt                    = ALC_KEY_FMT_RAW;
        kinfo_tweak_key->key                    = tweak_key;
        kinfo_tweak_key->len                    = tweak_key_len;
        cinfo->ci_algo_info.ai_xts.xi_tweak_key = kinfo_tweak_key;
    }

    alc_key_info_p        kinfo_siv_ctr_key = &cctx->kinfo_siv_ctr_key;
    
    
    // For SIV, Authentication Key assumed to be same length as Encryption Key
    // Hence not modifying cinfo->ci_key_info.key or cinfo->ci_key_info.len
    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_SIV) {
        // For openSSL SIV encryption and authentication key need to be in continous memory location. 
        // Second part of the key is authentication key
        kinfo_siv_ctr_key->len = keylen;
        kinfo_siv_ctr_key->key = key+(keylen/8);
        cinfo->ci_algo_info.ai_siv.xi_ctr_key = kinfo_siv_ctr_key;
     }

    // Check for support
    err = alcp_cipher_supported(cinfo);
    if (alcp_is_error(err)) {
        printf("Provider: Not supported algorithm!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Support success!\n");
    }
#endif

    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size(cinfo));

    // Request handle for the cipher
    err = alcp_cipher_request(cinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif
    // Enable Encryption Mode
    cctx->enc_flag = false;

    if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_GCM) {
        if (key != NULL && iv != NULL) {
            if (ivlen != -1) {
                err =
                    alcp_cipher_set_iv(&(cctx->handle),
                                       cctx->ivlen,
                                       cctx->pc_cipher_info.ci_algo_info.ai_iv);
                if (alcp_is_error(err)) {
                    printf("Provider: Error While Setting the IVLength\n");
                }
            } else {
                printf("Provider: Error IV Len is not initialized!\n");
            }
        }
    }
    cctx->add_inititalized = false;
    EXIT();
    return 1;
}

int
ALCP_prov_cipher_update(void*                vctx,
                        unsigned char*       out,
                        size_t*              outl,
                        size_t               outsize,
                        const unsigned char* in,
                        size_t               inl)
{
    alc_prov_cipher_ctx_p cctx     = vctx;
    alc_error_t           err      = ALC_ERROR_NONE;
    alc_cipher_info_p     cinfo    = &cctx->pc_cipher_info;
    const int             err_size = 256;
    Uint8                 err_buf[err_size];
    ENTER();

    if (inl == 0) {
        *outl = inl;
        return 1;
    }

    if (cctx->enc_flag) {
        if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_CCM) {
            if (out == NULL && outl != NULL && in != NULL) { // AAD call
                cctx->aadlen = inl;
                cctx->aad    = in;
            } else if (out != NULL && outl != NULL
                       && in != NULL) { // Encrypt Call
                err = alcp_cipher_set_tag_length(&(cctx->handle), cctx->taglen);
                if (alcp_is_error(err))
                    goto out;
                err =
                    alcp_cipher_set_iv(&(cctx->handle),
                                       cctx->ivlen,
                                       cctx->pc_cipher_info.ci_algo_info.ai_iv);
                if (alcp_is_error(err))
                    goto out;
                if (cctx->aadlen != 0) {
                    err = alcp_cipher_set_aad(
                        &(cctx->handle), cctx->aad, cctx->aadlen);
                    if (alcp_is_error(err))
                        goto out;
                }
                cctx->add_inititalized = true;
                err                    = alcp_cipher_encrypt_update(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    cctx->pc_cipher_info.ci_algo_info.ai_iv);
            }
        } else if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_GCM) {
            if (out == NULL) {
                err = alcp_cipher_set_aad(&(cctx->handle), in, inl);
            } else {
                err = alcp_cipher_encrypt_update(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    cctx->pc_cipher_info.ci_algo_info.ai_iv);
            }
        }  else if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_SIV) {
            if (out == NULL) {
                err = alcp_cipher_set_aad(&(cctx->handle), in, inl);
            } else {
                uint8_t fake_iv[100] = {0};
                err = alcp_cipher_encrypt(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    fake_iv);
            }
        } else {
            err = alcp_cipher_encrypt(&(cctx->handle),
                                      in,
                                      out,
                                      inl,
                                      cctx->pc_cipher_info.ci_algo_info.ai_iv);
        }
    } else {
        if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_CCM) {
            if (out == NULL && outl != NULL && in != NULL) { // AAD call
                cctx->aadlen = inl;
                cctx->aad    = in;
            } else if (out != NULL && outl != NULL
                       && in != NULL) { // Encrypt Call
                err = alcp_cipher_set_tag_length(&(cctx->handle), cctx->taglen);
                if (alcp_is_error(err))
                    goto out;
                err =
                    alcp_cipher_set_iv(&(cctx->handle),
                                       cctx->ivlen,
                                       cctx->pc_cipher_info.ci_algo_info.ai_iv);
                if (alcp_is_error(err))
                    goto out;
                if (cctx->aadlen != 0) {
                    err = alcp_cipher_set_aad(
                        &(cctx->handle), cctx->aad, cctx->aadlen);
                    if (alcp_is_error(err))
                        goto out;
                }
                cctx->add_inititalized = true;
                err                    = alcp_cipher_decrypt_update(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    cctx->pc_cipher_info.ci_algo_info.ai_iv);
            }
        } else if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_GCM) {
            if (out == NULL) {
                err = alcp_cipher_set_aad(&(cctx->handle), in, inl);
            } else {
                err = alcp_cipher_decrypt_update(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    cctx->pc_cipher_info.ci_algo_info.ai_iv);
            }
        } else if (cinfo->ci_algo_info.ai_mode == ALC_AES_MODE_SIV) {
            if (out == NULL) {
                err = alcp_cipher_set_aad(&(cctx->handle), in, inl);
            } else {
                // IV must be copied to cctx->tagbuff when application calls EVP_CIPHER_CTX_ctrl call 
                // with EVP_CTRL_AEAD_SET_TAG. This is done in ALCP_prov_cipher_set_ctx_params call.
                err = alcp_cipher_decrypt(
                    &(cctx->handle),
                    in,
                    out,
                    inl,
                    cctx->tagbuff);
            }
         }else {
            err = alcp_cipher_decrypt(&(cctx->handle),
                                      in,
                                      out,
                                      inl,
                                      cctx->pc_cipher_info.ci_algo_info.ai_iv);
        }
    }

out:
    if (alcp_is_error(err)) {
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%ld,%p\n", (void*)in, inl, (void*)out);
        printf("%d\n",
               cctx->pc_cipher_info.ci_algo_info.ai_mode == ALC_AES_MODE_CFB);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_algo_info.ai_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    *outl = inl;
    return 1;
}

int
ALCP_prov_cipher_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    ENTER();
    // alc_prov_cipher_ctx_p cctx = vctx;

    // TODO: Introduce Finish here for finalising the context and
    // handle the corresponding memory issues.
    // alcp_cipher_finish(&cctx->handle);
    // Nothing to do!
    *outl = 0;
    return 1;
}

static const char    CIPHER_DEF_PROP[]  = "provider=alcp,fips=no";
const OSSL_ALGORITHM ALC_prov_ciphers[] = {
    // CFB
    { ALCP_PROV_NAMES_AES_256_CFB, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB1, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB1, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB1, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB8, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB8, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB8, CIPHER_DEF_PROP, cfb_functions_128 },
    // CBC
    { ALCP_PROV_NAMES_AES_256_CBC, CIPHER_DEF_PROP, cbc_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CBC, CIPHER_DEF_PROP, cbc_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CBC, CIPHER_DEF_PROP, cbc_functions_128 },
    // OFB
    { ALCP_PROV_NAMES_AES_256_OFB, CIPHER_DEF_PROP, ofb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_OFB, CIPHER_DEF_PROP, ofb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_OFB, CIPHER_DEF_PROP, ofb_functions_128 },
    // CTR
    { ALCP_PROV_NAMES_AES_256_CTR, CIPHER_DEF_PROP, ctr_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CTR, CIPHER_DEF_PROP, ctr_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CTR, CIPHER_DEF_PROP, ctr_functions_128 },
    // ECB
    { ALCP_PROV_NAMES_AES_256_ECB, CIPHER_DEF_PROP, ecb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_ECB, CIPHER_DEF_PROP, ecb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_ECB, CIPHER_DEF_PROP, ecb_functions_128 },
    // XTS
    { ALCP_PROV_NAMES_AES_256_XTS, CIPHER_DEF_PROP, xts_functions_256 },
    { ALCP_PROV_NAMES_AES_128_XTS, CIPHER_DEF_PROP, xts_functions_128 },
    // GCM
    { ALCP_PROV_NAMES_AES_128_GCM, CIPHER_DEF_PROP, gcm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_GCM, CIPHER_DEF_PROP, gcm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_GCM, CIPHER_DEF_PROP, gcm_functions_256 },
    // CCM
    { ALCP_PROV_NAMES_AES_128_CCM, CIPHER_DEF_PROP, ccm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_CCM, CIPHER_DEF_PROP, ccm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_CCM, CIPHER_DEF_PROP, ccm_functions_256 },
    // SIV
    { ALCP_PROV_NAMES_AES_128_SIV, CIPHER_DEF_PROP, siv_functions_128 },
    { ALCP_PROV_NAMES_AES_192_SIV, CIPHER_DEF_PROP, siv_functions_192 },
    { ALCP_PROV_NAMES_AES_256_SIV, CIPHER_DEF_PROP, siv_functions_256 },
    // Terminate OpenSSL Algorithm list with Null Pointer.
    { NULL, NULL, NULL },
};

// FIXME: Refactor, offload some functionality to this function
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
    return tmp;
}
