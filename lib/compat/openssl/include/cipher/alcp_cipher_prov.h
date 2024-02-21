/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#ifndef _OPENSSL_ALCP_CIPHER_PROV_H
#define _OPENSSL_ALCP_CIPHER_PROV_H 2

/* OpenSSL Headers */
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

/* ALCP Headers */
#include <alcp/cipher.h>
#include <alcp/key.h>

/* Provider Internal Headers */
#include "debug.h"
#include "provider/alcp_provider.h"

struct _alc_prov_cipher_ctx
{
    /* Must be first */
    alc_prov_ctx_t*     pc_prov_ctx;
    alc_cipher_handle_t handle;
    alc_key_info_t      kinfo_tweak_key;

    // For storing CTR Key for AES-SIV
    alc_key_info_t kinfo_siv_ctr_key;
    int            enc_flag;

    Uint64       ivlen;
    int          taglen;
    Uint8*       tagbuff;
    const Uint8* aad;
    int          aadlen;
    bool         add_inititalized;

    bool  finalized;
    Uint8 key[2 * 48]; //  Maximum Key Size is 256 bits. Allocating double since
                       //  XTS key contains both encryption and tweak key
    const Uint8* iv;
    Uint64       keylen;
    bool         is_aead;

    alc_cipher_info_t      pc_cipher_info;
    alc_cipher_aead_info_t pc_cipher_aead_info;

    int pc_flags;

    OSSL_LIB_CTX* pc_libctx;
};
typedef struct _alc_prov_cipher_ctx alc_prov_cipher_ctx_t,
    *alc_prov_cipher_ctx_p;

EVP_CIPHER*
ALCP_prov_init_cipher(alc_prov_cipher_ctx_p c);

extern const OSSL_ALGORITHM ALC_prov_ciphers[];

/* TODO: ugly hack for openssl table */
typedef void (*fptr_t)(void);

void*
ALCP_prov_cipher_newctx(void* vprovctx, const void* cinfo, bool is_aead);
void
ALCP_prov_cipher_freectx(void* vctx);

int
ALCP_prov_cipher_get_ctx_params(void* vctx, OSSL_PARAM params[]);
int
ALCP_prov_cipher_set_ctx_params(void* vctx, const OSSL_PARAM params[]);
const OSSL_PARAM*
ALCP_prov_cipher_gettable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_cipher_settable_ctx_params(void* cctx, void* provctx);
const OSSL_PARAM*
ALCP_prov_cipher_gettable_params(void* provctx);
int
ALCP_prov_cipher_get_params(OSSL_PARAM params[],
                            int        mode,
                            int        key_size,
                            bool       is_aead);
int
ALCP_prov_cipher_set_params(const OSSL_PARAM params[]);

OSSL_FUNC_cipher_dupctx_fn         ALCP_prov_cipher_dupctx;
OSSL_FUNC_cipher_freectx_fn        ALCP_prov_cipher_freectx;
OSSL_FUNC_cipher_get_ctx_params_fn ALCP_prov_cipher_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ALCP_prov_cipher_set_ctx_params;
OSSL_FUNC_cipher_encrypt_init_fn   ALCP_prov_cipher_cfb_encrypt_init,
    ALCP_prov_cipher_cbc_encrypt_init, ALCP_prov_cipher_ofb_encrypt_init,
    ALCP_prov_cipher_ctr_encrypt_init, ALCP_prov_cipher_xts_encrypt_init,
    ALCP_prov_cipher_gcm_encrypt_init, ALCP_prov_cipher_ccm_encrypt_init,
    ALCP_prov_cipher_siv_encrypt_init;
OSSL_FUNC_cipher_decrypt_init_fn ALCP_prov_cipher_cfb_decrypt_init,
    ALCP_prov_cipher_cbc_decrypt_init, ALCP_prov_cipher_ofb_decrypt_init,
    ALCP_prov_cipher_ctr_decrypt_init, ALCP_prov_cipher_xts_decrypt_init,
    ALCP_prov_cipher_gcm_decrypt_init, ALCP_prov_cipher_ccm_decrypt_init,
    ALCP_prov_cipher_siv_decrypt_init;
OSSL_FUNC_cipher_update_fn ALCP_prov_cipher_cfb_update,
    ALCP_prov_cipher_cbc_update, ALCP_prov_cipher_ofb_update,
    ALCP_prov_cipher_ctr_update, ALCP_prov_cipher_xts_update,
    ALCP_prov_cipher_gcm_update, ALCP_prov_cipher_ccm_update,
    ALCP_prov_cipher_siv_update;
OSSL_FUNC_cipher_final_fn ALCP_prov_cipher_final;

// Macro for Context Creation
#define CIPHER_CONTEXT(mode, alcp_mode)                                        \
    static alc_cipher_info_t s_cipher_##mode##_info = {                        \
        .ci_type = ALC_CIPHER_TYPE_AES,                                        \
        .ci_key_info = {                                                       \
            ALC_KEY_TYPE_SYMMETRIC,                                            \
            ALC_KEY_FMT_RAW,                                                   \
            ALC_KEY_ALG_SYMMETRIC,                                             \
            ALC_KEY_LEN_128,                                                   \
            128,                                                               \
        },                                                                     \
        .ci_algo_info = {                                       \
                .ai_mode =      alcp_mode,                                     \
            },                                                             \
    }

// Macro for Context Creation
#define CIPHER_AEAD_CONTEXT(mode, alcp_mode)                                   \
    static alc_cipher_aead_info_t s_cipher_##mode##_info = {                    \
        .ci_type = ALC_CIPHER_TYPE_AES,                                        \
        .ci_key_info = {                                                       \
            ALC_KEY_TYPE_SYMMETRIC,                                            \
            ALC_KEY_FMT_RAW,                                                   \
            ALC_KEY_ALG_SYMMETRIC,                                             \
            ALC_KEY_LEN_128,                                                   \
            128,                                                               \
        },                                                                     \
        .ci_algo_info = {                                       \
                .ai_mode =      alcp_mode,                                     \
            },                                                             \
    }

// Macro for OpenSSL Dispatcher Creation
#define CREATE_CIPHER_DISPATCHERS(name, grp, mode, key_size, is_aead)          \
    static OSSL_FUNC_cipher_get_params_fn                                      \
               ALCP_prov_##name##_get_params_##key_size;                       \
    static int ALCP_prov_##name##_get_params_##key_size(OSSL_PARAM* params)    \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_cipher_get_params(params, mode, key_size, is_aead);   \
    }                                                                          \
                                                                               \
    static OSSL_FUNC_cipher_newctx_fn ALCP_prov_##name##_newctx_##key_size;    \
    static void* ALCP_prov_##name##_newctx_##key_size(void* provctx)           \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_aes_newctx(                                           \
            provctx, &s_cipher_##name##_info, is_aead);                        \
    }                                                                          \
    static OSSL_FUNC_cipher_decrypt_init_fn                                    \
               ALCP_prov_##name##_decrypt_init_##key_size;                     \
    static int ALCP_prov_##name##_decrypt_init_##key_size(                     \
        void*                vctx,                                             \
        const unsigned char* key,                                              \
        size_t               keylen,                                           \
        const unsigned char* iv,                                               \
        size_t               ivlen,                                            \
        const OSSL_PARAM     params[])                                         \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_cipher_##name##_decrypt_init(                         \
            vctx, key, key_size, iv, ivlen, params);                           \
    }                                                                          \
    static int ALCP_prov_##name##_encrypt_init_##key_size(                     \
        void*                vctx,                                             \
        const unsigned char* key,                                              \
        size_t               keylen,                                           \
        const unsigned char* iv,                                               \
        size_t               ivlen,                                            \
        const OSSL_PARAM     params[])                                         \
    {                                                                          \
        ENTER();                                                               \
        return ALCP_prov_cipher_##name##_encrypt_init(                         \
            vctx, key, key_size, iv, ivlen, params);                           \
    }                                                                          \
    const OSSL_DISPATCH name##_functions_##key_size[] = {                      \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
          (fptr_t)ALCP_prov_##name##_get_params_##key_size },                  \
        { OSSL_FUNC_CIPHER_NEWCTX,                                             \
          (fptr_t)ALCP_prov_##name##_newctx_##key_size },                      \
        { OSSL_FUNC_CIPHER_DUPCTX, (fptr_t)ALCP_prov_cipher_dupctx },          \
        { OSSL_FUNC_CIPHER_FREECTX, (fptr_t)ALCP_prov_cipher_freectx },        \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
          (fptr_t)ALCP_prov_cipher_gettable_params },                          \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
          (fptr_t)ALCP_prov_cipher_gettable_params },                          \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
          (fptr_t)ALCP_prov_##grp##_get_ctx_params },                          \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
          (fptr_t)ALCP_prov_cipher_settable_ctx_params },                      \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
          (fptr_t)ALCP_prov_##grp##_set_ctx_params },                          \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                       \
          (fptr_t)ALCP_prov_##name##_encrypt_init_##key_size },                \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                       \
          (fptr_t)ALCP_prov_##name##_decrypt_init_##key_size },                \
        { OSSL_FUNC_CIPHER_UPDATE, (fptr_t)ALCP_prov_cipher_##name##_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (fptr_t)ALCP_prov_cipher_final },            \
    }

/*
 * Dispatchers are created by alcp_cipher_aes.c using macro defined above
 */
extern const OSSL_DISPATCH cfb_functions_128[];
extern const OSSL_DISPATCH cfb_functions_192[];
extern const OSSL_DISPATCH cfb_functions_256[];
extern const OSSL_DISPATCH cbc_functions_128[];
extern const OSSL_DISPATCH cbc_functions_192[];
extern const OSSL_DISPATCH cbc_functions_256[];
extern const OSSL_DISPATCH ofb_functions_128[];
extern const OSSL_DISPATCH ofb_functions_192[];
extern const OSSL_DISPATCH ofb_functions_256[];
extern const OSSL_DISPATCH ctr_functions_128[];
extern const OSSL_DISPATCH ctr_functions_192[];
extern const OSSL_DISPATCH ctr_functions_256[];
extern const OSSL_DISPATCH ecb_functions_128[];
extern const OSSL_DISPATCH ecb_functions_192[];
extern const OSSL_DISPATCH ecb_functions_256[];
extern const OSSL_DISPATCH xts_functions_128[];
extern const OSSL_DISPATCH xts_functions_256[];
extern const OSSL_DISPATCH gcm_functions_128[];
extern const OSSL_DISPATCH gcm_functions_192[];
extern const OSSL_DISPATCH gcm_functions_256[];
extern const OSSL_DISPATCH ccm_functions_128[];
extern const OSSL_DISPATCH ccm_functions_192[];
extern const OSSL_DISPATCH ccm_functions_256[];
extern const OSSL_DISPATCH siv_functions_128[];
extern const OSSL_DISPATCH siv_functions_192[];
extern const OSSL_DISPATCH siv_functions_256[];

#endif /* _OPENSSL_ALCP_prov_CIPHER_PROV_H */
