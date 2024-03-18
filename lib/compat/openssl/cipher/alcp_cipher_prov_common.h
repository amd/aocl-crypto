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

#pragma once

#define AES_BLOCK_SIZE 16

#define MAXCHUNK    ((size_t)1 << 30)
#define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

#define GENERIC_BLOCK_SIZE 16

#define PROV_CIPHER_FUNC(type, name, args) typedef type(*OSSL_##name##_fn) args

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD            0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV       0x0002
#define PROV_CIPHER_FLAG_CTS             0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK 0x0008
#define PROV_CIPHER_FLAG_RAND_KEY        0x0010

int
ALCP_prov_cipher_generic_get_params(OSSL_PARAM   params[],
                                    unsigned int md,
                                    uint64_t     flags,
                                    size_t       kbits,
                                    size_t       blkbits,
                                    size_t       ivbits);

OSSL_FUNC_cipher_get_ctx_params_fn  ALCP_prov_cipher_generic_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn  ALCP_prov_cipher_generic_set_ctx_params;
OSSL_FUNC_cipher_gettable_params_fn ALCP_prov_cipher_generic_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn
    ALCP_prov_cipher_generic_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn
                                   ALCP_prov_cipher_generic_settable_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn ALCP_prov_cipher_var_keylen_set_ctx_params;
// OSSL_FUNC_cipher_settable_ctx_params_fn
//  ALCP_prov_cipher_var_keylen_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn
    ALCP_prov_cipher_aead_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn
    ALCP_prov_cipher_aead_settable_ctx_params;

// this macro needs to be removed.
#define OSSL_PARAM_END                                                         \
    {                                                                          \
        NULL, 0, NULL, 0, 0                                                    \
    }

// clang-format off

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_gettable_ctx_params[] = {                 \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),                         \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),                              \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),                    \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_gettable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_gettable_ctx_params;                                   \
}

#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_settable_ctx_params[] = {                 \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_settable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_settable_ctx_params;                                   \
}

// clang-format on