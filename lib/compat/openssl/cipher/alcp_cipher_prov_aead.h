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

#include "alcp_cipher_prov_common.h"

#define IV_STATE_UNINITIALISED 0 /* initial state is not initialized */
#define IV_STATE_BUFFERED      1 /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2 /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3 /* the iv has been used - so don't reuse it */

#define UNINITIALISED_SIZET ((size_t)-1)

#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

#define IMPLEMENT_aead_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)  \
    static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;   \
    static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])          \
    {                                                                          \
        return ALCP_prov_cipher_generic_get_params(                            \
            params, EVP_CIPH_##UCMODE##_MODE, flags, kbits, blkbits, ivbits);  \
    }                                                                          \
    static OSSL_FUNC_cipher_newctx_fn alg##kbits##lc##_newctx;                 \
    static void*                      alg##kbits##lc##_newctx(void* provctx)   \
    {                                                                          \
        return ALCP_prov_alg##_##lc##_newctx(provctx, kbits);                  \
    }                                                                          \
    static void* alg##kbits##lc##_dupctx(void* src)                            \
    {                                                                          \
        return ALCP_prov_alg##_##lc##_dupctx(src);                             \
    }                                                                          \
    const OSSL_DISPATCH ALCP_prov_##alg##kbits##lc##_functions[] = {           \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },  \
        { OSSL_FUNC_CIPHER_FREECTX,                                            \
          (void (*)(void))ALCP_prov_alg##_##lc##_freectx },                    \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))alg##kbits##lc##_dupctx },  \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_##lc##_einit },                            \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                       \
          (void (*)(void))ALCP_prov_##lc##_dinit },                            \
        { OSSL_FUNC_CIPHER_UPDATE,                                             \
          (void (*)(void))ALCP_prov_##lc##_stream_update },                    \
        { OSSL_FUNC_CIPHER_FINAL,                                              \
          (void (*)(void))ALCP_prov_##lc##_stream_final },                     \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ALCP_prov_##lc##_cipher },  \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
          (void (*)(void))alg##_##kbits##_##lc##_get_params },                 \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_##lc##_get_ctx_params },                   \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
          (void (*)(void))ALCP_prov_##lc##_set_ctx_params },                   \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
          (void (*)(void))ALCP_prov_cipher_generic_gettable_params },          \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_aead_gettable_ctx_params },         \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
          (void (*)(void))ALCP_prov_cipher_aead_settable_ctx_params },         \
        { 0, NULL }                                                            \
    }
