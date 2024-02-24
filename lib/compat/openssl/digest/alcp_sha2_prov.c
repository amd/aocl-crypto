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

#include "digest/alcp_digest_prov.h"

// sha2 Functions
int
alcp_prov_sha2_init(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    alc_prov_digest_ctx_p cctx = vctx;
    alc_error_t           err;

    alc_digest_info_p dinfo = &cctx->pc_digest_info;
    err                     = alcp_digest_request(dinfo, &(cctx->handle));
    if (alcp_is_error(err)) {
        printf("Provider: Somehow request failed\n");
        return 0;
    }
    EXIT();
    return 1;
}

#define ALCP_CREATE_SHA2_FUNCTIONS(                                            \
    name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)               \
    CREATE_DIGEST_DISPATCHERS(                                                 \
        name, grp, len, blockSize, alcp_mode, grp_upper_case, flags)           \
    const OSSL_DISPATCH name##_##grp##_functions[] = {                         \
        { OSSL_FUNC_DIGEST_GET_PARAMS,                                         \
          (fptr_t)alcp_prov_digest_##name##_##grp##_get_params },              \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                    \
          (fptr_t)alcp_prov_digest_gettable_params },                          \
        { OSSL_FUNC_DIGEST_NEWCTX,                                             \
          (fptr_t)alcp_prov_##name##_##grp##_newctx },                         \
        { OSSL_FUNC_DIGEST_DUPCTX, (fptr_t)alcp_prov_digest_dupctx },          \
        { OSSL_FUNC_DIGEST_FREECTX, (fptr_t)alcp_prov_digest_freectx },        \
        { OSSL_FUNC_DIGEST_INIT, (fptr_t)alcp_prov_sha2_init },                \
        { OSSL_FUNC_DIGEST_UPDATE, (fptr_t)alcp_prov_digest_update },          \
        { OSSL_FUNC_DIGEST_FINAL, (fptr_t)alcp_prov_digest_final },            \
        { 0, NULL }                                                            \
    }

ALCP_CREATE_SHA2_FUNCTIONS(sha512_256,
                           sha2,
                           ALC_DIGEST_LEN_256,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_512,
                           ALC_SHA2_512,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA2_FUNCTIONS(sha512_224,
                           sha2,
                           ALC_DIGEST_LEN_224,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_512,
                           ALC_SHA2_512,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA2_FUNCTIONS(sha512,
                           sha2,
                           ALC_DIGEST_LEN_512,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_512,
                           ALC_SHA2_512,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA2_FUNCTIONS(sha384,
                           sha2,
                           ALC_DIGEST_LEN_384,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_512,
                           ALC_SHA2_384,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA2_FUNCTIONS(sha256,
                           sha2,
                           ALC_DIGEST_LEN_256,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_256,
                           ALC_SHA2_256,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);

ALCP_CREATE_SHA2_FUNCTIONS(sha224,
                           sha2,
                           ALC_DIGEST_LEN_224,
                           ALC_DIGEST_BLOCK_SIZE_SHA2_256,
                           ALC_SHA2_224,
                           SHA2,
                           ALCP_FLAG_ALGID_ABSENT);
