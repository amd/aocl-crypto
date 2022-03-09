/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp_digest_sha2.h"

SHA2_CONTEXT(sha512, ALC_DIGEST_LEN_512, ALC_SHA2_512);
SHA2_CONTEXT(sha384, ALC_DIGEST_LEN_384, ALC_SHA2_384);
SHA2_CONTEXT(sha256, ALC_DIGEST_LEN_256, ALC_SHA2_256);
SHA2_CONTEXT(sha224, ALC_DIGEST_LEN_224, ALC_SHA2_224);

int
ALCP_prov_sha2_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    EXIT();
    return ALCP_prov_digest_get_ctx_params(vctx, params);
}

int
ALCP_prov_sha2_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    EXIT();
    return ALCP_prov_digest_set_ctx_params(vctx, params);
}

void
ALCP_prov_sha2_ctxfree(alc_prov_digest_ctx_p dig_ctx)
{
    EXIT();
    ALCP_prov_digest_freectx(dig_ctx);
}

/* Sha2 dispatchers */
CREATE_DIGEST_DISPATCHERS(sha512, sha2, 0);
CREATE_DIGEST_DISPATCHERS(sha384, sha2, 0);
CREATE_DIGEST_DISPATCHERS(sha256, sha2, 0);
CREATE_DIGEST_DISPATCHERS(sha224, sha2, 0);
