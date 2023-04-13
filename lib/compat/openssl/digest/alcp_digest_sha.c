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

#include "digest/alcp_digest_sha.h"

// SHA2
DEFINE_SHA2_CONTEXT(sha2, sha512_256, ALC_DIGEST_LEN_256, ALC_SHA2_512);
DEFINE_SHA2_CONTEXT(sha2, sha512_224, ALC_DIGEST_LEN_224, ALC_SHA2_512);
DEFINE_SHA2_CONTEXT(sha2, sha512, ALC_DIGEST_LEN_512, ALC_SHA2_512);
DEFINE_SHA2_CONTEXT(sha2, sha384, ALC_DIGEST_LEN_384, ALC_SHA2_384);
DEFINE_SHA2_CONTEXT(sha2, sha256, ALC_DIGEST_LEN_256, ALC_SHA2_256);
DEFINE_SHA2_CONTEXT(sha2, sha224, ALC_DIGEST_LEN_224, ALC_SHA2_224);

// SHA3
DEFINE_SHA3_CONTEXT(sha3, sha512, ALC_DIGEST_LEN_512, ALC_SHA2_512);
DEFINE_SHA3_CONTEXT(sha3, sha384, ALC_DIGEST_LEN_384, ALC_SHA2_384);
DEFINE_SHA3_CONTEXT(sha3, sha256, ALC_DIGEST_LEN_256, ALC_SHA2_256);
DEFINE_SHA3_CONTEXT(sha3, sha224, ALC_DIGEST_LEN_224, ALC_SHA2_224);

// SHAKE
DEFINE_SHA3_CONTEXT(sha3, shake128, ALC_DIGEST_LEN_CUSTOM, ALC_SHAKE_128);
DEFINE_SHA3_CONTEXT(sha3, shake256, ALC_DIGEST_LEN_CUSTOM, ALC_SHAKE_256);

// SHA2 Functions
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

// SHA3 Functions
int
ALCP_prov_sha3_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    int ret = ALCP_prov_digest_get_ctx_params(vctx, params);
    EXIT();
    return ret;
}

int
ALCP_prov_sha3_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    int ret = ALCP_prov_digest_set_ctx_params(vctx, params);
    EXIT();
    return ret;
}

void
ALCP_prov_sha3_ctxfree(alc_prov_digest_ctx_p dig_ctx)
{
    ENTER();
    ALCP_prov_digest_freectx(dig_ctx);
    EXIT();
}

/* Sha2 dispatchers */
CREATE_DIGEST_DISPATCHERS(sha512_256, sha2, ALC_DIGEST_LEN_256);
CREATE_DIGEST_DISPATCHERS(sha512_224, sha2, ALC_DIGEST_LEN_224);
CREATE_DIGEST_DISPATCHERS(sha512, sha2, ALC_DIGEST_LEN_512);
CREATE_DIGEST_DISPATCHERS(sha384, sha2, ALC_DIGEST_LEN_384);
CREATE_DIGEST_DISPATCHERS(sha256, sha2, ALC_DIGEST_LEN_256);
CREATE_DIGEST_DISPATCHERS(sha224, sha2, ALC_DIGEST_LEN_224);

/* Sha3 dispatchers */
CREATE_DIGEST_DISPATCHERS(sha512, sha3, ALC_DIGEST_LEN_512);
CREATE_DIGEST_DISPATCHERS(sha384, sha3, ALC_DIGEST_LEN_384);
CREATE_DIGEST_DISPATCHERS(sha256, sha3, ALC_DIGEST_LEN_256);
CREATE_DIGEST_DISPATCHERS(sha224, sha3, ALC_DIGEST_LEN_224);

/* Shake dispatchers */
CREATE_DIGEST_DISPATCHERS(shake128, sha3, ALC_DIGEST_LEN_CUSTOM);
CREATE_DIGEST_DISPATCHERS(shake256, sha3, ALC_DIGEST_LEN_CUSTOM);
