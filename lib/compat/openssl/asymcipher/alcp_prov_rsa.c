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
#include <openssl/obj_mac.h>

int
alcp_rsa_size(const Rsa* r)
{
    return BN_num_bytes((BIGNUM*)(r->n));
}

int
alcp_rsa_get_digest_mode(const char* str)
{
    ENTER();
    alc_digest_mode_t digest_mode;
    if (str == NULL) {
        EXIT();
        printf("Error : Digest string is null.Using the default Sha1 mode");
        digest_mode = ALC_SHA1;
        return digest_mode;
    }

    if (!strcasecmp(str, "md5")) {
        digest_mode = ALC_MD5;
    } else if (!strcasecmp(str, "sha1")) {
        digest_mode = ALC_SHA1;
    } else if (!strcasecmp(str, "md5-sha1")) {
        digest_mode = ALC_MD5_SHA1;
    } else if (!strcasecmp(str, "sha256") || !strcasecmp(str, "SHA2-256")) {
        digest_mode = ALC_SHA2_256;
    } else if (!strcasecmp(str, "sha224") || !strcasecmp(str, "SHA2-224")) {
        digest_mode = ALC_SHA2_224;
    } else if (!strcasecmp(str, "sha384") || !strcasecmp(str, "SHA2-384")) {
        digest_mode = ALC_SHA2_384;
    } else if (!strcasecmp(str, "sha512") || !strcasecmp(str, "SHA2-512")) {
        digest_mode = ALC_SHA2_512;
    } else if (!strcasecmp(str, "sha512-224")
               || !strcasecmp(str, "SHA2-512/224")) {
        digest_mode = ALC_SHA2_512_224;
    } else if (!strcasecmp(str, "sha512-256")
               || !strcasecmp(str, "SHA2-512/256")) {
        digest_mode = ALC_SHA2_512_256;
    } else if (!strcasecmp(str, "sha3-224")) {
        digest_mode = ALC_SHA3_224;
    } else if (!strcasecmp(str, "sha3-256")) {
        digest_mode = ALC_SHA3_256;
    } else if (!strcasecmp(str, "sha3-384")) {
        digest_mode = ALC_SHA3_384;
    } else if (!strcasecmp(str, "sha3-512")) {
        digest_mode = ALC_SHA3_512;
    } else {
        digest_mode = -1;
        printf("RSA Provider: Digest '%s' not Supported\n", str);
    }
    EXIT();
    return digest_mode;
}

int
alcp_rsa_get_digest_size(alc_digest_mode_t mode)
{
    Uint64 len = 0;
    switch (mode) {
        case ALC_MD5:
            len = ALC_DIGEST_LEN_128;
            break;
        case ALC_SHA1:
            len = ALC_DIGEST_LEN_160;
            break;
        case ALC_MD5_SHA1:
            len = ALC_DIGEST_LEN_288;
            break;
        case ALC_SHAKE_128:
            len = ALC_DIGEST_LEN_128;
            break;
        case ALC_SHA2_224:
        case ALC_SHA3_224:
        case ALC_SHA2_512_224:
            len = ALC_DIGEST_LEN_224;
            break;
        case ALC_SHA2_256:
        case ALC_SHA3_256:
        case ALC_SHA2_512_256:
        case ALC_SHAKE_256:
            len = ALC_DIGEST_LEN_256;
            break;
        case ALC_SHA2_384:
        case ALC_SHA3_384:
            len = ALC_DIGEST_LEN_384;
            break;
        case ALC_SHA2_512:
        case ALC_SHA3_512:
            len = ALC_DIGEST_LEN_512;
            break;
        default:
            printf("Error: Unsupported mode\n");
    }
    return len / 8;
}
