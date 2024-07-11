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
#include <openssl/obj_mac.h>
#include <strings.h>

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

int
alcp_rsa_get_digest_info_index(alc_digest_mode_t mode)
{
    int index = 0;
    switch (mode) {
        case ALC_MD5:
            index = MD_5;
            break;
        case ALC_SHA1:
            index = SHA_1;
            break;
        case ALC_MD5_SHA1:
            index = MD_5_SHA_1;
            break;
        case ALC_SHA2_224:
            index = SHA_224;
            break;
        case ALC_SHA2_256:
            index = SHA_256;
            break;
        case ALC_SHA2_384:
            index = SHA_384;
            break;
        case ALC_SHA2_512:
            index = SHA_512;
            break;
        case ALC_SHA2_512_224:
            index = SHA_512_224;
            break;
        case ALC_SHA2_512_256:
            index = SHA_512_256;
            break;
        default:
            printf("Error: Unsupported mode %d\n", mode);
            index = -1;
    }
    return index;
}

int
alcp_rsa_get_digest_info_size(alc_digest_mode_t mode)
{
    int size = 0;
    switch (mode) {
        case ALC_MD5:
            size = 18;
            break;
        case ALC_SHA1:
            size = 15;
            break;
        case ALC_MD5_SHA1:
            size = 0;
            break;
        case ALC_SHA2_224:
        case ALC_SHA2_256:
        case ALC_SHA2_384:
        case ALC_SHA2_512:
        case ALC_SHA2_512_224:
        case ALC_SHA2_512_256:
            size = 19;
            break;
        default:
            printf("Error: Unsupported mode\n");
            size = 0;
    }
    return size;
}

void
alcp_rsa_free(Rsa* r)
{
    if (r == NULL)
        return;

    // ToDO : need to check if we need this support
    // CRYPTO_DOWN_REF(&r->references, &i, r->lock);

    // if (i > 0)
    //     return;
    // if(i < 0)
    // {
    //     printf("reference count issue");
    //     return;
    // }

    if (r->meth != NULL) {
        BN_MONT_CTX_free(r->_method_mod_n);
        BN_MONT_CTX_free(r->_method_mod_p);
        BN_MONT_CTX_free(r->_method_mod_q);
    }

    // CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

    // CRYPTO_THREAD_lock_free(r->lock);

    BN_free((BIGNUM*)r->n);
    BN_free((BIGNUM*)r->e);
    BN_clear_free((BIGNUM*)r->d);
    BN_clear_free((BIGNUM*)r->p);
    BN_clear_free((BIGNUM*)r->q);
    BN_clear_free((BIGNUM*)r->dmp1);
    BN_clear_free((BIGNUM*)r->dmq1);
    BN_clear_free((BIGNUM*)r->iqmp);

    RSA_PSS_PARAMS_free(r->pss);
    // sk_RSA_PRIME_INFO_pop_free(r->prime_infos, qat_rsa_multip_info_free);

    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r);
}
