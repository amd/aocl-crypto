/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 notice,
 *    this list of conditions and the following disclaimer in the
 documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS"
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

#include "alcp_mac_prov.h"
#include "provider/alcp_names.h"
#include <string.h>

void
ALCP_prov_mac_freectx(void* vctx)
{
    ENTER();
    alc_prov_mac_ctx_p mctx = vctx;
    alc_error_t        err  = alcp_mac_finish(&(mctx->handle));
    if (alcp_is_error(err)) {
        printf("MAC Provider: Error in MAC Finish\n");
    }
    OPENSSL_free(mctx->handle.ch_context);
    mctx->handle.ch_context = NULL;
    EVP_MAC_CTX_free(mctx->pc_evp_mac_ctx);
    OPENSSL_free(vctx);
    vctx = NULL;
    EXIT();
}

void*
ALCP_prov_mac_newctx(void* vprovctx, const alc_mac_info_p macinfo)
{
    ENTER();

    alc_prov_mac_ctx_p mac_ctx;
    alc_prov_ctx_p     pctx = (alc_prov_ctx_p)vprovctx;
    mac_ctx                 = OPENSSL_zalloc(sizeof(*mac_ctx));

    if (mac_ctx != NULL) {
        mac_ctx->pc_prov_ctx = pctx;
        mac_ctx->pc_libctx   = pctx->ap_libctx;
        mac_ctx->pc_mac_info = *macinfo;
    }

    EXIT();
    return mac_ctx;
}

void*
ALCP_prov_mac_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implementation pending for context copy
    alc_prov_mac_ctx_p csrc = vctx;

    EXIT();
    return csrc;
}

/*-
 * Generic mac functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM mac_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_DIGEST, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_CIPHER, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_mac_gettable_params(void* provctx)
{
    ENTER();

    EXIT();
    return mac_known_gettable_params;
}

int
ALCP_prov_mac_get_params(OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

const OSSL_PARAM*
ALCP_prov_mac_gettable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return 0;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_mac_settable_ctx_params(void* cctx, void* provctx)
{
    ENTER();
    EXIT();
    return 0;
}

int
ALCP_prov_mac_set_params(const OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

int
ALCP_prov_mac_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ENTER();
    EXIT();
    return 0;
}

int
HMAC_init(char* digest, alc_mac_info_p macinfo)
{
    ENTER();
    if (digest == NULL) {
        return 0;
    }
    // FIXME: Key does not need to be in bytes
    macinfo->mi_keyinfo.len /= 8;

    alc_digest_info_t digestinfo;
    alc_digest_type_t digest_type;
    alc_digest_len_t  digest_len;
    alc_digest_mode_t digest_mode;

    if (!strcasecmp(digest, "sha256")) {
        digest_type         = ALC_DIGEST_TYPE_SHA2;
        digest_len          = ALC_DIGEST_LEN_256;
        digest_mode.dm_sha2 = ALC_SHA2_256;
    } else if (!strcasecmp(digest, "sha224")) {
        digest_type         = ALC_DIGEST_TYPE_SHA2;
        digest_len          = ALC_DIGEST_LEN_224;
        digest_mode.dm_sha2 = ALC_SHA2_224;
    } else if (!strcasecmp(digest, "sha384")) {
        digest_type         = ALC_DIGEST_TYPE_SHA2;
        digest_len          = ALC_DIGEST_LEN_384;
        digest_mode.dm_sha2 = ALC_SHA2_384;
    } else if (!strcasecmp(digest, "sha512")) {
        digest_type         = ALC_DIGEST_TYPE_SHA2;
        digest_len          = ALC_DIGEST_LEN_512;
        digest_mode.dm_sha2 = ALC_SHA2_512;
    } else if (!strcasecmp(digest, "sha3-224")) {
        digest_type         = ALC_DIGEST_TYPE_SHA3;
        digest_len          = ALC_DIGEST_LEN_224;
        digest_mode.dm_sha3 = ALC_SHA3_224;
    } else if (!strcasecmp(digest, "sha3-256")) {
        digest_type         = ALC_DIGEST_TYPE_SHA3;
        digest_len          = ALC_DIGEST_LEN_256;
        digest_mode.dm_sha3 = ALC_SHA3_256;
    } else if (!strcasecmp(digest, "sha3-384")) {
        digest_type         = ALC_DIGEST_TYPE_SHA3;
        digest_len          = ALC_DIGEST_LEN_384;
        digest_mode.dm_sha3 = ALC_SHA3_384;
    } else if (!strcasecmp(digest, "sha3-512")) {
        digest_type         = ALC_DIGEST_TYPE_SHA3;
        digest_len          = ALC_DIGEST_LEN_512;
        digest_mode.dm_sha3 = ALC_SHA3_512;
    } else {
        printf("HMAC Provider: Digest '%s' Not Supported", digest);
        EXIT();
        return 0;
    }
    digestinfo.dt_type                    = digest_type;
    digestinfo.dt_len                     = digest_len;
    digestinfo.dt_mode                    = digest_mode;
    macinfo->mi_algoinfo.hmac.hmac_digest = digestinfo;
    EXIT();
    return 1;
}

int
ALCP_prov_mac_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ENTER();
    int               ret = 0;
    const OSSL_PARAM* p_digest =
        OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
    if (p_digest != NULL) {
        char* digest = p_digest->data;
        ret = HMAC_init(digest, &(((alc_prov_mac_ctx_p)vctx)->pc_mac_info));
        return ret;
    }
    const OSSL_PARAM* p_cipher =
        OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p_cipher != NULL) {
        char* cipher = p_cipher->data;
        if (!strcasecmp(cipher, "aes128") || !strcasecmp(cipher, "aes192")
            || !strcasecmp(cipher, "aes256")
            || !strcasecmp(cipher, "aes-128-cbc")
            || !strcasecmp(cipher, "aes-192-cbc")
            || !strcasecmp(cipher, "aes-256-cbc")) {
            return 1;
        } else {
            printf("CMAC Provider: Cipher '%s' not supported\n", cipher);
        }
    }

    EXIT();
    return ret;
}
int
ALCP_prov_mac_init(void*                vctx,
                   const unsigned char* key,
                   size_t               keylen,
                   const OSSL_PARAM     params[])
{
    ENTER();

    alc_key_info_t kinfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                             .fmt  = ALC_KEY_FMT_RAW,
                             .algo = ALC_KEY_ALG_MAC,
                             .len  = keylen * 8,
                             .key  = key };
    // Handling OpenSSL Speed Initial Init Request
    if (keylen == 0 && key == NULL) {
        kinfo.key = OPENSSL_malloc(128);
        kinfo.len = 128;
    }
    alc_prov_mac_ctx_p cctx    = vctx;
    alc_error_t        err     = ALC_ERROR_NONE;
    alc_mac_info_p     macinfo = &cctx->pc_mac_info;

    macinfo->mi_keyinfo = kinfo;

    if (params != NULL) {
        const OSSL_PARAM* p =
            OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
        if (p != NULL) {
            char* digest = (char*)p->data;
            if (digest != NULL) {
                if (!HMAC_init(digest, macinfo)) {
                    return 0;
                };
            }
        }
    }
    Uint64 size             = alcp_mac_context_size(macinfo);
    cctx->handle.ch_context = OPENSSL_malloc(size);
    err                     = alcp_mac_request(&(cctx->handle), macinfo);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Request Failed\n");
        return 0;
    }
    EXIT();
    return 1;
}

int
ALCP_prov_mac_update(void* vctx, const unsigned char* in, size_t inl)
{
    ENTER();

    alc_error_t        err;
    alc_prov_mac_ctx_p cctx = vctx;
    err                     = alcp_mac_update(&(cctx->handle), in, inl);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Update Failed\n");
        EXIT();
        return 0;
    }
    EXIT();
    return 1;
}

int
ALCP_prov_mac_final(void*          vctx,
                    unsigned char* out,
                    size_t*        outl,
                    size_t         outsize)
{
    ENTER();
    alc_error_t        err  = ALC_ERROR_NONE;
    alc_prov_mac_ctx_p mctx = vctx;
    err                     = alcp_mac_finalize(&(mctx->handle), NULL, 0);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Failed to Finalize\n");
        return 0;
    }
    alc_mac_info_p macinfo = &((alc_prov_mac_ctx_p)vctx)->pc_mac_info;
    if (macinfo->mi_type == ALC_MAC_CMAC) {
        outsize = outsize / 8;
    }
    err = alcp_mac_copy(&(mctx->handle), out, (Uint64)outsize);
    if (alcp_is_error(err)) {
        printf("MAC Provider: Failed to copy Hash\n");
        return 0;
    }

    alcp_mac_reset(&(mctx->handle));

    *outl = outsize;
    EXIT();
    return 1;
}

static const char MAC_DEF_PROP[] = "provider=alcp,fips=no";

extern const OSSL_DISPATCH mac_CMAC_functions[];
extern const OSSL_DISPATCH mac_HMAC_functions[];

const OSSL_ALGORITHM ALC_prov_macs[] = {
    { ALCP_PROV_NAMES_CMAC, MAC_DEF_PROP, mac_CMAC_functions },
    { ALCP_PROV_NAMES_HMAC, MAC_DEF_PROP, mac_HMAC_functions },
    { NULL, NULL, NULL },
};
