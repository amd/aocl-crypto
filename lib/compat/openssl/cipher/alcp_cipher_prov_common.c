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
#include <assert.h>
#include <inttypes.h>

#include "cipher/alcp_cipher_prov.h"
#include "provider/alcp_names.h"

#include "alcp_cipher_prov_common.h"

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM alcp_prov_cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM*
ALCP_prov_cipher_generic_gettable_params(ossl_unused void* provctx)
{
    printf("\n generic gettable ctx params ");
    return alcp_prov_cipher_known_gettable_params;
}

int
ALCP_prov_cipher_generic_get_params(OSSL_PARAM   params[],
                                    unsigned int md,
                                    uint64_t     flags,
                                    size_t       kbits,
                                    size_t       blkbits,
                                    size_t       ivbits)
{
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(
            p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

// clang-format off

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(ALCP_prov_cipher_generic)
{ OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0, OSSL_PARAM_UNMODIFIED },
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(ALCP_prov_cipher_generic)

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(ALCP_prov_cipher_generic)
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(ALCP_prov_cipher_generic)

    // clang-format on

    /*
     * Variable key length cipher functions for OSSL_PARAM settables
     */

    int ALCP_prov_cipher_var_keylen_set_ctx_params(void*            vctx,
                                                   const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    const OSSL_PARAM*       p;
    ENTER();

    if (params == NULL)
        return 1;

    if (!ALCP_prov_cipher_generic_set_ctx_params(vctx, params))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (cipherctx->keyLen_in_bytes != keylen) {
            cipherctx->keyLen_in_bytes = keylen;
            cipherctx->isKeySet        = 0;
        }
    }
    return 1;
}

// clang-format off
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(ALCP_prov_cipher_var_keylen)
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(ALCP_prov_cipher_var_keylen)
    // clang-format on

    /*-
     * AEAD cipher functions for OSSL_PARAM gettables and settables
     */

    static const OSSL_PARAM
    alcp_prov_cipher_aead_known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
                                NULL,
                                0),
        OSSL_PARAM_END
    };

const OSSL_PARAM*
ALCP_prov_cipher_aead_gettable_ctx_params(ossl_unused void* cctx,
                                          ossl_unused void* provctx)
{
    ENTER();

    return alcp_prov_cipher_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM cipher_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM*
ALCP_prov_cipher_aead_settable_ctx_params(ossl_unused void* cctx,
                                          ossl_unused void* provctx)
{
    ENTER();
    return cipher_aead_known_settable_ctx_params;
}

OSSL_LIB_CTX*
ALCP_prov_libctx_of(ALCP_PROV_CIPHER_CTX* ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

void
ALCP_prov_cipher_generic_reset_ctx(ALCP_PROV_CIPHER_CTX* ctx)
{
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);

    if (ctx != NULL && genCipherctx->alloced) {
        OPENSSL_free(genCipherctx->tlsmac);
        genCipherctx->alloced = 0;
        genCipherctx->tlsmac  = NULL;
    }
}

static int
cipher_generic_init_internal(ALCP_PROV_CIPHER_CTX* ctx,
                             const Uint8*          key,
                             size_t                keylen,
                             const Uint8*          iv,
                             size_t                ivlen,
                             const OSSL_PARAM      params[],
                             int                   enc)
{

    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    genCipherctx->num     = 0;
    genCipherctx->bufsz   = 0;
    genCipherctx->updated = 0;
    cipherctx->enc        = enc ? 1 : 0;

    // if (!ossl_prov_is_running())
    // return 0;

    if (iv != NULL && cipherctx->mode != EVP_CIPH_ECB_MODE) {

        alc_error_t err = alcp_cipher_init(&(ctx->handle), NULL, 0, iv, ivlen);
        if (alcp_is_error(err)) {
            return 0;
        }
    }

    if (iv == NULL && cipherctx->ivState
        && (cipherctx->mode == EVP_CIPH_CBC_MODE
            || cipherctx->mode == EVP_CIPH_CFB_MODE
            || cipherctx->mode == EVP_CIPH_OFB_MODE)) {
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(cipherctx->iv_buff, genCipherctx->oiv_buff, cipherctx->ivLen);

        // setIv, this maynot be necessary since iv is buffered.
        // this can be removed after verification.
        alc_error_t err = alcp_cipher_init(
            &(ctx->handle), NULL, 0, cipherctx->iv_buff, ivlen);
        if (alcp_is_error(err)) {
            return 0;
        }
    }

    if (key != NULL) {
        if (genCipherctx->variable_keylength == 0) {
            if (keylen != cipherctx->keyLen_in_bytes) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            cipherctx->keyLen_in_bytes = keylen;
        }

        alc_error_t err = alcp_cipher_init(
            &(ctx->handle), key, cipherctx->keyLen_in_bytes * 8, NULL, 0);
        if (alcp_is_error(err)) {
            return 0;
        }

        cipherctx->isKeySet = 1;
    }
    return ALCP_prov_cipher_generic_set_ctx_params(ctx, params);
}

int
ALCP_prov_cipher_generic_einit(void*            vctx,
                               const Uint8*     key,
                               size_t           keylen,
                               const Uint8*     iv,
                               size_t           ivlen,
                               const OSSL_PARAM params[])
{
    ENTER();
    return cipher_generic_init_internal(
        vctx, key, keylen, iv, ivlen, params, 1);
}

int
ALCP_prov_cipher_generic_dinit(void*            vctx,
                               const Uint8*     key,
                               size_t           keylen,
                               const Uint8*     iv,
                               size_t           ivlen,
                               const OSSL_PARAM params[])
{
    ENTER();
    return cipher_generic_init_internal(
        vctx, key, keylen, iv, ivlen, params, 0);
}

/* Max padding including padding length byte */
#define MAX_PADDING 256

int
ALCP_prov_cipher_generic_block_update(void*        vctx,
                                      Uint8*       out,
                                      size_t*      outl,
                                      size_t       outsize,
                                      const Uint8* in,
                                      size_t       inl)
{
    size_t                      outlint      = 0;
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    alc_error_t err = ALC_ERROR_NONE;

    size_t blksz = genCipherctx->blocksize;
    size_t nextblocks;

    if (!cipherctx->isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (genCipherctx->tlsversion > 0) {
        /*
         * Each update call corresponds to a TLS record and is individually
         * padded
         */

        /* Sanity check inputs */
        if (in == NULL || in != out || outsize < inl || !cipherctx->pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (cipherctx->enc) {
            Uint8  padval;
            size_t padnum, loop;

            /* Add padding */

            padnum = blksz - (inl % blksz);

            if (outsize < inl + padnum) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }

            if (padnum > MAX_PADDING) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
            padval = (Uint8)(padnum - 1);
            if (genCipherctx->tlsversion == ACLP_SSL3_VERSION) {
                if (padnum > 1)
                    memset(out + inl, 0, padnum - 1);
                *(out + inl + padnum - 1) = padval;
            } else {
                /* we need to add 'padnum' padding bytes of value padval */
                for (loop = inl; loop < inl + padnum; loop++)
                    out[loop] = padval;
            }
            inl += padnum;
        }

        if ((inl % blksz) != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        /* Shouldn't normally fail */
        if (cipherctx->enc) {
            err = alcp_cipher_encrypt(&(ctx->handle), in, out, inl);
        } else {
            err = alcp_cipher_decrypt(&(ctx->handle), in, out, inl);
        }
        if (alcp_is_error(err)) {
            printf("Error: cipher encrypt/decrypt failed \n");
            // ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (genCipherctx->alloced) {
            OPENSSL_free(genCipherctx->tlsmac);
            genCipherctx->alloced = 0;
            genCipherctx->tlsmac  = NULL;
        }

        /* This only fails if padding is publicly invalid */
        *outl = inl;
#if 0        
        if (!cipherctx->enc
            && !ALCP_prov_cipher_tlsunpadblock(ctx->base.libctx,
                                          genCipherctx->tlsversion,
                                          out,
                                          outl,
                                          blksz,
                                          &genCipherctx->tlsmac,
                                          &genCipherctx->alloced,
                                          genCipherctx->tlsmacsize,
                                          0)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
#endif
        return 1;
    }

    if (genCipherctx->bufsz != 0)
        nextblocks = ALCP_prov_cipher_fillblock(
            cipherctx->buf, &genCipherctx->bufsz, blksz, &in, &inl);
    else
        nextblocks = inl & ~(blksz - 1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (genCipherctx->bufsz == blksz
        && (cipherctx->enc || inl > 0 || !cipherctx->pad)) {
        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }

        if (cipherctx->enc) {
            err =
                alcp_cipher_encrypt(&(ctx->handle), cipherctx->buf, out, blksz);
        } else {
            err =
                alcp_cipher_decrypt(&(ctx->handle), cipherctx->buf, out, blksz);
        }
        if (alcp_is_error(err)) {
            printf("Error: cipher encrypt/decrypt failed \n");
            return 0;
        }

        genCipherctx->bufsz = 0;
        outlint             = blksz;
        out += blksz;
    }
    if (nextblocks > 0) {
        if (!cipherctx->enc && cipherctx->pad && nextblocks == inl) {
            // if (!assert(inl >= blksz)) {
            if (inl >= blksz) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= blksz;
        }
        outlint += nextblocks;
        if (outsize < outlint) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    }
    if (nextblocks > 0) {
        if (cipherctx->enc) {
            err = alcp_cipher_encrypt(&(ctx->handle), in, out, nextblocks);
        } else {
            err = alcp_cipher_decrypt(&(ctx->handle), in, out, nextblocks);
        }
        if (alcp_is_error(err)) {
            printf("Error: cipher encrypt/decrypt failed \n");
            return 0;
        }

        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0
        && !ALCP_prov_cipher_trailingdata(
            cipherctx->buf, &genCipherctx->bufsz, blksz, &in, &inl)) {
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

int
ALCP_prov_cipher_generic_block_final(void*   vctx,
                                     Uint8*  out,
                                     size_t* outl,
                                     size_t  outsize)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);

    ENTER();
    alc_error_t err = ALC_ERROR_NONE;

    size_t blksz = genCipherctx->blocksize;

    // if (!ossl_prov_is_running())
    //  return 0;

    if (!cipherctx->isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (genCipherctx->tlsversion > 0) {
        /* We never finalize TLS, so this is an error */
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (cipherctx->enc) {
        if (cipherctx->pad) {
            ALCP_prov_cipher_padblock(
                cipherctx->buf, &genCipherctx->bufsz, blksz);
        } else if (genCipherctx->bufsz == 0) {
            *outl = 0;
            return 1;
        } else if (genCipherctx->bufsz != blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }

        if (cipherctx->enc) {
            err =
                alcp_cipher_encrypt(&(ctx->handle), cipherctx->buf, out, blksz);
        } else {
            err =
                alcp_cipher_decrypt(&(ctx->handle), cipherctx->buf, out, blksz);
        }
        if (alcp_is_error(err)) {
            printf("Error: cipher encrypt/decrypt failed \n");
            // ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        genCipherctx->bufsz = 0;
        *outl               = blksz;
        return 1;
    }

    /* Decrypting */
    if (genCipherctx->bufsz != blksz) {
        if (genCipherctx->bufsz == 0 && !cipherctx->pad) {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (cipherctx->enc) {
        // FIXME: input and output buffer are same, this might fail
        err = alcp_cipher_encrypt(
            &(ctx->handle), cipherctx->buf, cipherctx->buf, blksz);
    } else {
        err = alcp_cipher_decrypt(
            &(ctx->handle), cipherctx->buf, cipherctx->buf, blksz);
    }
    if (alcp_is_error(err)) {
        printf("Error: cipher encrypt/decrypt failed \n");
        // ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (cipherctx->pad
        && !ALCP_prov_cipher_unpadblock(
            cipherctx->buf, &genCipherctx->bufsz, blksz)) {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < genCipherctx->bufsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, cipherctx->buf, genCipherctx->bufsz);
    *outl               = genCipherctx->bufsz;
    genCipherctx->bufsz = 0;
    return 1;
}

int
ALCP_prov_cipher_generic_stream_update(void*        vctx,
                                       Uint8*       out,
                                       size_t*      outl,
                                       size_t       outsize,
                                       const Uint8* in,
                                       size_t       inl)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    alc_error_t err = ALC_ERROR_NONE;

    if (!cipherctx->isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (cipherctx->enc) {
        err = alcp_cipher_encrypt(&(ctx->handle), in, out, inl);
    } else {
        err = alcp_cipher_decrypt(&(ctx->handle), in, out, inl);
    }
    if (alcp_is_error(err)) {
        printf("Error: cipher encrypt/decrypt failed \n");
        // ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    if (!cipherctx->enc && genCipherctx->tlsversion > 0) {
        /*
         * Remove any TLS padding. Only used by cipher_aes_cbc_hmac_sha1_hw.c
         * and cipher_aes_cbc_hmac_sha256_hw.c
         */
        if (genCipherctx->removetlspad) {
            /*
             * We should have already failed in the cipher() call above if this
             * isn't true.
             */
            // if (!assert(*outl >= (size_t)(out[inl - 1] + 1))){
            if (*outl >= (size_t)(out[inl - 1] + 1)) {
                return 0;
            }
            /* The actual padding length */
            *outl -= out[inl - 1] + 1;
        }

        /* TLS MAC and explicit IV if relevant. We should have already failed
         * in the cipher() call above if *outl is too short.
         */
        // if (!assert(*outl >= genCipherctx->removetlsfixed)){
        if ((*outl >= genCipherctx->removetlsfixed)) {
            return 0;
        }
        *outl -= genCipherctx->removetlsfixed;

        /* Extract the MAC if there is one */
        if (genCipherctx->tlsmacsize > 0) {
            if (*outl < genCipherctx->tlsmacsize)
                return 0;

            genCipherctx->tlsmac = out + *outl - genCipherctx->tlsmacsize;
            *outl -= genCipherctx->tlsmacsize;
        }
    }

    return 1;
}
int
ALCP_prov_cipher_generic_stream_final(void*   vctx,
                                      Uint8*  out,
                                      size_t* outl,
                                      size_t  outsize)
{
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    ENTER();

    // if (!ossl_prov_is_running())
    //  return 0;

    if (!cipherctx->isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    *outl = 0;
    return 1;
}

int
ALCP_prov_cipher_generic_cipher(void*        vctx,
                                Uint8*       out,
                                size_t*      outl,
                                size_t       outsize,
                                const Uint8* in,
                                size_t       inl)
{
    ALCP_PROV_CIPHER_CTX*   ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t* cipherctx = &(ctx->prov_cipher_data);
    ENTER();

    alc_error_t err = ALC_ERROR_NONE;

    // if (!ossl_prov_is_running())
    //  return 0;

    if (!cipherctx->isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (cipherctx->enc) {
        err = alcp_cipher_encrypt(&(ctx->handle), in, out, inl);
    } else {
        err = alcp_cipher_decrypt(&(ctx->handle), in, out, inl);
    }
    if (alcp_is_error(err)) {
        printf("Error: cipher encrypt/decrypt failed \n");
        return 0;
    }

    *outl = inl;
    return 1;
}

int
ALCP_prov_cipher_generic_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, cipherctx->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(
            p, &genCipherctx->oiv_buff, cipherctx->ivLen)
        && !OSSL_PARAM_set_octet_string(
            p, &genCipherctx->oiv_buff, cipherctx->ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &cipherctx->iv_buff, cipherctx->ivLen)
        && !OSSL_PARAM_set_octet_string(
            p, &cipherctx->iv_buff, cipherctx->ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, genCipherctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->keyLen_in_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(
            p, genCipherctx->tlsmac, genCipherctx->tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

int
ALCP_prov_cipher_generic_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    const OSSL_PARAM* p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        cipherctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if (p != NULL) {
        unsigned int bits;

        if (!OSSL_PARAM_get_uint(p, &bits)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        genCipherctx->use_bits = bits ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &genCipherctx->tlsversion)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &genCipherctx->tlsmacsize)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        genCipherctx->num = num;
    }
    return 1;
}

int
ALCP_prov_cipher_generic_initiv(ALCP_PROV_CIPHER_CTX* ctx,
                                const Uint8*          iv,
                                size_t                ivlen)
{
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();

    if (ivlen != cipherctx->ivLen || ivlen > sizeof(cipherctx->iv_buff)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }
    cipherctx->ivState = 1;
    memcpy(cipherctx->iv_buff, iv, ivlen);
    memcpy(genCipherctx->oiv_buff, iv, ivlen);
    return 1;
}

void
ALCP_prov_cipher_generic_initkey(void*        vctx,
                                 size_t       kbits,
                                 size_t       blkbits,
                                 size_t       ivbits,
                                 unsigned int mode,
                                 uint64_t     flags,
                                 void*        provctx)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_prov_cipher_data_t*     cipherctx    = &(ctx->prov_cipher_data);
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->generic);
    ENTER();
    if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0) {
        genCipherctx->inverse_cipher = 1;
    }
    if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0) {
        genCipherctx->variable_keylength = 1;
    }

    cipherctx->pad             = 1;
    cipherctx->keyLen_in_bytes = ((kbits) / 8);
    cipherctx->ivLen           = ((ivbits) / 8);
    cipherctx->mode            = mode;
    genCipherctx->blocksize    = blkbits / 8;
    if (provctx != NULL) {
        ctx->libctx = ALCP_prov_libctx_of(provctx); /* used for rand */
    }
}

static const char    CIPHER_DEF_PROP[]  = "provider=alcp,fips=no";
const OSSL_ALGORITHM ALC_prov_ciphers[] = {

// ccm, siv, xts to be added.

#if 0 // generic cipher to be enabled after multi-update implementation. Current
      // code work with openssl speed without multi-update but its not complete
    // CTR
    { ALCP_PROV_NAMES_AES_128_CTR,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128ctr_functions },
    { ALCP_PROV_NAMES_AES_192_CTR,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192ctr_functions },
    { ALCP_PROV_NAMES_AES_256_CTR,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256ctr_functions },

    // CBC
    { ALCP_PROV_NAMES_AES_128_CBC,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128cbc_functions },
    { ALCP_PROV_NAMES_AES_192_CBC,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192cbc_functions },
    { ALCP_PROV_NAMES_AES_256_CBC,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256cbc_functions },

    // CFB
    { ALCP_PROV_NAMES_AES_128_CFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128cfb_functions },
    { ALCP_PROV_NAMES_AES_192_CFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192cfb_functions },
    { ALCP_PROV_NAMES_AES_256_CFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256cfb_functions },

    // OFB
    { ALCP_PROV_NAMES_AES_128_OFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128ofb_functions },
    { ALCP_PROV_NAMES_AES_192_OFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192ofb_functions },
    { ALCP_PROV_NAMES_AES_256_OFB,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256ofb_functions },
#endif
    // GCM
    { ALCP_PROV_NAMES_AES_128_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128gcm_functions },
    { ALCP_PROV_NAMES_AES_192_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192gcm_functions },
    { ALCP_PROV_NAMES_AES_256_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256gcm_functions },

    // Terminate OpenSSL Algorithm list with Null Pointer.
    { NULL, NULL, NULL },
};

#if 0
// FIXME: Refactor, offload some functionality to this function
EVP_CIPHER*
ALCP_prov_cipher_init(alc_prov_ctx_p cc)
{
    /* FIXME: this could be wrong */
    alc_prov_cipher_ctx_t* c = (alc_prov_cipher_ctx_t*)cc;

    ENTER();

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
#endif
