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

#if 0
    /*
     * Variable key length cipher functions for OSSL_PARAM settables
     */
    int ALCP_prov_cipher_var_keylen_set_ctx_params(void*            vctx,
                                              const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*  ctx = (ALCP_PROV_CIPHER_CTX*)vctx;
    const OSSL_PARAM* p;

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
        if (cipherctx->m_keyLen_in_bytes != keylen) {
            cipherctx->m_keyLen_in_bytes  = keylen;
            cipherctx->m_isKeySet = 0;
        }
    }
    return 1;
}
#endif

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

// to do:

#if 0
void
ossl_cipher_generic_reset_ctx(ALCP_PROV_CIPHER_CTX* ctx)
{
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    if (ctx != NULL && genCipherctx->m_alloced) {
        OPENSSL_free(genCipherctx->m_tlsmac);
        genCipherctx->m_alloced = 0;
        genCipherctx->m_tlsmac  = NULL;
    }
}

static int
cipher_generic_init_internal(ALCP_PROV_CIPHER_CTX* ctx,
                             const unsigned char*  key,
                             size_t                keylen,
                             const unsigned char*  iv,
                             size_t                ivlen,
                             const OSSL_PARAM      params[],
                             int                   enc)
{
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    genCipherctx->m_num     = 0;
    genCipherctx->m_bufsz   = 0;
    genCipherctx->m_updated = 0;
    cipherctx->enc          = enc ? 1 : 0;

    if (!ossl_prov_is_running())
        return 0;

    if (iv != NULL && cipherctx->m_mode != EVP_CIPH_ECB_MODE) {
        if (!ossl_cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && cipherctx->m_ivState
        && (cipherctx->m_mode == EVP_CIPH_CBC_MODE
            || cipherctx->m_mode == EVP_CIPH_CFB_MODE
            || cipherctx->m_mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(
            cipherctx->m_iv_buff, genCipherctx->m_oiv_buff, cipherctx->m_ivLen);

    if (key != NULL) {
        if (genCipherctx->m_variable_keylength == 0) {
            if (keylen != cipherctx->m_keyLen_in_bytes) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            cipherctx->m_keyLen_in_bytes = keylen;
        }
        if (!cipherctx->hw->init(ctx, key, cipherctx->m_keyLen_in_bytes))
            return 0;
        cipherctx->m_isKeySet = 1;
    }
    return ossl_cipher_generic_set_ctx_params(ctx, params);
}

int
ossl_cipher_generic_einit(void*                vctx,
                          const unsigned char* key,
                          size_t               keylen,
                          const unsigned char* iv,
                          size_t               ivlen,
                          const OSSL_PARAM     params[])
{
    return cipher_generic_init_internal(
        (ALCP_PROV_CIPHER_CTX*)vctx, key, keylen, iv, ivlen, params, 1);
}

int
ossl_cipher_generic_dinit(void*                vctx,
                          const unsigned char* key,
                          size_t               keylen,
                          const unsigned char* iv,
                          size_t               ivlen,
                          const OSSL_PARAM     params[])
{
    return cipher_generic_init_internal(
        (ALCP_PROV_CIPHER_CTX*)vctx, key, keylen, iv, ivlen, params, 0);
}

/* Max padding including padding length byte */
#define MAX_PADDING 256

int
ossl_cipher_generic_block_update(void*                vctx,
                                 unsigned char*       out,
                                 size_t*              outl,
                                 size_t               outsize,
                                 const unsigned char* in,
                                 size_t               inl)
{
    size_t                      outlint      = 0;
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    size_t blksz = genCipherctx->m_blocksize;
    size_t nextblocks;

    if (!cipherctx->m_isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (genCipherctx->m_tlsversion > 0) {
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
            unsigned char padval;
            size_t        padnum, loop;

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
            padval = (unsigned char)(padnum - 1);
            if (genCipherctx->m_tlsversion == SSL3_VERSION) {
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
        if (!cipherctx->hw->cipher(ctx, out, in, inl)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (genCipherctx->m_alloced) {
            OPENSSL_free(genCipherctx->m_tlsmac);
            genCipherctx->m_alloced = 0;
            genCipherctx->m_tlsmac  = NULL;
        }

        /* This only fails if padding is publicly invalid */
        *outl = inl;
        if (!cipherctx->enc
            && !ossl_cipher_tlsunpadblock(ctx->base.libctx,
                                          genCipherctx->m_tlsversion,
                                          out,
                                          outl,
                                          blksz,
                                          &genCipherctx->m_tlsmac,
                                          &genCipherctx->m_alloced,
                                          genCipherctx->m_tlsmacsize,
                                          0)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        return 1;
    }

    if (genCipherctx->m_bufsz != 0)
        nextblocks = ossl_cipher_fillblock(
            cipherctx->buf, &genCipherctx->m_bufsz, blksz, &in, &inl);
    else
        nextblocks = inl & ~(blksz - 1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (genCipherctx->m_bufsz == blksz
        && (cipherctx->enc || inl > 0 || !cipherctx->pad)) {
        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!cipherctx->hw->cipher(ctx, out, cipherctx->buf, blksz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        genCipherctx->m_bufsz = 0;
        outlint               = blksz;
        out += blksz;
    }
    if (nextblocks > 0) {
        if (!cipherctx->enc && cipherctx->pad && nextblocks == inl) {
            if (!ossl_assert(inl >= blksz)) {
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
        if (!cipherctx->hw->cipher(ctx, out, in, nextblocks)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0
        && !ossl_cipher_trailingdata(
            cipherctx->buf, &genCipherctx->m_bufsz, blksz, &in, &inl)) {
        /* ERR_raise already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

int
ossl_cipher_generic_block_final(void*          vctx,
                                unsigned char* out,
                                size_t*        outl,
                                size_t         outsize)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    size_t blksz = genCipherctx->m_blocksize;

    if (!ossl_prov_is_running())
        return 0;

    if (!cipherctx->m_isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (genCipherctx->m_tlsversion > 0) {
        /* We never finalize TLS, so this is an error */
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (cipherctx->enc) {
        if (cipherctx->pad) {
            ossl_cipher_padblock(cipherctx->buf, &genCipherctx->m_bufsz, blksz);
        } else if (genCipherctx->m_bufsz == 0) {
            *outl = 0;
            return 1;
        } else if (genCipherctx->m_bufsz != blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!cipherctx->hw->cipher(ctx, out, cipherctx->buf, blksz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        genCipherctx->m_bufsz = 0;
        *outl                 = blksz;
        return 1;
    }

    /* Decrypting */
    if (genCipherctx->m_bufsz != blksz) {
        if (genCipherctx->m_bufsz == 0 && !cipherctx->pad) {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (!cipherctx->hw->cipher(ctx, cipherctx->buf, cipherctx->buf, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (cipherctx->pad
        && !ossl_cipher_unpadblock(
            cipherctx->buf, &genCipherctx->m_bufsz, blksz)) {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < genCipherctx->m_bufsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, cipherctx->buf, genCipherctx->m_bufsz);
    *outl                 = genCipherctx->m_bufsz;
    genCipherctx->m_bufsz = 0;
    return 1;
}

int
ossl_cipher_generic_stream_update(void*                vctx,
                                  unsigned char*       out,
                                  size_t*              outl,
                                  size_t               outsize,
                                  const unsigned char* in,
                                  size_t               inl)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    if (!cipherctx->m_isKeySet) {
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

    if (!cipherctx->hw->cipher(ctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    if (!cipherctx->enc && genCipherctx->m_tlsversion > 0) {
        /*
         * Remove any TLS padding. Only used by cipher_aes_cbc_hmac_sha1_hw.c
         * and cipher_aes_cbc_hmac_sha256_hw.c
         */
        if (genCipherctx->m_removetlspad) {
            /*
             * We should have already failed in the cipher() call above if this
             * isn't true.
             */
            if (!ossl_assert(*outl >= (size_t)(out[inl - 1] + 1)))
                return 0;
            /* The actual padding length */
            *outl -= out[inl - 1] + 1;
        }

        /* TLS MAC and explicit IV if relevant. We should have already failed
         * in the cipher() call above if *outl is too short.
         */
        if (!ossl_assert(*outl >= genCipherctx->m_removetlsfixed))
            return 0;
        *outl -= genCipherctx->m_removetlsfixed;

        /* Extract the MAC if there is one */
        if (genCipherctx->m_tlsmacsize > 0) {
            if (*outl < genCipherctx->m_tlsmacsize)
                return 0;

            genCipherctx->m_tlsmac = out + *outl - genCipherctx->m_tlsmacsize;
            *outl -= genCipherctx->m_tlsmacsize;
        }
    }

    return 1;
}
int
ossl_cipher_generic_stream_final(void*          vctx,
                                 unsigned char* out,
                                 size_t*        outl,
                                 size_t         outsize)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    if (!ossl_prov_is_running())
        return 0;

    if (!cipherctx->m_isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    *outl = 0;
    return 1;
}

int
ossl_cipher_generic_cipher(void*                vctx,
                           unsigned char*       out,
                           size_t*              outl,
                           size_t               outsize,
                           const unsigned char* in,
                           size_t               inl)
{
    ALCP_PROV_CIPHER_CTX* ctx       = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*    cipherctx = ctx->base.prov_cipher_data;

    if (!ossl_prov_is_running())
        return 0;

    if (!cipherctx->m_isKeySet) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!cipherctx->hw->cipher(ctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

int
ossl_cipher_generic_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->m_ivLen)) {
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
            p, &genCipherctx->m_oiv_buff, cipherctx->m_ivLen)
        && !OSSL_PARAM_set_octet_string(
            p, &genCipherctx->m_oiv_buff, cipherctx->m_ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(
            p, &cipherctx->m_iv_buff, cipherctx->m_ivLen)
        && !OSSL_PARAM_set_octet_string(
            p, &cipherctx->m_iv_buff, cipherctx->m_ivLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, cipherctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, cipherctx->m_keyLen_in_bytes)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(
            p, genCipherctx->m_tlsmac, genCipherctx->m_tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

int
ossl_cipher_generic_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

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
        genCipherctx->m_use_bits = bits ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &genCipherctx->m_tlsversion)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &genCipherctx->m_tlsmacsize)) {
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
        cipherctx->num = num;
    }
    return 1;
}

int
ossl_cipher_generic_initiv(ALCP_PROV_CIPHER_CTX* ctx,
                           const unsigned char*  iv,
                           size_t                ivlen)
{
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    if (ivlen != cipherctx->m_ivLen || ivlen > sizeof(cipherctx->m_iv_buff)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }
    cipherctx->m_ivState = 1;
    memcpy(cipherctx->m_iv_buff, iv, ivlen);
    memcpy(genCipherctx->m_oiv_buff, iv, ivlen);
    return 1;
}

void
ossl_cipher_generic_initkey(void*        vctx,
                            size_t       kbits,
                            size_t       blkbits,
                            size_t       ivbits,
                            unsigned int m_mode,
                            uint64_t     flags,
                            void*        provctx)
{
    ALCP_PROV_CIPHER_CTX*       ctx          = (ALCP_PROV_CIPHER_CTX*)vctx;
    alc_cipher_data_t*          cipherctx    = ctx->base.prov_cipher_data;
    _alc_cipher_generic_data_t* genCipherctx = &(cipherctx->m_generic);

    if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
        cipherctx->inverse_cipher = 1;
    if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
        cipherctx->variable_keylength = 1;

    cipherctx->pad               = 1;
    cipherctx->m_keyLen_in_bytes = ((kbits) / 8);
    cipherctx->m_ivLen           = ((ivbits) / 8);
    // cipherctx->hw        = hw;
    cipherctx->m_mode         = m_mode;
    genCipherctx->m_blocksize = blkbits / 8;
    if (provctx != NULL)
        ctx->base.libctx = PROV_LIBCTX_OF(provctx); /* used for rand */
}

#endif

///////////// to be removed below code

#if 0

void
ALCP_prov_cipher_freectx(void* vctx)
{
    ENTER();
    alc_prov_cipher_ctx_t* pcctx = vctx;

    if (pcctx->handle.ch_context != NULL) {
        alcp_cipher_finish(&pcctx->handle);
        OPENSSL_free(pcctx->handle.ch_context);
        pcctx->handle.ch_context = NULL;
    }

    OPENSSL_free(vctx);
    vctx = NULL;
    EXIT();
}

void*
ALCP_prov_cipher_newctx(void* vprovctx, const void* cinfo, bool is_aead)
{
    alc_prov_cipher_ctx_t* ciph_ctx;
    alc_prov_ctx_p         pctx = (alc_prov_ctx_p)vprovctx;

    ENTER();
    ciph_ctx = OPENSSL_zalloc(sizeof(*ciph_ctx));

    if (ciph_ctx != NULL) {
        ciph_ctx->pc_prov_ctx = pctx;
        ciph_ctx->pc_libctx   = pctx->ap_libctx;
        if (is_aead) {
            ciph_ctx->is_aead             = true;
            ciph_ctx->pc_cipher_aead_info = *((alc_cipher_aead_info_t*)cinfo);
            ciph_ctx->finalized           = false;

        } else {
            ciph_ctx->is_aead        = false;
            ciph_ctx->pc_cipher_info = *((alc_cipher_info_t*)cinfo);
        }
        ciph_ctx->is_key_assigned      = false;
        ciph_ctx->ivlen                = -1;
        ciph_ctx->is_openssl_speed_siv = false;
    }

    return ciph_ctx;
}

void*
ALCP_prov_cipher_dupctx(void* vctx)
{
    ENTER();
    // FIXME: Implement
    alc_prov_cipher_ctx_t* csrc = vctx;
    EXIT();
    return csrc;
}

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM*
ALCP_prov_cipher_gettable_params(void* provctx)
{
    EXIT();
    return cipher_known_gettable_params;
}

int
ALCP_prov_cipher_get_params(OSSL_PARAM params[],
                            int        mode,
                            int        key_size,
                            bool       is_aead)
{
    OSSL_PARAM* p;
    int         kbits   = key_size;
    int         blkbits = 128;
    int         ivbits  = is_aead ? 96 : 128;

    ENTER();

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        EXIT();
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, is_aead ? 1 : 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    EXIT();
    return 1;
}

const OSSL_PARAM*
ALCP_prov_cipher_gettable_ctx_params(void* cctx, void* provctx)
{
    return cipher_known_gettable_params;
}

/* Parameters that libcrypto can send to this implementation */
const OSSL_PARAM*
ALCP_prov_cipher_settable_ctx_params(void* cctx, void* provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END,
    };
    EXIT();
    return table;
}

int
ALCP_prov_cipher_set_params(const OSSL_PARAM params[])
{
    ENTER();
    return 1;
}

int
ALCP_prov_cipher_get_ctx_params(void* vctx, OSSL_PARAM params[])
{
    OSSL_PARAM*            p;
    alc_prov_cipher_ctx_t* cctx   = (alc_prov_cipher_ctx_t*)vctx;
    size_t                 keylen = 0;
    if (cctx->is_aead) {
        keylen = cctx->pc_cipher_aead_info.ci_keyLen;

    } else {
        keylen = cctx->pc_cipher_info.ci_keyLen;
    }

    ENTER();
    int ivlen = (cctx->ivlen < 0)
                    ? 16
                    : cctx->ivlen; // cctx->ivlen < 0 means ivlen was never set.
                                   // For non-AEAD modes default iv length is 16
                                   // and for AEAD modes default iv length is 12
    if ((cctx->ivlen < 0) && cctx->is_aead) {
        ivlen = 12;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    if (keylen > 0
        && (p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "tag")) != NULL) {
        const void* tag;
        size_t      used_length;
        if (!OSSL_PARAM_get_octet_string_ptr(params, &tag, &used_length)) {
            printf("Provider: An error has occurred\n");
        }
#ifdef DEBUG
        printf("Provider: Size is %ld and tag is %p\n", used_length, tag);
#endif
        cctx->taglen = used_length;
        if (!cctx->add_inititalized
            && (cctx->is_aead
                && (cctx->pc_cipher_aead_info.ci_mode == ALC_AES_MODE_CCM))) {
            Uint8 a;
            alcp_cipher_aead_set_tag_length(&(cctx->handle), cctx->taglen);

            alc_error_t err = alcp_cipher_aead_init(&(cctx->handle),
                                                    cctx->pc_cipher_info.ci_key,
                                                    keylen,
                                                    cctx->iv,
                                                    cctx->ivlen);
            if (err != ALC_ERROR_NONE) {
                printf("Provider: Error in aead init\n");
                return 0;
            }

            if (cctx->aadlen != 0)
                alcp_cipher_aead_set_aad(
                    &(cctx->handle), cctx->aad, cctx->aadlen);
            cctx->add_inititalized = true;
            alcp_cipher_aead_encrypt_update(&(cctx->handle), &a, &a, 0);
        }
        alc_error_t err =
            alcp_cipher_aead_get_tag(&(cctx->handle), (Uint8*)tag, used_length);
        if (alcp_is_error(err)) {
            printf("ALCP Provider: Error while getting GCM Tag\n");
            return 1;
        }
    }

    EXIT();
    return 1;
}

int
ALCP_prov_cipher_set_ctx_params(void* vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM*      p;
    alc_prov_cipher_ctx_t* cctx = (alc_prov_cipher_ctx_t*)vctx;
    ENTER();

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;
        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
        if (cctx->is_aead) {
            cctx->pc_cipher_aead_info.ci_keyLen = keylen;

        } else {

            cctx->pc_cipher_info.ci_keyLen = keylen;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen;
        if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
#ifdef DEBUG
        printf("Provider: IVLEN Length is %ld \n", ivlen);
#endif
        cctx->ivlen = ivlen;
    }

    // Getting the Tag for AEAD including SIV
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            printf("Provider: TAG is in wrong format!\n");
            return 0;
        }
        cctx->tagbuff = p->data;
        cctx->taglen  = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, (int*)&cctx->is_openssl_speed_siv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            HERE();
            return 0;
        }
    }

#ifdef DEBUG
    printf("Provider: Got tag with size:%d\n", cctx->taglen);
#endif

    EXIT();
    return 1;
}


static inline int
ALCP_prov_cipher_aes_encrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    alc_prov_cipher_ctx_t* cctx  = vctx;
    alc_cipher_info_t*     cinfo = &cctx->pc_cipher_info;
    alc_error_t            err;

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key,
               key,
               (cinfo->ci_mode == ALC_AES_MODE_XTS ? 2 : 1)
                   * (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }

    if (((cctx->is_key_assigned == false) || (cctx->iv == NULL)
         || (cctx->keylen == 0) || (cctx->ivlen == 0))) {

#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }

    cctx->pc_cipher_info.ci_iv  = cctx->iv;
    cctx->pc_cipher_info.ci_key = cctx->key;

    // OpenSSL Speed likes to keep keylen 0
    if (cctx->keylen != 0) {
        cctx->pc_cipher_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_info.ci_keyLen = 128;
        cctx->pc_cipher_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n",
           cinfo->ci_keyLen,
           keylen,
           cctx->key);
#endif

    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        if (!((keylen == 128) || (keylen == 256))) {

#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with error
            return 0;
        }
    }

    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size());

    // Request handle for the cipher
    err =
        alcp_cipher_request(cinfo->ci_mode, cinfo->ci_keyLen, &(cctx->handle));

    if (err != ALC_ERROR_NONE) {
        free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (cctx->pc_cipher_info.ci_iv != NULL) {
#ifdef DEBUG
            printf("Provider: Setting iv length as %ld from %d\n",
                   ivlen,
                   cctx->ivlen);
#endif
            if (ivlen == 0) {
                cctx->ivlen = 16;
            } else {
                cctx->ivlen = ivlen;
            }
        }
    }

    err = alcp_cipher_init(&(cctx->handle),
                           cinfo->ci_key,
                           cinfo->ci_keyLen,
                           cinfo->ci_iv,
                           cctx->ivlen);
    if (alcp_is_error(err)) {
        printf("Error in cipher init\n");
        return 0;
    }

    // Enable Encryption Mode
    cctx->enc_flag         = true;
    cctx->add_inititalized = false;
    return 1;
}


static inline int
ALCP_prov_cipher_aes_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    alc_prov_cipher_ctx_t* cctx  = vctx;
    alc_cipher_info_t*     cinfo = &cctx->pc_cipher_info;

    alc_error_t err;

    if (keylen != 0) {
        cctx->keylen = keylen;
    }
    if (ivlen != 0) {
        cctx->ivlen = ivlen;
    }
    if (key != NULL) {
        memcpy(cctx->key,
               key,
               (cinfo->ci_mode == ALC_AES_MODE_XTS ? 2 : 1)
                   * (cctx->keylen / 8));
        cctx->is_key_assigned = true;
    }
    if (iv != NULL) {
        cctx->iv = iv;
    }
    if (((cctx->is_key_assigned == false) || (cctx->iv == NULL)
         || (cctx->keylen == 0) || (cctx->ivlen == 0))) {
#ifdef DEBUG
        printf("Returning because all of key, iv, ivlen and keylen not "
               "available\n");
#endif
        return 1;
    }
    cctx->pc_cipher_info.ci_type = ALC_CIPHER_TYPE_AES;

    // Mode Already set
    if (cctx->iv != NULL) {
        cctx->pc_cipher_info.ci_iv = cctx->iv;
    } else {
        // FIXME:return error!
    }

    cctx->pc_cipher_info.ci_key = cctx->key;

    if (cctx->keylen != 0) {
        cctx->pc_cipher_info.ci_keyLen = cctx->keylen;
    } else {
        cctx->pc_cipher_info.ci_keyLen = 128;
        cctx->pc_cipher_info.ci_key    = OPENSSL_malloc(128);
    }

#ifdef DEBUG
    printf("Provider: %d keylen:%ld, key:%p\n", cinfo->ci_keyLen, keylen, iv);
#endif

    // For AES XTS Mode, get the tweak key
    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (!key) {
            // For handling when openssl speed probes the code with null key
            return 1;
        }
        if (!((keylen == 128) || (keylen == 256))) {

#ifdef DEBUG
            printf("Provider: Unsupported Key Length %ld in AES XTS Mode of "
                   "Operation\n",
                   keylen);
#endif
            // Return with error
            return 0;
        }
    }

    // Manually allocate context
    (cctx->handle).ch_context = OPENSSL_malloc(alcp_cipher_context_size());

    // Request handle for the cipher
    err =
        alcp_cipher_request(cinfo->ci_mode, cinfo->ci_keyLen, &(cctx->handle));
    if (err != ALC_ERROR_NONE) {
        free((cctx->handle).ch_context);
        printf("Provider: Request somehow failed!\n");
        return 0;
    }
#ifdef DEBUG
    else {
        printf("Provider: Request success!\n");
    }
#endif

    if (cinfo->ci_mode == ALC_AES_MODE_XTS) {
        if (cctx->pc_cipher_info.ci_iv != NULL) {
#ifdef DEBUG
            printf("Provider: Setting iv length as %ld from %d\n",
                   ivlen,
                   cctx->ivlen);
#endif
            if (ivlen == 0) {
                cctx->ivlen = 16;
            } else {
                cctx->ivlen = ivlen;
            }
        }
    }

    err = alcp_cipher_init(&(cctx->handle),
                           cinfo->ci_key,
                           cinfo->ci_keyLen,
                           cinfo->ci_iv,
                           cctx->ivlen);
    if (alcp_is_error(err)) {
        printf("Error in cipher init\n");
        return 0;
    }

    // Enable Decryption Mode
    cctx->enc_flag = false;

    cctx->add_inititalized = false;
    EXIT();
    return 1;
}

int
ALCP_prov_cipher_cfb_decrypt_init(void*                vctx,
                                  const unsigned char* key,
                                  size_t               keylen,
                                  const unsigned char* iv,
                                  size_t               ivlen,
                                  const OSSL_PARAM     params[])
{
    ENTER();
    PRINT("Provider: CFB\n");
    int ret =
        ALCP_prov_cipher_aes_decrypt_init(vctx, key, keylen, iv, ivlen, params);
    EXIT();
    return ret;
}



static inline int
ALCP_prov_cipher_update(void*                vctx,
                        unsigned char*       out,
                        size_t*              outl,
                        size_t               outsize,
                        const unsigned char* in,
                        size_t               inl)
{
    alc_prov_cipher_ctx_t* cctx = vctx;
    alc_error_t            err  = ALC_ERROR_NONE;

    if (inl == 0) {
        *outl = inl;
        return 1;
    }

    if (cctx->enc_flag) {
        err = alcp_cipher_encrypt(&(cctx->handle), in, out, inl);
    } else {
        err = alcp_cipher_decrypt(&(cctx->handle), in, out, inl);
    }

    if (err != ALC_ERROR_NONE) {
        const int err_size = 256;
        Uint8     err_buf[err_size];
        alcp_error_str(err, err_buf, err_size);
        printf("Provider: Encyption/Decryption Failure! ALCP:%s\n", err_buf);
        printf("%p,%10" PRId64 "%p\n", (void*)in, inl, (void*)out);
        printf("%d\n", cctx->pc_cipher_info.ci_mode == ALC_AES_MODE_CFB);
        printf("%p\n", (void*)cctx->pc_cipher_info.ci_iv);
        alcp_error_str(err, err_buf, err_size);
        return 0;
    }
    *outl = inl;
    return 1;
}
int
ALCP_prov_cipher_cfb_update(void*                vctx,
                            unsigned char*       out,
                            size_t*              outl,
                            size_t               outsize,
                            const unsigned char* in,
                            size_t               inl)
{
    ENTER();
    PRINT("Provider: CFB\n");
    int ret = ALCP_prov_cipher_update(vctx, out, outl, outsize, in, inl);
    EXIT();
    return ret;
}




int
ALCP_prov_cipher_final(void*          vctx,
                       unsigned char* out,
                       size_t*        outl,
                       size_t         outsize)
{
    ENTER();
    // alc_prov_cipher_ctx_t* cctx = vctx;

    // TODO: Introduce Finish here for finalising the context and
    // handle the corresponding memory issues.
    // alcp_cipher_finish(&cctx->handle);
    // Nothing to do!
    *outl                       = 0;
    int                    ret  = 1;
    alc_prov_cipher_ctx_t* cctx = vctx;
    if ((cctx->is_aead) && (cctx->tagbuff != NULL) && (cctx->taglen != 0)) {
        Uint8       tag[16]; // 16 is maximum tag length
        alc_error_t err =
            alcp_cipher_aead_get_tag(&(cctx->handle), tag, cctx->taglen);
        if (err != ALC_ERROR_NONE) {
            printf("Provider: Error occurred in finalize while getting AEAD "
                   "Tag\n");
            ret = 0;
        }
        if (memcmp(cctx->tagbuff, tag, cctx->taglen)) {
            // Tag mismatch, hence finalize should return failure
            ret = 0;
        }
    }
    cctx->finalized = true;
    return ret;
}
#endif
///////////// to be removed above code

static const char    CIPHER_DEF_PROP[]  = "provider=alcp,fips=no";
const OSSL_ALGORITHM ALC_prov_ciphers[] = {
#if 0
    // CFB
    { ALCP_PROV_NAMES_AES_256_CFB, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB1, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB1, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB1, CIPHER_DEF_PROP, cfb_functions_128 },
    { ALCP_PROV_NAMES_AES_256_CFB8, CIPHER_DEF_PROP, cfb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_CFB8, CIPHER_DEF_PROP, cfb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_CFB8, CIPHER_DEF_PROP, cfb_functions_128 },

// FIXME: Enable CBC and CTR after adding multi update APIs as enabling them
// is causing TLS Handshake failure in OpenSSL

// CTR
    // Enabling CTR does not cause any failures but since OpenSSL is calling ALCP
    // CTR for CTR-DRBG its not proper to enable CTR without multi update API
    {ALCP_PROV_NAMES_AES_256_CTR, CIPHER_DEF_PROP, ctr_functions_256 },
    {ALCP_PROV_NAMES_AES_192_CTR, CIPHER_DEF_PROP, ctr_functions_192 },
    {ALCP_PROV_NAMES_AES_128_CTR, CIPHER_DEF_PROP, ctr_functions_128 },
// CBC
    // { ALCP_PROV_NAMES_AES_256_CBC, CIPHER_DEF_PROP, cbc_functions_256 },
    // { ALCP_PROV_NAMES_AES_192_CBC, CIPHER_DEF_PROP, cbc_functions_192 },
    // { ALCP_PROV_NAMES_AES_128_CBC, CIPHER_DEF_PROP, cbc_functions_128 },
// OFB
    { ALCP_PROV_NAMES_AES_256_OFB, CIPHER_DEF_PROP, ofb_functions_256 },
    { ALCP_PROV_NAMES_AES_192_OFB, CIPHER_DEF_PROP, ofb_functions_192 },
    { ALCP_PROV_NAMES_AES_128_OFB, CIPHER_DEF_PROP, ofb_functions_128 },


    // XTS
    { ALCP_PROV_NAMES_AES_256_XTS, CIPHER_DEF_PROP, xts_functions_256 },
    { ALCP_PROV_NAMES_AES_128_XTS, CIPHER_DEF_PROP, xts_functions_128 },
#endif
    // GCM
    { ALCP_PROV_NAMES_AES_128_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes128gcm_functions },
    // gcm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes192gcm_functions },
    // gcm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_GCM,
      CIPHER_DEF_PROP,
      ALCP_prov_aes256gcm_functions },
// gcm_functions_256 },

#if 0
    // CCM
    { ALCP_PROV_NAMES_AES_128_CCM, CIPHER_DEF_PROP, ccm_functions_128 },
    { ALCP_PROV_NAMES_AES_192_CCM, CIPHER_DEF_PROP, ccm_functions_192 },
    { ALCP_PROV_NAMES_AES_256_CCM, CIPHER_DEF_PROP, ccm_functions_256 },
    // SIV
    { ALCP_PROV_NAMES_AES_128_SIV, CIPHER_DEF_PROP, siv_functions_128 },
    { ALCP_PROV_NAMES_AES_192_SIV, CIPHER_DEF_PROP, siv_functions_192 },
    { ALCP_PROV_NAMES_AES_256_SIV, CIPHER_DEF_PROP, siv_functions_256 },
#endif
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
