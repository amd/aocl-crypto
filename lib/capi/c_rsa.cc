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

#include "alcp/alcp.hh"
#include "alcp/capi/defs.hh"
#include "alcp/capi/rsa/builder.hh"
#include "alcp/capi/rsa/ctx.hh"

#include "alcp/digest/md5.hh"
#include "alcp/digest/md5_sha1.hh"
#include "alcp/digest/sha1.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha512.hh"
#include "alcp/rng/drbg_hmac.hh"
#include "alcp/rsa.h"

using namespace alcp;

EXTERN_C_BEGIN

Int32
alcp_rsa_get_digest_info_index(alc_digest_mode_t mode)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
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

Int32
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
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "DigestInfoSize %6d\n", size);
#endif
    return size;
}

Uint64
alcp_rsa_context_size(void)
{
    Uint64 size = sizeof(rsa::Context);
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CtxSize %6ld\n", size);
#endif
    return size;
}

alc_error_t
alcp_rsa_request(alc_rsa_handle_p pRsaHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, ALC_ERROR_NONE);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, ALC_ERROR_NONE);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    // To initialize all context members
    new (ctx) rsa::Context;

    return rsa::RsaBuilder::Build(*ctx);
}

alc_error_t
alcp_rsa_publickey_encrypt(const alc_rsa_handle_p pRsaHandle,
                           const Uint8*           pText,
                           Uint64                 textSize,
                           Uint8*                 pEncText)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, ALC_ERROR_NONE);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, ALC_ERROR_NONE);
    ALCP_BAD_PTR_ERR_RET(pText, ALC_ERROR_NONE);
    ALCP_BAD_PTR_ERR_RET(pEncText, ALC_ERROR_NONE);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    return ctx->encryptPublicFn(ctx->m_rsa, pText, textSize, pEncText);
}

alc_error_t
alcp_rsa_privatekey_decrypt(const alc_rsa_handle_p pRsaHandle,
                            alc_rsa_padding        pad,
                            const Uint8*           pEncText,
                            Uint64                 encSize,
                            Uint8*                 pText)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "EncSize %6ld", encSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->decryptPrivateFn(ctx->m_rsa, pEncText, encSize, pText);
    return err;
}

static void*
fetch_digest(alc_digest_mode_t mode)
{
    using namespace digest;
    void* digest = nullptr;
    switch (mode) {
        case ALC_MD5: {
            digest = new Md5;
            break;
        }
        case ALC_SHA1: {
            digest = new Sha1;
            break;
        }
        case ALC_MD5_SHA1: {
            digest = new Md5_Sha1;
            break;
        }
        case ALC_SHA2_256: {
            digest = new Sha256;
            break;
        }
        case ALC_SHA2_224: {
            digest = new Sha224;
            break;
        }
        case ALC_SHA2_384: {
            digest = new Sha384;
            break;
        }
        case ALC_SHA2_512: {
            digest = new Sha512;
            break;
        }
        case ALC_SHA2_512_224: {
            digest = new Sha512_224;
            break;
        }
        case ALC_SHA2_512_256: {
            digest = new Sha512_256;
            break;
        }
        default: {
            digest = nullptr;
            break;
        }
    }
    return digest;
}

alc_error_t
alcp_rsa_add_digest(const alc_rsa_handle_p pRsaHandle, alc_digest_mode_t mode)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    if (ctx->m_digest) {
        delete static_cast<digest::IDigest*>(ctx->m_digest);
    }

    ctx->m_digest = fetch_digest(mode);
    if (ctx->m_digest == nullptr) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    ctx->setDigest(ctx->m_rsa, static_cast<digest::IDigest*>(ctx->m_digest));

    return err;
}

alc_error_t
alcp_rsa_add_mgf(const alc_rsa_handle_p pRsaHandle, alc_digest_mode_t mode)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    using alcp::digest::IDigest;
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    if (ctx->m_mgf) {
        delete static_cast<digest::IDigest*>(ctx->m_mgf);
    }

    ctx->m_mgf = fetch_digest(mode);
    if (ctx->m_mgf == nullptr) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    ctx->setMgf(ctx->m_rsa, static_cast<digest::IDigest*>(ctx->m_mgf));

    return err;
}

alc_error_t
alcp_rsa_publickey_encrypt_oaep(const alc_rsa_handle_p pRsaHandle,
                                const Uint8*           pText,
                                Uint64                 textSize,
                                const Uint8*           label,
                                Uint64                 labelSize,
                                const Uint8*           pSeed,
                                Uint8*                 pEncText)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %ld,LabelSize %6ld", textSize, labelSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pSeed, err);

    if (label == nullptr && labelSize > 0) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    if (!ctx->m_digest) {
        ctx->m_digest = new alcp::digest::Sha256;
        ctx->setDigest(ctx->m_rsa,
                       static_cast<digest::IDigest*>(ctx->m_digest));
    }

    if (!ctx->m_mgf) {
        ctx->m_mgf = new alcp::digest::Sha256;
        ctx->setMgf(ctx->m_rsa, static_cast<digest::IDigest*>(ctx->m_mgf));
    }

    err = ctx->encryptPublicOaepFn(
        ctx->m_rsa, pText, textSize, label, labelSize, pSeed, pEncText);
    return err;
}

alc_error_t
alcp_rsa_privatekey_decrypt_oaep(const alc_rsa_handle_p pRsaHandle,
                                 const Uint8*           pEncText,
                                 Uint64                 encSize,
                                 const Uint8*           label,
                                 Uint64                 labelSize,
                                 Uint8*                 pText,
                                 Uint64*                textSize)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "EncSize %6ld,LabelSize %6ld", encSize, labelSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(textSize, err);

    if (label == nullptr && labelSize > 0) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->decryptPrivateOaepFn(
        ctx->m_rsa, pEncText, encSize, label, labelSize, pText, *textSize);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_pss(const alc_rsa_handle_p pRsaHandle,
                             bool                   check,
                             const Uint8*           pText,
                             Uint64                 textSize,
                             const Uint8*           pSalt,
                             Uint64                 saltSize,
                             Uint8*                 pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld,SaltSize %6ld", textSize, saltSize);
#endif

    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    if (pSalt == nullptr && saltSize > 0) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->signPrivatePssFn(
        ctx->m_rsa, check, pText, textSize, pSalt, saltSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_pss(const alc_rsa_handle_p pRsaHandle,
                              const Uint8*           pText,
                              Uint64                 textSize,
                              const Uint8*           pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->verifyPublicPssFn(ctx->m_rsa, pText, textSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_hash_pss(const alc_rsa_handle_p pRsaHandle,
                                  const Uint8*           pHash,
                                  Uint64                 hashSize,
                                  const Uint8*           pSalt,
                                  Uint64                 saltSize,
                                  Uint8*                 pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "SaltSize %6ld", saltSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pHash, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    if (pSalt == nullptr && saltSize > 0) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->signPrivatePssWithoutHashFn(
        ctx->m_rsa, pHash, hashSize, pSalt, saltSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_hash_pss(const alc_rsa_handle_p pRsaHandle,
                                   const Uint8*           pHash,
                                   Uint64                 hashSize,
                                   const Uint8*           pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "HashSize %6ld", hashSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pHash, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->verifyPublicPssWithoutHashFn(
        ctx->m_rsa, pHash, hashSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                  bool                   check,
                                  const Uint8*           pText,
                                  Uint64                 textSize,
                                  Uint8*                 pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->signPrivatePkcsv15Fn(
        ctx->m_rsa, check, pText, textSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                   const Uint8*           pText,
                                   Uint64                 textSize,
                                   const Uint8*           pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->verifyPublicPkcsv15Fn(ctx->m_rsa, pText, textSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_sign_hash_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                       const Uint8*           pText,
                                       Uint64                 textSize,
                                       Uint8*                 pSignedText)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);
    err = ctx->signPrivatePkcsv15WithoutHashFn(
        ctx->m_rsa, pText, textSize, pSignedText);
    return err;
}
ALCP_API_EXPORT alc_error_t
alcp_rsa_privatekey_decrypt_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                     const Uint8*           pText,
                                     Uint8*                 pDecryptText,
                                     Uint64*                textSize)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pDecryptText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err =
        ctx->decryptPrivatePkcsv15Fn(ctx->m_rsa, pText, pDecryptText, textSize);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_verify_hash_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                        const Uint8*           pText,
                                        Uint64                 textSize,
                                        const Uint8*           pSignedBuff)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pSignedBuff, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->verifyPublicPkcsv15WithoutHashFn(
        ctx->m_rsa, pText, textSize, pSignedBuff);
    return err;
}

ALCP_API_EXPORT alc_error_t
alcp_rsa_publickey_encrypt_pkcs1v15(const alc_rsa_handle_p pRsaHandle,
                                    const Uint8*           pText,
                                    Uint64                 textSize,
                                    Uint8*                 pEncryptText,
                                    const Uint8*           randomPad)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "TextSize %6ld", textSize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pEncryptText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->encryptPublicPkcsv15Fn(
        ctx->m_rsa, pText, textSize, pEncryptText, randomPad);
    return err;
}

Uint64
alcp_rsa_get_key_size(const alc_rsa_handle_p pRsaHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    assert(pRsaHandle != nullptr);
    if (pRsaHandle == nullptr) {
        return 0;
    }
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    return ctx->getKeySize(ctx->m_rsa);
}

alc_error_t
alcp_rsa_set_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64                 exponent,
                       const Uint8*           pModulus,
                       Uint64                 keySize)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeySize %6ld", keySize);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pModulus, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->setPublicKey(ctx->m_rsa, exponent, pModulus, keySize);

    return err;
}

alc_error_t
alcp_rsa_set_bignum_public_key(const alc_rsa_handle_p pRsaHandle,
                               const BigNum*          exponent,
                               const BigNum*          pModulus)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pModulus, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->setPublicKeyAsBignum(ctx->m_rsa, exponent, pModulus);

    return err;
}

alc_error_t
alcp_rsa_set_privatekey(const alc_rsa_handle_p pRsaHandle,
                        const Uint8*           dp,
                        const Uint8*           dq,
                        const Uint8*           p,
                        const Uint8*           q,
                        const Uint8*           qinv,
                        const Uint8*           mod,
                        Uint64                 size)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeySize %6ld", size);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(dp, err);
    ALCP_BAD_PTR_ERR_RET(dq, err);
    ALCP_BAD_PTR_ERR_RET(p, err);
    ALCP_BAD_PTR_ERR_RET(q, err);
    ALCP_BAD_PTR_ERR_RET(qinv, err);
    ALCP_BAD_PTR_ERR_RET(mod, err);
    ALCP_ZERO_LEN_ERR_RET(size, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->setPrivateKey(ctx->m_rsa, dp, dq, p, q, qinv, mod, size);

    return err;
}

alc_error_t
alcp_rsa_set_bignum_private_key(const alc_rsa_handle_p pRsaHandle,
                                const BigNum*          dp,
                                const BigNum*          dq,
                                const BigNum*          p,
                                const BigNum*          q,
                                const BigNum*          qinv,
                                const BigNum*          mod)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(dp, err);
    ALCP_BAD_PTR_ERR_RET(dq, err);
    ALCP_BAD_PTR_ERR_RET(p, err);
    ALCP_BAD_PTR_ERR_RET(q, err);
    ALCP_BAD_PTR_ERR_RET(qinv, err);
    ALCP_BAD_PTR_ERR_RET(mod, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_rsa, ALC_ERROR_NONE);

    err = ctx->setPrivateKeyAsBignum(ctx->m_rsa, dp, dq, p, q, qinv, mod);

    return err;
}

void
alcp_rsa_finish(const alc_rsa_handle_p pRsaHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    if (ctx->finish && ctx->m_rsa) {
        ctx->finish(ctx->m_rsa);
        ctx->m_rsa = nullptr;
    }

    if (ctx->m_digest) {
        delete static_cast<const alcp::digest::IDigest*>(ctx->m_digest);
        ctx->m_digest = nullptr;
    }

    if (ctx->m_mgf) {
        delete static_cast<const alcp::digest::IDigest*>(ctx->m_mgf);
        ctx->m_mgf = nullptr;
    }
    ctx->~Context();
}

alc_error_t
alcp_rsa_context_copy(const alc_rsa_handle_p pSrcHandle,
                      const alc_rsa_handle_p pDestHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pSrcHandle, err);
    ALCP_BAD_PTR_ERR_RET(pDestHandle, err);

    auto src_ctx  = static_cast<rsa::Context*>(pSrcHandle->context);
    auto dest_ctx = static_cast<rsa::Context*>(pDestHandle->context);

    ALCP_BAD_PTR_ERR_RET(src_ctx, err);
    ALCP_BAD_PTR_ERR_RET(dest_ctx, err);
    ALCP_BAD_PTR_ERR_RET(src_ctx->m_rsa, err);

    new (dest_ctx) rsa::Context;

    err = src_ctx->duplicate(src_ctx, dest_ctx);
    return err;
}

EXTERN_C_END
