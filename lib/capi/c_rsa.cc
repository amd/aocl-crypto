/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha2_384.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/rng/drbg_hmac.hh"
#include "alcp/rsa.h"
#include "alcp/rsa/rsaerror.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_rsa_context_size()
{
    Uint64 size = sizeof(rsa::Context) + rsa::RsaBuilder::getSize();
    return size;
}

alc_error_t
alcp_rsa_supported()
{
    alc_error_t err = ALC_ERROR_NOT_SUPPORTED;

    return err;
}

alc_error_t
alcp_rsa_request(alc_rsa_handle_p pRsaHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    // To initialize all context members
    new (ctx) rsa::Context;

    ctx->status = rsa::RsaBuilder::Build(*ctx);

    return ctx->status.ok() ? err : ALC_ERROR_GENERIC;
}

alc_error_t
alcp_rsa_publickey_encrypt(const alc_rsa_handle_p pRsaHandle,
                           alc_rsa_padding        pad,
                           const Uint8*           pPublicKeyMod,
                           Uint64                 pPublicKeyModSize,
                           Uint64                 publicKeyExp,
                           const Uint8*           pText,
                           Uint64                 textSize,
                           Uint8*                 pEncText)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pPublicKeyMod, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    ctx->status = ctx->encryptPublicFn(ctx->m_rsa, pText, textSize, pEncText);

    if (ctx->status.ok()) {
        return err;
    } else {
        // fetching the module error
        Uint16 module_error = (ctx->status.code() >> 16) & 0xff;
        return (alcp::rsa::ErrorCode::eNotPermitted == module_error)
                   ? ALC_ERROR_NOT_PERMITTED
                   : ALC_ERROR_GENERIC;
    }
}

alc_error_t
alcp_rsa_privatekey_decrypt(const alc_rsa_handle_p pRsaHandle,
                            alc_rsa_padding        pad,
                            const Uint8*           pEncText,
                            Uint64                 encSize,
                            Uint8*                 pText)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    ctx->status = ctx->decryptPrivateFn(ctx->m_rsa, pEncText, encSize, pText);

    if (ctx->status.ok()) {
        return err;
    } else {
        // fetching the module error
        Uint16 module_error = (ctx->status.code() >> 16) & 0xff;
        return (alcp::rsa::ErrorCode::eNotPermitted == module_error)
                   ? ALC_ERROR_NOT_PERMITTED
                   : ALC_ERROR_GENERIC;
    }
}

static void*
fetch_digest(const alc_digest_info_t& digestInfo)
{
    using namespace alcp::digest;
    void* digest = nullptr;
    switch (digestInfo.dt_type) {
        case ALC_DIGEST_TYPE_SHA2: {
            switch (digestInfo.dt_mode.dm_sha2) {
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
                default: {
                    digest = nullptr;
                }
            }
            break;
        }
        case ALC_DIGEST_TYPE_SHA3: {
            switch (digestInfo.dt_mode.dm_sha3) {
                case ALC_SHA3_224: {
                    digest = new digest::Sha3(digestInfo);
                    break;
                }
                default: {
                    digest = nullptr;
                    break;
                }
            }
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
alcp_rsa_add_digest_oaep(const alc_rsa_handle_p pRsaHandle,
                         alc_digest_info_t      digestInfo)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    if (ctx->m_digest) {
        delete static_cast<digest::IDigest*>(ctx->m_digest);
        ctx->m_digest = nullptr;
    }

    ctx->m_digest = fetch_digest(digestInfo);

    ctx->setDigest(ctx->m_rsa, static_cast<digest::IDigest*>(ctx->m_digest));

    return err;
}

alc_error_t
alcp_rsa_add_mgf_oaep(const alc_rsa_handle_p pRsaHandle,
                      alc_digest_info_t      digestInfo)
{
    using alcp::digest::IDigest;
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    if (ctx->m_mgf) {
        delete static_cast<digest::IDigest*>(ctx->m_mgf);
        ctx->m_mgf = nullptr;
    }

    ctx->m_mgf = fetch_digest(digestInfo);
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
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(label, err);
    ALCP_BAD_PTR_ERR_RET(pSeed, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    if (!ctx->m_digest) {
        ctx->m_digest = new alcp::digest::Sha256;
        ctx->setDigest(ctx->m_rsa,
                       static_cast<digest::IDigest*>(ctx->m_digest));
    }

    if (!ctx->m_mgf) {
        ctx->m_mgf = new alcp::digest::Sha256;
        ctx->setMgf(ctx->m_rsa, static_cast<digest::IDigest*>(ctx->m_mgf));
    }

    ctx->status = ctx->encryptPublicOaepFn(
        ctx->m_rsa, pText, textSize, label, labelSize, pSeed, pEncText);

    if (ctx->status.ok()) {
        return err;
    } else {
        // fetching the module error
        Uint16 module_error = (ctx->status.code() >> 16) & 0xff;
        return (alcp::rsa::ErrorCode::eNotPermitted == module_error)
                   ? ALC_ERROR_NOT_PERMITTED
                   : ALC_ERROR_GENERIC;
    }
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
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pEncText, err);
    ALCP_BAD_PTR_ERR_RET(pText, err);
    ALCP_BAD_PTR_ERR_RET(label, err);
    ALCP_BAD_PTR_ERR_RET(textSize, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    ctx->status = ctx->decryptPrivateOaepFn(
        ctx->m_rsa, pEncText, encSize, label, labelSize, pText, *textSize);

    if (ctx->status.ok()) {
        return err;
    } else {
        // fetching the module error
        Uint16 module_error = (ctx->status.code() >> 16) & 0xff;
        return (alcp::rsa::ErrorCode::eNotPermitted == module_error)
                   ? ALC_ERROR_NOT_PERMITTED
                   : ALC_ERROR_GENERIC;
    }
}

Uint64
alcp_rsa_get_key_size(const alc_rsa_handle_p pRsaHandle)
{
    assert(pRsaHandle != nullptr);
    if (pRsaHandle == nullptr) {
        return 0;
    }
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    return ctx->getKeySize(ctx->m_rsa);
}

alc_error_t
alcp_rsa_get_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64*                publicKey,
                       Uint8*                 pModulus,
                       Uint64                 keySize)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pModulus, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    rsa::RsaPublicKey pub_key;
    pub_key.modulus = pModulus;
    pub_key.size    = keySize;

    ctx->status = ctx->getPublickey(ctx->m_rsa, pub_key);

    *publicKey = pub_key.public_exponent;

    return ctx->status.ok() ? err : ALC_ERROR_GENERIC;
}

alc_error_t
alcp_rsa_set_publickey(const alc_rsa_handle_p pRsaHandle,
                       Uint64                 exponent,
                       const Uint8*           pModulus,
                       Uint64                 keySize)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);
    ALCP_BAD_PTR_ERR_RET(pModulus, err);

    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    ctx->status = ctx->setPublicKey(ctx->m_rsa, exponent, pModulus, keySize);

    return ctx->status.ok() ? err : ALC_ERROR_GENERIC;
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

    ctx->status = ctx->setPrivateKey(ctx->m_rsa, dp, dq, p, q, qinv, mod, size);

    return ctx->status.ok() ? err : ALC_ERROR_GENERIC;
}

void
alcp_rsa_finish(const alc_rsa_handle_p pRsaHandle)
{
    auto ctx = static_cast<rsa::Context*>(pRsaHandle->context);
    ctx->finish(ctx->m_rsa);
    ctx->~Context();

    delete static_cast<const alcp::digest::IDigest*>(ctx->m_digest);
    ctx->m_digest = nullptr;

    delete static_cast<const alcp::digest::IDigest*>(ctx->m_mgf);
    ctx->m_mgf = nullptr;
}

alc_error_t
alcp_rsa_error(const alc_rsa_handle_p pRsaHandle, Uint8* buf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pRsaHandle, err);
    ALCP_BAD_PTR_ERR_RET(pRsaHandle->context, err);

    auto p_ctx = static_cast<rsa::Context*>(pRsaHandle->context);

    String message = String(p_ctx->status.message());

    int size_to_copy = size > message.size() ? message.size() : size;
    snprintf((char*)buf, size_to_copy, "%s", message.c_str());

    return err;
}

EXTERN_C_END
