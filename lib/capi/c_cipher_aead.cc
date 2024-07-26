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
#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/cipher_aead.h"

#include "alcp/capi/cipher/ctx.hh"
#include "alcp/capi/defs.hh"

using namespace alcp::cipher;

EXTERN_C_BEGIN

Uint64
alcp_cipher_aead_context_size()
{
    Uint64 size = sizeof(Context);
    return size;
}

static CipherKeyLen
getKeyLen(const Uint64 keyLen)
{
    CipherKeyLen key_size = CipherKeyLen::eKey128Bit;
    if (keyLen == 192) {
        key_size = CipherKeyLen::eKey192Bit;
    } else if (keyLen == 256) {
        key_size = CipherKeyLen::eKey256Bit;
    }
    return key_size;
}

static CipherMode
getCipherAeadMode(const alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_GCM:
            return CipherMode::eAesGCM;
        case ALC_AES_MODE_CCM:
            return CipherMode::eAesCCM;
        case ALC_AES_MODE_SIV:
            return CipherMode::eAesSIV;
        case ALC_CHACHA20_POLY1305:
            return CipherMode::eCHACHA20_POLY1305;
        default:
            return CipherMode::eCipherModeNone;
    }
}

alc_error_t
alcp_cipher_aead_request(const alc_cipher_mode_t mode,
                         const Uint64            keyLen,
                         alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    new (ctx) Context;

    ALCP_ZERO_LEN_ERR_RET(keyLen, err);

    auto alcpCipher       = new CipherFactory<iCipherAead>;
    ctx->m_cipher_factory = static_cast<void*>(alcpCipher);

    auto aead = alcpCipher->create(getCipherAeadMode(mode), getKeyLen(keyLen));
    if (aead == nullptr) {
        printf("\n cipher algo create failed");
        return ALC_ERROR_GENERIC;
    }
    ctx->m_cipher = static_cast<void*>(aead);

    return err;
}

alc_error_t
alcp_cipher_aead_encrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    err = i->encrypt(pInput, pOutput, len);

    return err;
}

alc_error_t
alcp_cipher_aead_decrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint8*                    pOutput,
                         Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);
    // ALCP_BAD_PTR_ERR_RET(i->decrypt, err);
    err = i->decrypt(pInput, pOutput, len);

    return err;
}

// FIXME: alcp_cipher_init can be reused here as well.
alc_error_t
alcp_cipher_aead_init(const alc_cipher_handle_p pCipherHandle,
                      const Uint8*              pKey,
                      Uint64                    keyLen,
                      const Uint8*              pIv,
                      Uint64                    ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);
    // ALCP_BAD_PTR_ERR_RET(i->init, err);
    if ((pKey != NULL && keyLen != 0) || (pIv != NULL && ivLen != 0)) {
        err = i->init(pKey, keyLen, pIv, ivLen);
    }

    return err;
}

alc_error_t
alcp_cipher_aead_set_aad(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint64                    aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (aadLen == 0) {
        return err;
    }

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    err = i->setAad(pInput, aadLen);

    return err;
}

alc_error_t
alcp_cipher_aead_get_tag(const alc_cipher_handle_p pCipherHandle,
                         Uint8*                    pOutput,
                         Uint64                    tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    ALCP_BAD_PTR_ERR_RET(pOutput, err);

    ALCP_ZERO_LEN_ERR_RET(tagLen, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);

    err = i->getTag(pOutput, tagLen);

    return err;
}

alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    ALCP_ZERO_LEN_ERR_RET(tagLen, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipherAead*>(ctx->m_cipher);
    // ALCP_BAD_PTR_ERR_RET(i->setTagLength, err);
    err = i->setTagLength(tagLen);

    return err;
}

alc_error_t
alcp_cipher_aead_set_ccm_plaintext_length(
    const alc_cipher_handle_p pCipherHandle, Uint64 plaintextLength)
{
#ifdef CCM_MULTI_UPDATE
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ctx->setPlainTextLength, err);
    err = ctx->setPlainTextLength(ctx, plaintextLength);

    return err;
#else
    printf("Plaintext length cannot be set in advance without compiling with "
           "multi update support enabled\n");
    return ALC_ERROR_NOT_PERMITTED;
#endif
}

void
alcp_cipher_aead_finish(const alc_cipher_handle_p pCipherHandle)
{
    if (nullptr == pCipherHandle)
        return;
    if (pCipherHandle->ch_context == nullptr) {
        return;
    }

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return;
    }
    auto alcpCipher =
        static_cast<CipherFactory<iCipherAead>*>(ctx->m_cipher_factory);

    if (alcpCipher != nullptr) {
        delete alcpCipher;
    }

    if (ctx->destructed == 1) {
        return;
    }
    // ctx->finish(ctx);

    ctx->~Context();
}

EXTERN_C_END
