/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/capi/cipher/ctx.hh"
#include "alcp/capi/defs.hh"

using namespace alcp::cipher;

EXTERN_C_BEGIN

Uint64
alcp_cipher_context_size()
{
    Uint64 size = sizeof(Context);
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CtxSize %6ld", size);
#endif
    return size;
}

bool
validateKeys(const Uint8* tweakKey, const Uint8* encKey, Uint32 len)
{
    for (Uint32 i = 0; i < len / 8; i++) {
        if (tweakKey[i] != encKey[i]) {
            return false;
        }
    }
    return true;
}

// temporary duplicate, c_cipher.cc and c_cipher_aead.cc to be unified.
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
getCipherMode(const alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_CBC:
            return CipherMode::eAesCBC;
        case ALC_AES_MODE_OFB:
            return CipherMode::eAesOFB;
        case ALC_AES_MODE_CTR:
            return CipherMode::eAesCTR;
        case ALC_AES_MODE_CFB:
            return CipherMode::eAesCFB;
        case ALC_AES_MODE_XTS:
            return CipherMode::eAesXTS;
        case ALC_CHACHA20:
            return CipherMode::eCHACHA20;
        default:
            return CipherMode::eCipherModeNone;
    }
}

alc_error_t
alcp_cipher_request(const alc_cipher_mode_t mode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeyLen %6ld", keyLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    new (ctx) Context;

    ALCP_ZERO_LEN_ERR_RET(keyLen, err);

    auto alcpCipher       = new CipherFactory<iCipher>;
    ctx->m_cipher_factory = static_cast<void*>(alcpCipher);

    auto aead = alcpCipher->create(getCipherMode(mode), getKeyLen(keyLen));

    if (aead == nullptr) {
        printf("\n cipher algo create failed");
        return ALC_ERROR_GENERIC;
    }
    ctx->m_cipher = static_cast<void*>(aead);

    return err;
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    len)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "PTLen %6ld", len);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);
    auto i = static_cast<iCipher*>(ctx->m_cipher);
    err    = i->encrypt(pPlainText, pCipherText, len);

    return err;
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    len)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "CTLen %6ld", len);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipher*>(ctx->m_cipher);
    err    = i->decrypt(pCipherText, pPlainText, len);

    return err;
}

alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
                 const Uint8*              pKey,
                 Uint64                    keyLen,
                 const Uint8*              pIv,
                 Uint64                    ivLen)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_DBG, "KeyLen %6ld,IVLen %6ld", keyLen, ivLen);
#endif
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return ALC_ERROR_BAD_STATE;
    }
    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);

    auto i = static_cast<iCipher*>(ctx->m_cipher);

    // init can be called to setKey or setIv or both
    if ((pKey != NULL && keyLen != 0) || (pIv != NULL && ivLen != 0)) {
        err = i->init(pKey, keyLen, pIv, ivLen);
    } else {
        err = ALC_ERROR_INVALID_ARG;
    }
    return err;
}

void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle)
{
#ifdef ALCP_ENABLE_DEBUG_LOGGING
    ALCP_DEBUG_LOG(LOG_INFO);
#endif
    if (pCipherHandle == nullptr || pCipherHandle->ch_context == nullptr)
        return;

    auto ctx = static_cast<Context*>(pCipherHandle->ch_context);
    if (ctx->destructed == 1) {
        return;
    }
    auto alcpCipher =
        static_cast<CipherFactory<iCipher>*>(ctx->m_cipher_factory);

    if (alcpCipher != nullptr) {
        delete alcpCipher;
    }

    ctx->~Context();
}

EXTERN_C_END
