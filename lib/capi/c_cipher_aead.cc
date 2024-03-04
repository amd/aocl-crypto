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

#include <iostream> /* TODO: remove after debug messages */

#include "alcp/alcp.hh"
#include "alcp/cipher.h"

#include "alcp/capi/cipher/builder.hh"
#include "alcp/capi/defs.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_cipher_aead_context_size(const alc_cipher_aead_info_p pCipherInfo)
{
    ALCP_BAD_PTR_ERR_RET(pCipherInfo, err);
    Uint64 size = sizeof(cipher::Context);
    return size;
}

alc_error_t
alcp_cipher_aead_request(const alc_cipher_mode_t cipherMode,
                         const Uint64            keyLen,
                         alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_ZERO_LEN_ERR_RET(keyLen, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    new (ctx) cipher::Context;

    err = cipher::CipherAeadBuilder::Build(cipherMode, keyLen, *ctx);

    return err;
}

alc_error_t
alcp_cipher_aead_encrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pPlainText,
                         Uint8*                    pCipherText,
                         Uint64                    len,
                         const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);
    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify Encrypt to return Status and assign to context status
    err = ctx->encrypt(ctx->m_cipher, pPlainText, pCipherText, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_aead_encrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len,
                                const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);
    // Sometimes Encrypt needs to be called with 0 length
    // ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify encryptUpdate to return Status and assign to context
    // status
    err = ctx->encryptUpdate(ctx->m_cipher, pInput, pOutput, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_aead_decrypt(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pCipherText,
                         Uint8*                    pPlainText,
                         Uint64                    len,
                         const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);
    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify decrypt to return Status and assign to context status
    err = ctx->decrypt(ctx->m_cipher, pCipherText, pPlainText, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_aead_decrypt_update(const alc_cipher_handle_p pCipherHandle,
                                const Uint8*              pInput,
                                Uint8*                    pOutput,
                                Uint64                    len,
                                const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);
    // Sometimes Encrypt needs to be called with 0 length
    // ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->decryptUpdate(ctx->m_cipher, pInput, pOutput, len, pIv);

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

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // init can be called to setKey or setIv or both
    if ((pKey != NULL && keyLen != 0) || (pIv != NULL && ivLen != 0)) {
        err = ctx->init(ctx->m_cipher, pKey, keyLen, pIv, ivLen);
    }

    return err;
}

alc_error_t
alcp_cipher_aead_set_aad(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pInput,
                         Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);

    // ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify setAad to return Status and assign to context status
    err = ctx->setAad(ctx->m_cipher, pInput, len);

    return err;
}

alc_error_t
alcp_cipher_aead_get_tag(const alc_cipher_handle_p pCipherHandle,
                         Uint8*                    pOutput,
                         Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    ALCP_BAD_PTR_ERR_RET(pOutput, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify getTag to return Status and assign to context status
    err = ctx->getTag(ctx->m_cipher, pOutput, len);

    return err;
}

alc_error_t
alcp_cipher_aead_set_tag_length(const alc_cipher_handle_p pCipherHandle,
                                Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify setTagLength to return Status and assign to context
    // status
    err = ctx->setTagLength(ctx->m_cipher, len);

    return err;
}

void
alcp_cipher_aead_finish(const alc_cipher_handle_p pCipherHandle)
{
    if (nullptr == pCipherHandle)
        return;
    if (pCipherHandle->ch_context == nullptr) {
        return;
    }

    cipher::Context* ctx =
        reinterpret_cast<cipher::Context*>(pCipherHandle->ch_context);

    ctx->finish(ctx->m_cipher);

    ctx->~Context();
}

alc_error_t
alcp_cipher_aead_error(alc_cipher_handle_p pCipherHandle,
                       Uint8*              pBuff,
                       Uint64              size)
{
    alc_error_t err = ALC_ERROR_NONE;
    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    auto p_ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    String message = String(p_ctx->status.message());

    int size_to_copy = size > message.size() ? message.size() : size;
    snprintf((char*)pBuff, size_to_copy, "%s", message.c_str());

    return err;
}

EXTERN_C_END
