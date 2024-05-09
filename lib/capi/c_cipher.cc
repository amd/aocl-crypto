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

#include <iostream> /* TODO: remove after debug messages */

#include "alcp/alcp.hh"
#include "alcp/cipher.h"

#include "alcp/capi/cipher/builder.hh"
#include "alcp/capi/defs.hh"

using namespace alcp;

EXTERN_C_BEGIN

Uint64
alcp_cipher_context_size()
{
    Uint64 size = sizeof(cipher::Context);
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

alc_error_t
alcp_cipher_request(const alc_cipher_mode_t cipherMode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_ZERO_LEN_ERR_RET(keyLen, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    new (ctx) cipher::Context;

    err = cipher::CipherBuilder::Build(cipherMode, keyLen, *ctx);

    // assign ctx cipher_data to handle
    pCipherHandle->alc_prov_cipher_data = &(ctx->m_prov_cipher_data);

    return err;
}

// is separate encrypt and encrypt init required?
alc_error_t
alcp_cipher_encrypt_init(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pKey,
                         Uint64                    keyLen,
                         const Uint8*              pIv,
                         Uint64                    ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    return err;
}

alc_error_t
alcp_cipher_decrypt_init(const alc_cipher_handle_p pCipherHandle,
                         const Uint8*              pKey,
                         Uint64                    keyLen,
                         const Uint8*              pIv,
                         Uint64                    ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    return err;
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->encrypt(ctx, pPlainText, pCipherText, len);

    return err;
}

alc_error_t
alcp_cipher_blocks_encrypt_xts(const alc_cipher_handle_p pCipherHandle,
                               const Uint8*              pPlainText,
                               Uint8*                    pCipherText,
                               Uint64                    currPlainTextLen,
                               Uint64                    startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);

    ALCP_ZERO_LEN_ERR_RET(currPlainTextLen, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->encryptBlocksXts(
        ctx, pPlainText, pCipherText, currPlainTextLen, startBlockNum);

    return err;
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    // FIXME: Modify decrypt to return Status and assign to context status
    err = ctx->decrypt(ctx, pCipherText, pPlainText, len);

    return err;
}

alc_error_t
alcp_cipher_blocks_decrypt_xts(const alc_cipher_handle_p pCipherHandle,
                               const Uint8*              pCipherText,
                               Uint8*                    pPlainText,
                               Uint64                    currCipherTextLen,
                               Uint64                    startBlockNum)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);

    ALCP_ZERO_LEN_ERR_RET(currCipherTextLen, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    ALCP_BAD_PTR_ERR_RET(ctx->m_cipher, err);
    ALCP_BAD_PTR_ERR_RET(ctx->decryptBlocksXts, err);
    err = ctx->decryptBlocksXts(
        ctx, pCipherText, pPlainText, currCipherTextLen, startBlockNum);

    return err;
}

alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
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
        err = ctx->init(ctx, pKey, keyLen, pIv, ivLen);
    } else {
        err = ALC_ERROR_INVALID_ARG;
    }
    return err;
}

void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle)
{
    if (pCipherHandle == nullptr || pCipherHandle->ch_context == nullptr)
        return;

    cipher::Context* ctx =
        reinterpret_cast<cipher::Context*>(pCipherHandle->ch_context);

    ctx->finish(ctx);

    ctx->~Context();
}
EXTERN_C_END
