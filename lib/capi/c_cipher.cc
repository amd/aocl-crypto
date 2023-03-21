/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/capi/defs.hh"
#include "capi/cipher/builder.hh"
#include "cipher.hh"

using namespace alcp;

EXTERN_C_BEGIN

alc_error_t
alcp_cipher_supported(const alc_cipher_info_p pCipherInfo)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* TODO: Check for pointer validity */

    // err = cipher::FindCipher(*pCipherInfo).isSupported();

    // if (Error::isError(err))
    //    goto outa;

    // outa:
    return err;
}

Uint64
alcp_cipher_context_size(const alc_cipher_info_p pCipherInfo)
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
alcp_cipher_request(const alc_cipher_info_p pCipherInfo,
                    alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherInfo, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

    if (pCipherInfo->ci_algo_info.ai_mode == ALC_AES_MODE_XTS) {
        auto tweak_key = pCipherInfo->ci_algo_info.ai_xts.xi_tweak_key;
        if (tweak_key == nullptr
            || (tweak_key->len != 128 && tweak_key->len != 256)
            || (tweak_key->len != pCipherInfo->ci_key_info.len)) {
            return ALC_ERROR_INVALID_ARG;
        }
        if (validateKeys(tweak_key->key,
                         pCipherInfo->ci_key_info.key,
                         pCipherInfo->ci_key_info.len)) {
            return ALC_ERROR_DUPLICATE_KEY;
        }
    }

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = cipher::CipherBuilder::Build(*pCipherInfo, *ctx);

    return err;
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    len,
                    const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);
    err      = ctx->encrypt(ctx->m_cipher, pPlainText, pCipherText, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_encrypt_update(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pInput,
                           Uint8*                    pOutput,
                           Uint64                    len,
                           const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);

    // Sometimes Encrypt needs to be called with 0 length
    // ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->encryptUpdate(ctx->m_cipher, pInput, pOutput, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    len,
                    const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pPlainText, err);
    ALCP_BAD_PTR_ERR_RET(pCipherText, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->decrypt(ctx->m_cipher, pCipherText, pPlainText, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_decrypt_update(const alc_cipher_handle_p pCipherHandle,
                           const Uint8*              pInput,
                           Uint8*                    pOutput,
                           Uint64                    len,
                           const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);

    // Sometimes Encrypt needs to be called with 0 length
    // ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->decryptUpdate(ctx->m_cipher, pInput, pOutput, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_set_iv(const alc_cipher_handle_p pCipherHandle,
                   Uint64                    len,
                   const Uint8*              pIv)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pIv, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->setIv(ctx->m_cipher, len, pIv);

    return err;
}

alc_error_t
alcp_cipher_set_aad(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pInput,
                    Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pInput, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->setAad(ctx->m_cipher, pInput, len);

    return err;
}

alc_error_t
alcp_cipher_get_tag(const alc_cipher_handle_p pCipherHandle,
                    Uint8*                    pOutput,
                    Uint64                    len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pOutput, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->getTag(ctx->m_cipher, pOutput, len);

    return err;
}

alc_error_t
alcp_cipher_set_tag_length(const alc_cipher_handle_p pCipherHandle, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);

    ALCP_ZERO_LEN_ERR_RET(len, err);

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->setTagLength(ctx->m_cipher, len);

    return err;
}

void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle)
{
    if (nullptr == pCipherHandle)
        return;

    cipher::Context* ctx =
        reinterpret_cast<cipher::Context*>(pCipherHandle->ch_context);

    ctx->finish(ctx->m_cipher);
}

EXTERN_C_END
