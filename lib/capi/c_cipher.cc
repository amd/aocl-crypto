/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher.h"
#include "alcp/macros.h"

#include "cipher.hh"
#include "defs.hh"
#include "error.hh"

#include "capi/cipher/builder.hh"

using namespace alcp;

EXTERN_C_BEGIN

alc_error_t
alcp_cipher_supported(const alc_cipher_info_p pCipherInfo)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* TODO: Check for pointer validity */

    // err = cipher::FindCipher(*pCipherInfo).isSupported();

    if (Error::isError(err))
        goto outa;

outa:
    return err;
}

Uint64
alcp_cipher_context_size(const alc_cipher_info_p pCipherInfo)
{
    Uint64 size = sizeof(cipher::Context);
    return size;
}

alc_error_t
alcp_cipher_request(const alc_cipher_info_p pCipherInfo,
                    alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t err = ALC_ERROR_NONE;

    ALCP_BAD_PTR_ERR_RET(pCipherHandle, err);
    ALCP_BAD_PTR_ERR_RET(pCipherInfo, err);
    ALCP_BAD_PTR_ERR_RET(pCipherHandle->ch_context, err);

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

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->encrypt(ctx->m_cipher, pPlainText, pCipherText, len, pIv);

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

    auto ctx = static_cast<cipher::Context*>(pCipherHandle->ch_context);

    err = ctx->decrypt(ctx->m_cipher, pCipherText, pPlainText, len, pIv);

    return err;
}

/**
 * \notes
 */
void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle)
{
    /* TODO: Check for pointer validity */
    cipher::Context* ctx =
        reinterpret_cast<cipher::Context*>(pCipherHandle->ch_context);

    // pCipherHandle will be freed by the application
    ctx->finish(ctx->m_cipher);
}

EXTERN_C_END
