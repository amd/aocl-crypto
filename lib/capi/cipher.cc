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

#include "alcp/macros.h"

#include "algorithm.hh"
#include "cipher.hh"
#include "cipher/aes.hh" /* for cipher::Aes */
#include "error.hh"
#include "module.hh"
#include "modulemanager.hh"

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

uint64_t
alcp_cipher_context_size(const alc_cipher_info_p pCipherInfo)
{
    uint64_t size = sizeof(cipher::Handle);
    return size;
}

alc_error_t
alcp_cipher_request(const alc_cipher_info_p pCipherInfo,
                    alc_cipher_handle_p     pCipherHandle)
{
    alc_error_t e = ALC_ERROR_NONE;

    /* TODO: Check pCipherInfo for pointer validity */

    /* TODO: Check pCipherHandle  */

    auto cipher_context =
        cipher::CipherBuilder::Build(*pCipherInfo, pCipherHandle, e);
    if (Error::isError(e)) {
        return e;
    }

    pCipherHandle->context = cipher_context;

    return e;
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pPlainText,
                    uint8_t*                  pCipherText,
                    uint64_t                  len)
{
    /* TODO: Check for pointer validity */
    auto cp = reinterpret_cast<Cipher*>(&pCipherHandle->context);

    // Error& e = cp->encrypt(plaintxt, ciphertxt, len);

    return ALC_ERROR_NONE;
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pCipherText,
                    uint8_t*                  pPlainText,
                    uint64_t                  len,
                    const uint8_t*            pKey,
                    const uint8_t*            pIv)
{

    /* TODO: Check for pointer validity */
    cipher::Handle* h =
        reinterpret_cast<cipher::Handle*>(pCipherHandle->context);

    return h->wrapper.decrypt(
        h->m_cipher, pCipherText, pPlainText, len, pKey, pIv);
}

void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle)
{
    auto cp = reinterpret_cast<Cipher*>(pCipherHandle->context);
    delete cp;
}

EXTERN_C_END
