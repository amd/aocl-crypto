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
    /* TODO: Check for pointer validity */
    ModuleManager& mm  = ModuleManager::getInstance();
    alc_error_t    err = ALC_ERROR_NONE;

    /* TODO: Check for pointer validity */

    // Module& mod = mm.findCipher(&mod_c_info, err);

    if (Error::isError(err))
        goto outa;

outa:
    return err;
}

uint64_t
alcp_cipher_context_size(const alc_cipher_info_p pCipherInfo)
{
    ModuleManager& mm   = ModuleManager::getInstance();
    uint64_t       size = 100; /* FIXME: 100 used for testing purpose */
    alc_error_t    e;

    /* TODO: Check cinfo for pointer validity */

    // Module& mod = mm.findModule(&mod_c_info, e);
    if (Error::isError(e))
        return 0;

    return size;
}

alc_error_t
alcp_cipher_request(const alc_cipher_info_p pCipherInfo,
                    alc_cipher_handle_p     pCipherHandle)
{
    ModuleManager& mm = ModuleManager::getInstance();
    alc_error_t    e;

    /* TODO: Check cinfo for pointer validity */

    /* TODO: Check ctx  */

    // Module& mod = mm.findCipher(pCipherInfo, e);
    switch (pCipherInfo->cipher_type) {
        case ALC_CIPHER_TYPE_AES:
            auto aes_context = cipher::AesBuilder::Build(pCipherInfo, e);
            if (Error::isError(e)) {
                return e;
            }

            pCipherHandle->context = aes_context;
            break;
    }

    if (Error::isError(e)) {
        std::cout << "Some error" << __func__ << std::endl;
        return e;
    }

    // pCipherHandle->context = static_cast<Cipher&>(mod)

    return ALC_ERROR_NONE;
}

alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pPlainText,
                    uint8_t*                  pCipherText,
                    uint64_t                  len)
{
    /* TODO: Check for pointer validity */
    const alcp::Cipher* cp = reinterpret_cast<const Cipher*>(pCipherHandle);

    // Error& e = cp->encrypt(plaintxt, ciphertxt, len);

    return ALC_ERROR_NONE;
}

alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const uint8_t*            pCipherText,
                    uint8_t*                  pPlainText,
                    uint64_t                  len)
{
    /* TODO: Check for pointer validity */

    const Cipher* cp = reinterpret_cast<const Cipher*>(pCipherHandle->context);

    // Error& e = cp->decrypt(ciphertxt, plaintxt, len);

    return ALC_ERROR_NONE;
}

void
alcp_cipher_finish(const alc_cipher_handle_p context)
{}

EXTERN_C_END
