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

#include <immintrin.h>

#include "alcp/error.h"

#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "cipher/vaes.hh"

namespace alcp::cipher {

static alc_error_t
__aes_wrapper_decrypt(const Cipher&  rCipher,
                      const uint8_t* pCipherText,
                      uint8_t*       pPlainText,
                      uint64_t       len,
                      const uint8_t* pIv)
{
    /*
     * We can safely assume all pointers are checked before coming here ..
     */
    alc_error_t e  = ALC_ERROR_NONE;
    const Aes&  ap = static_cast<const Aes&>(rCipher);

    e = ap.decrypt(pCipherText, pPlainText, len, pIv);

    return e;
}

static alc_error_t
__aes_wrapper_encrypt(const Cipher&  rCipher,
                      const uint8_t* pPlainText,
                      uint8_t*       pCipherText,
                      uint64_t       len,
                      const uint8_t* pIv)
{
    /*
     * We can safely assume all pointers are checked before coming here ..
     */
    alc_error_t e = ALC_ERROR_NONE;

    const Aes& ap = static_cast<const Aes&>(rCipher);

    e = ap.encrypt(pPlainText, pCipherText, len, pIv);

    return e;
}

Cipher*
AesBuilder::Build(const alc_aes_info_t& aesInfo,
                  const alc_key_info_t& keyInfo,
                  Handle&               rHandle,
                  alc_error_t&          err)
{
    Cipher* cp = nullptr;

    switch (aesInfo.mode) {
        case ALC_AES_MODE_CFB: {
            Cfb::isSupported(aesInfo, keyInfo);
            auto algo = new Cfb(aesInfo, keyInfo);
            cp        = algo;
        } break;

        default:
            Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
            break;
    }

    if (!Error::isError(err)) {
        rHandle.m_cipher        = cp;
        rHandle.wrapper.decrypt = __aes_wrapper_decrypt;
        rHandle.wrapper.encrypt = __aes_wrapper_encrypt;
    }

    return cp;
}

void
Rijndael::expandKeys(const uint8_t* pUserKey,
                     uint8_t*       pEncKey,
                     uint8_t*       pDecKey)
{
    uint8_t dummy_key[Rijndael::cMaxKeySizeBytes] = { 0 };

    const uint8_t* key = pUserKey ? pUserKey : &dummy_key[0];

    if (isVaesAvailable()) {
        vaes::ExpandKeys(key, pEncKey, pDecKey, m_nrounds);
        return;
    }

    if (isAesniAvailable()) {
        aesni::ExpandKeys(key, pEncKey, pDecKey, m_nrounds);
        return;
    }

    /* Default Key expansion */
}
} // namespace alcp::cipher
