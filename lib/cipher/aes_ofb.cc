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

#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "cipher/vaes.hh"

namespace alcp::cipher {
alc_error_t
Ofb::decrypt(const uint8_t* pCipherText,
             uint8_t*       pPlainText,
             uint64_t       len,
             const uint8_t* pIv) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (Cipher::isVaesAvailable()) {
        // err = vaes::DecryptOfb(
        err = aesni::DecryptOfb(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }
    if (Cipher::isAesniAvailable()) {
        err = aesni::DecryptOfb(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    // dispatch to REF

    return err;
}

alc_error_t
Ofb::encrypt(const uint8_t* pPlainText,
             uint8_t*       pCipherText,
             uint64_t       len,
             const uint8_t* pIv) const
{
    alc_error_t err = ALC_ERROR_NONE;

    if (Cipher::isVaesAvailable()) {
        // err = vaes::EncryptOfb(
        err = aesni::EncryptOfb(
            pPlainText, pCipherText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }
    if (Cipher::isAesniAvailable()) {
        err = aesni::EncryptOfb(
            pPlainText, pCipherText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    // dispatch to REF

    return err;
}
} // namespace alcp::cipher
