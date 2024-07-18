/*
 * Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/cipher_error.hh"

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aesni.hh"

namespace alcp::cipher {

alc_error_t
Aes::setKey(const Uint8* pKey, const Uint64 keyLen)
{
    alc_error_t e = ALC_ERROR_NONE;

    // keyLen should be checked if its same as keyLen used during create call
    if (keyLen != m_keyLen_in_bytes_aes * 8) {
        printf("\n setKey failed, keySize invalid");
        return ALC_ERROR_INVALID_SIZE;
    }

    Rijndael::initRijndael(pKey, keyLen);
    getKey();
    m_isKeySet_aes = 1; // FIXME: use enum instead
    return e;
}

alc_error_t
Aes::setIv(const Uint8* pIv, const Uint64 ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;
    m_ivLen_aes   = ivLen;
    if ((ivLen == 0) || (ivLen > m_ivLen_max) || (ivLen < m_ivLen_min)) {
        return ALC_ERROR_INVALID_SIZE;
    }

    if (pIv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    // copy IV and set IvLen
    e = utils::SecureCopy<Uint8>(
        m_iv_aes, MAX_CIPHER_IV_SIZE, pIv, ivLen); // copy iv to aes
    if (e != ALC_ERROR_NONE) {
        return e;
    }
    m_pIv_aes = m_iv_aes;

    m_ivLen_aes   = ivLen;
    m_ivState_aes = 1;

    return e;
}

alc_error_t
Aes::init(const Uint8* pKey,
          const Uint64 keyLen,
          const Uint8* pIv,
          const Uint64 ivLen)
{

    alc_error_t err = ALC_ERROR_NONE;

    if (pKey != NULL && keyLen != 0) {
        err = setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    if (pIv != NULL && ivLen != 0) {
        err = setIv(pIv, ivLen);
    }

    return err;
}

#if 0
Status
Aes::setKey(const Uint8* pUserKey, Uint64 len)
{
    // Already Expanded in Rijndael class, we just need to transpose
    Rijndael::setKey(pUserKey, len);

    return StatusOk();
}
#endif

Status
Aes::setMode(alc_cipher_mode_t mode)
{
    if ((mode <= ALC_AES_MODE_CBC) || (mode >= ALC_AES_MODE_MAX)) {
        return status::InvalidMode("aes mode not supported");
    }
    m_mode = mode;
    return StatusOk();
}

} // namespace alcp::cipher
