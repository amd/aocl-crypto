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

// FIXME: need to choose a better name for setKey and setKey
alc_error_t
Aes::setKey(const Uint8* pKey, const Uint64 keyLen)
{
    alc_error_t e = ALC_ERROR_NONE;
    Rijndael::initRijndael(keyLen, pKey);
    getKey();
    m_isKeyset = true;
    return e;
}

alc_error_t
Aes::setIv(const Uint8* pIv, const Uint64 ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;
    if (ivLen <= 0) {
        return ALC_ERROR_INVALID_SIZE;
    }

    if (pIv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    // set IV and IvLen
    m_iv      = pIv;
    m_ivLen   = ivLen;
    m_isIvset = true;

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
