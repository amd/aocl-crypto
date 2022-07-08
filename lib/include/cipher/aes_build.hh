/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#ifndef _CIPHER_AES_BUILD_HH
#define _CIPHER_AES_BUILD_HH 2

#include "capi/cipher/builder.hh"

#include "cipher.hh"
#include "cipher/aes.hh"
#include "cipher/aes_cfb.hh"

namespace alcp::cipher {

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapper(const void*    rCipher,
              const uint8_t* pSrc,
              uint8_t*       pDest,
              uint64_t       len,
              const uint8_t* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<const CIPHERMODE*>(rCipher);

    if (encrypt)
        e = ap->encrypt(pSrc, pDest, len, pIv);
    else
        e = ap->decrypt(pSrc, pDest, len, pIv);

    return e;
}

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapperUpdate(void*          rCipher,
                    const uint8_t* pSrc,
                    uint8_t*       pDest,
                    uint64_t       len,
                    const uint8_t* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    if (encrypt)
        e = ap->encryptUpdate(pSrc, pDest, len, pIv);
    else
        e = ap->decryptUpdate(pSrc, pDest, len, pIv);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_dtor(const void* rCipher)
{
    alc_error_t e  = ALC_ERROR_NONE;
    auto        ap = static_cast<const CIPHERMODE*>(rCipher);
    delete ap;
    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__build_aes(const alc_aes_info_t& aesInfo,
            const alc_key_info_t& keyInfo,
            Context&              ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!Cfb::isSupported(aesInfo, keyInfo))
        err = ALC_ERROR_NOT_SUPPORTED;

    if (!Error::isError(err)) {
        auto algo         = new CIPHERMODE(aesInfo, keyInfo);
        ctx.m_cipher      = static_cast<void*>(algo);
        ctx.decrypt       = __aes_wrapper<CIPHERMODE, false>;
        ctx.encrypt       = __aes_wrapper<CIPHERMODE, true>;
        ctx.decryptUpdate = __aes_wrapperUpdate<CIPHERMODE, false>;
        ctx.encryptUpdate = __aes_wrapperUpdate<CIPHERMODE, true>;
        ctx.finish        = __aes_dtor<CIPHERMODE>;
    }

    return err;
}

class AesBuilder
{
  public:
    static alc_error_t Build(const alc_aes_info_t& aesInfo,
                             const alc_key_info_t& keyInfo,
                             Context&              ctx);
};

alc_error_t
AesBuilder::Build(const alc_aes_info_t& aesInfo,
                  const alc_key_info_t& keyInfo,
                  Context&              ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (aesInfo.ai_mode) {
        case ALC_AES_MODE_CFB:
            err = __build_aes<Cfb>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_CBC:
            err = __build_aes<Cbc>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_OFB:
            err = __build_aes<Ofb>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_CTR:
            err = __build_aes<Ctr>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_GCM:
            err = __build_aes<Gcm>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_XTS:
            err = __build_aes<Xts>(aesInfo, keyInfo, ctx);
            break;

        default:
            Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
            break;
    }

    return err;
}

} // namespace alcp::cipher

#endif /* _CIPHER_AES_BUILD_HH */
