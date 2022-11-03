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

#include <type_traits> /* for is_same_v<> */

namespace alcp::cipher {

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapper(const void*  rCipher,
              const Uint8* pSrc,
              Uint8*       pDest,
              Uint64       len,
              const Uint8* pIv)
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
__aes_wrapperUpdate(void*        rCipher,
                    const Uint8* pSrc,
                    Uint8*       pDest,
                    Uint64       len,
                    const Uint8* pIv)
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
__aes_wrapperSetIv(void* rCipher, Uint64 len, const Uint8* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->setIv(len, pIv);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_wrapperGetTag(void* rCipher, Uint8* pTag, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->getTag(pTag, len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_wrapperSetTagLength(void* rCipher, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->setTagLength(len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_wrapperSetAad(void* rCipher, const Uint8* pAad, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->setAad(pAad, len);

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
__build_aes(const alc_cipher_algo_info_t& aesInfo,
            const alc_key_info_t&         keyInfo,
            Context&                      ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!Error::isError(err)) {
        auto algo    = new CIPHERMODE(aesInfo, keyInfo);
        ctx.m_cipher = static_cast<void*>(algo);
        ctx.decrypt  = __aes_wrapper<CIPHERMODE, false>;
        ctx.encrypt  = __aes_wrapper<CIPHERMODE, true>;
        if constexpr (std::is_same_v<CIPHERMODE, Gcm>) {
            ctx.decryptUpdate = __aes_wrapperUpdate<Gcm, false>;
            ctx.encryptUpdate = __aes_wrapperUpdate<Gcm, true>;
            ctx.setAad        = __aes_wrapperSetAad<Gcm>;
            ctx.setIv         = __aes_wrapperSetIv<Gcm>;
            ctx.getTag        = __aes_wrapperGetTag<Gcm>;
        } else if constexpr (std::is_same_v<CIPHERMODE, Ccm>) {
            ctx.decryptUpdate = __aes_wrapperUpdate<Ccm, false>;
            ctx.encryptUpdate = __aes_wrapperUpdate<Ccm, true>;
            ctx.setAad        = __aes_wrapperSetAad<Ccm>;
            ctx.setIv         = __aes_wrapperSetIv<Ccm>;
            ctx.getTag        = __aes_wrapperGetTag<Ccm>;
            ctx.setTagLength  = __aes_wrapperSetTagLength<Ccm>;
        }
        ctx.finish = __aes_dtor<CIPHERMODE>;
    }

    return err;
}

class AesBuilder
{
  public:
    static alc_error_t Build(const alc_cipher_algo_info_t& aesInfo,
                             const alc_key_info_t&         keyInfo,
                             Context&                      ctx);
};

alc_error_t
AesBuilder::Build(const alc_cipher_algo_info_t& aesInfo,
                  const alc_key_info_t&         keyInfo,
                  Context&                      ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (aesInfo.ai_mode) {
        case ALC_AES_MODE_CFB: {
            if (!Cfb::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Cfb>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_CBC: {
            if (!Cbc::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Cbc>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_OFB: {
            if (!Ofb::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Ofb>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_CTR: {
            if (!Ctr::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Ctr>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_GCM: {
            if (!Gcm::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Gcm>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_XTS: {
            if (!Xts::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Xts>(aesInfo, keyInfo, ctx);
        } break;

        case ALC_AES_MODE_CCM: {
            if (!Ccm::isSupported(aesInfo, keyInfo)) {
                err = ALC_ERROR_NOT_SUPPORTED;
                return err;
            };
            err = __build_aes<Ccm>(aesInfo, keyInfo, ctx);
        } break;

        default:
            Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
            break;
    }

    return err;
}

} // namespace alcp::cipher

#endif /* _CIPHER_AES_BUILD_HH */
