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
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_build.hh"
#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cfb.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/aes_gcm.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

#if 0
#include "cipher/aes_ccm.hh"
#include "cipher/aes_ctr.hh"
#include "cipher/aes_gcm.hh"
#include "cipher/aes_xts.hh"
#endif

#include <type_traits> /* for is_same_v<> */

namespace alcp::cipher {

enum class CpuCipherFeatures
{
    eAesni,
    eVaes256,
    eVaes512,
};

using Context = alcp::cipher::Context;
using namespace alcp::base;

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

CpuCipherFeatures
getCpuCipherfeature()
{
    CpuCipherFeatures cpu_feature =
        CpuCipherFeatures::eAesni; // default minimum arch feature
                                   // considered to be present.

    if (CpuId::cpuHasVaes()) {
        cpu_feature = CpuCipherFeatures::eVaes256;

        if (CpuId::cpuHasAvx512(utils::AVX512_F)
            && CpuId::cpuHasAvx512(utils::AVX512_DQ)
            && CpuId::cpuHasAvx512(utils::AVX512_BW)) {
            cpu_feature = CpuCipherFeatures::eVaes512;
        }
    }
    return cpu_feature;
}

template<typename CIPHERMODE>
void
_build_aes_cipher(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    auto algo    = new CIPHERMODE(pKey, keyLen);
    ctx.m_cipher = static_cast<void*>(algo);

    ctx.decrypt = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt = __aes_wrapper<CIPHERMODE, true>;

    ctx.finish = __aes_dtor<CIPHERMODE>;
}

template<typename CIPHERMODE>
static Status
__build_aes(const alc_cipher_algo_info_t& aesInfo,
            const alc_key_info_t&         keyInfo,
            Context&                      ctx)
{
    Status sts = StatusOk();

    auto algo    = new CIPHERMODE(aesInfo, keyInfo);
    ctx.m_cipher = static_cast<void*>(algo);
    ctx.decrypt  = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt  = __aes_wrapper<CIPHERMODE, true>;
    if constexpr (std::is_same_v<CIPHERMODE, Ccm>) {
        ctx.decryptUpdate = __aes_wrapperUpdate<Ccm, false>;
        ctx.encryptUpdate = __aes_wrapperUpdate<Ccm, true>;
        ctx.setAad        = __aes_wrapperSetAad<Ccm>;
        ctx.setIv         = __aes_wrapperSetIv<Ccm>;
        ctx.getTag        = __aes_wrapperGetTag<Ccm>;
        ctx.setTagLength  = __aes_wrapperSetTagLength<Ccm>;
    } else if constexpr (std::is_same_v<CIPHERMODE, Xts>) {
        ctx.setIv = __aes_wrapperSetIv<Xts>;
    } else if constexpr (std::is_same_v<CIPHERMODE, CmacSiv>) {
        ctx.setAad = __aes_wrapperSetAad<CmacSiv>;
        ctx.getTag = __aes_wrapperGetTag<CmacSiv>;
    }
    ctx.finish = __aes_dtor<CIPHERMODE>;

    return sts;
}

template<typename AEADMODE>
void
_build_aead(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    auto algo         = new AEADMODE(pKey, keyLen);
    ctx.m_cipher      = static_cast<void*>(algo);
    ctx.decryptUpdate = __aes_wrapperUpdate<AEADMODE, false>;
    ctx.encryptUpdate = __aes_wrapperUpdate<AEADMODE, true>;

    ctx.setAad = __aes_wrapperSetAad<AEADMODE>;
    ctx.setIv  = __aes_wrapperSetIv<AEADMODE>;
    ctx.getTag = __aes_wrapperGetTag<AEADMODE>;

    ctx.finish = __aes_dtor<AEADMODE>;
}

static Status
__build_GcmAead(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        /* FIXME: cipher request should fail invalid key length. At this
         * level only valid key length is passed.*/
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead<vaes512::GcmAEAD128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead<vaes512::GcmAEAD192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead<vaes512::GcmAEAD256>(pKey, keyLen, ctx);
        }
    } else {

        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead<aesni::GcmAEAD128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead<aesni::GcmAEAD192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead<aesni::GcmAEAD256>(pKey, keyLen, ctx);
        }
    }

    return sts;
}

static Status
__build_aesCtr(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aes_cipher<vaes512::Ctr128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aes_cipher<vaes512::Ctr192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aes_cipher<vaes512::Ctr256>(pKey, keyLen, ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aes_cipher<vaes::Ctr128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aes_cipher<vaes::Ctr192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aes_cipher<vaes::Ctr256>(pKey, keyLen, ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aes_cipher<aesni::Ctr128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aes_cipher<aesni::Ctr192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aes_cipher<aesni::Ctr256>(pKey, keyLen, ctx);
        }
    }

    return sts;
}

// FIXME: AesBuilder::Build  & CipherBuilder::Build to be modified similar to
// CTR
alc_error_t
AesBuilder::Build(const alc_cipher_algo_info_t& aesInfo,
                  const alc_key_info_t&         keyInfo,
                  Context&                      ctx)
{
    Status sts = StatusOk();

    switch (aesInfo.ai_mode) {
        case ALC_AES_MODE_CFB:
            if (Cfb::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Cfb>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_CBC:
            if (Cbc::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Cbc>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_OFB:
            if (Ofb::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Ofb>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_XTS:
            if (Xts::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Xts>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_CCM:
            if (Ccm::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Ccm>(aesInfo, keyInfo, ctx);
            break;
        case ALC_AES_MODE_SIV:
            sts = __build_aes<CmacSiv>(aesInfo, keyInfo, ctx);
            break;

        default:
            break;
    }
    return (alc_error_t)sts.code();
}

alc_error_t
CipherBuilder::Build(const alc_cipher_info_t& cipherInfo, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherInfo.ci_type) {
        case ALC_CIPHER_TYPE_AES:
            err = AesBuilder::Build(
                cipherInfo.ci_algo_info, cipherInfo.ci_key_info, ctx);
            break;

        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

alc_error_t
AesBuilder::Build(const alc_cipher_mode_t cipherMode,
                  const Uint8*            pKey,
                  const Uint32            keyLen,
                  Context&                ctx)
{
    Status sts = StatusOk();

    switch (cipherMode) {
        case ALC_AES_MODE_CTR:
            if (Ctr::isSupported(keyLen))
                sts = __build_aesCtr(pKey, keyLen, ctx);
            break;
            // FIXME: GCM, XTS, CCM should be moved to AeadBuilder.
        case ALC_AES_MODE_GCM:
            if (Gcm::isSupported(keyLen))
                sts = __build_GcmAead(pKey, keyLen, ctx);
            break;

        default:
            break;
    }
    return (alc_error_t)sts.code();
}

alc_error_t
CipherBuilder::Build(const alc_cipher_type_t cipherType,
                     const alc_cipher_mode_t cipherMode,
                     const Uint8*            pKey,
                     const Uint32            keyLen,
                     Context&                ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherType) {
        case ALC_CIPHER_TYPE_AES:
            err = AesBuilder::Build(cipherMode, pKey, keyLen, ctx);
            break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

} // namespace alcp::cipher