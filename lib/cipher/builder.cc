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
#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cfb.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aes_xts.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

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
__aes_wrapperSetTKey(void* rCipher, const Uint8* pTag, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    ap->setTweakKey(pTag, len);

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

/* CIPHER CONTEXT INTERFACE BINDING */
/**
 * @brief CAPI Context Interface Binding for Generic Ciphers.
 *
 * Takes a cipher class and binds its functions to the Context
 * @tparam CIPHERMODE
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the cipher
 */
template<typename CIPHERMODE>
void
_build_aes_cipher(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    CIPHERMODE* algo = new CIPHERMODE(pKey, keyLen);

    ctx.m_cipher = static_cast<void*>(algo);

    ctx.decrypt = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt = __aes_wrapper<CIPHERMODE, true>;

    ctx.finish = __aes_dtor<CIPHERMODE>;
}

// For XTS and Some modes
template<typename T1, typename T2>
void
__build_aes_cipher(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T1>(pKey, keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T2>(pKey, keyLen, ctx);
    }
}

template<typename T1, typename T2, typename T3>
void
__build_aes_cipher(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T1>(pKey, keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_192) {
        _build_aes_cipher<T2>(pKey, keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T3>(pKey, keyLen, ctx);
    }
}

/**
 * @brief Legacy CAPI Context Interface Binding.
 *
 * Takes a cipher class and binds its functions to the Context
 * @tparam CIPHERMODE
 * @param aesInfo       AES information structure
 * @param keyInfo       Key information structure
 * @param ctx           Context for the cipher
 * @return Status
 */
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
        // } else if constexpr (std::is_same_v<CIPHERMODE, Xts>) {
        //     ctx.setIv = __aes_wrapperSetIv<Xts>;
    }
    ctx.finish = __aes_dtor<CIPHERMODE>;

    return sts;
}

/* MODE SPECIFIC BUILDER */
/**
 * @brief CAPI Context Interface Binding for AEAD Ciphers.
 *
 * Takes a cipher class and binds its functions to the Context
 * @tparam CIPHERMODE
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the AEAD Cipher
 */
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

/**
 * @brief Builder specific to GCM AEAD Mode with Dispatcher
 *
 * Takes the params and builds the appropriate path given size info
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the AEAD GCM Cipher
 * @return Status
 */
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

/**
 * @brief Builder specific to CTR Generic Cipher Mode with Dispatcher
 *
 * Takes the params and builds the appropriate path given size info
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the CTR Cipher Mode
 * @return Status
 */
static Status
__build_aesCtr(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(pKey, keyLen, ctx);
    }

    return sts;
}

/**
 * @brief Builder specific to CFB Generic Cipher Mode with Dispatcher
 *
 * Takes the params and builds the appropriate path given size info
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the CFB Cipher Mode
 * @return Status
 */
static Status
__build_aesCfb(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    // cpu_feature                   = CpuCipherFeatures::eVaes256;
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cfb<aesni::EncryptCfb128, DecryptCfb128>,
                           Cfb<aesni::EncryptCfb192, DecryptCfb192>,
                           Cfb<aesni::EncryptCfb256, DecryptCfb256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cfb<aesni::EncryptCfb128, DecryptCfb128>,
                           Cfb<aesni::EncryptCfb192, DecryptCfb192>,
                           Cfb<aesni::EncryptCfb256, DecryptCfb256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Cfb<EncryptCfb128, DecryptCfb128>,
                           Cfb<EncryptCfb192, DecryptCfb192>,
                           Cfb<EncryptCfb256, DecryptCfb256>>(
            pKey, keyLen, ctx);
    }

    return sts;
}

/**
 * @brief Builder specific to CBC Generic Cipher Mode
 *
 * Takes the params and builds the appropriate path given size info
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the CBC Cipher Mode
 * @return Status
 */
static Status
__build_aesCbc(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    // cpu_feature                   = CpuCipherFeatures::eVaes256;
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cbc<aesni::EncryptCbc128, DecryptCbc128>,
                           Cbc<aesni::EncryptCbc192, DecryptCbc192>,
                           Cbc<aesni::EncryptCbc256, DecryptCbc256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cbc<aesni::EncryptCbc128, DecryptCbc128>,
                           Cbc<aesni::EncryptCbc192, DecryptCbc192>,
                           Cbc<aesni::EncryptCbc256, DecryptCbc256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Cbc<EncryptCbc128, DecryptCbc128>,
                           Cbc<EncryptCbc192, DecryptCbc192>,
                           Cbc<EncryptCbc256, DecryptCbc256>>(
            pKey, keyLen, ctx);
    }

    return sts;
}

/**
 * @brief Builder specific to XTS Generic Cipher Mode
 *
 * Takes the params and builds the appropriate path given size info
 * @param pKey      Key for initializing cipher class
 * @param keyLen    Length of the key
 * @param ctx       Context for the XTS Cipher Mode
 * @return Status
 */
static Status
__build_aesXts(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Xts<EncryptXts128, DecryptXts128>,
                           Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Xts<EncryptXts128, DecryptXts128>,
                           Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Xts<EncryptXts128, DecryptXts128>,
                           Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    }

    return sts;
}

// FIXME: Horror ahead, custom builder for SIV
// FIXME: Bringup New AEAD builder with support for all AEAD
#if 1

template<typename AEADMODE>
void
__build_aead_siv(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo,
                 Context&                      ctx)
{
    auto algo    = new AEADMODE(aesInfo, keyInfo);
    ctx.m_cipher = static_cast<void*>(algo);
    ctx.decrypt  = __aes_wrapper<AEADMODE, false>;
    ctx.encrypt  = __aes_wrapper<AEADMODE, true>;

    ctx.setAad = __aes_wrapperSetAad<AEADMODE>;
    ctx.getTag = __aes_wrapperGetTag<AEADMODE>;

    ctx.finish = __aes_dtor<AEADMODE>;
}

template<typename T1, typename T2, typename T3>
void
__build_aes(const alc_cipher_algo_info_t& aesInfo,
            const alc_key_info_t&         keyInfo,
            Context&                      ctx)
{
    if (keyInfo.len == ALC_KEY_LEN_128) {
        __build_aead_siv<T1>(aesInfo, keyInfo, ctx);
    } else if (keyInfo.len == ALC_KEY_LEN_192) {
        __build_aead_siv<T2>(aesInfo, keyInfo, ctx);
    } else if (keyInfo.len == ALC_KEY_LEN_256) {
        __build_aead_siv<T3>(aesInfo, keyInfo, ctx);
    }
}

static Status
__build_aesSiv(const alc_cipher_algo_info_t& aesInfo,
               const alc_key_info_t&         keyInfo,
               Context&                      ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            aesInfo, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            aesInfo, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            aesInfo, keyInfo, ctx);
    }
    return sts;
}

#endif

// DEPRICIATED AES BUILDER
alc_error_t
AesBuilder::Build(const alc_cipher_algo_info_t& aesInfo,
                  const alc_key_info_t&         keyInfo,
                  Context&                      ctx)
{
    Status sts = StatusOk();

    switch (aesInfo.ai_mode) {
        case ALC_AES_MODE_OFB:
            if (Ofb::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Ofb>(aesInfo, keyInfo, ctx);
            break;

        case ALC_AES_MODE_CCM:
            if (Ccm::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Ccm>(aesInfo, keyInfo, ctx);
            break;
        // New builder has to come in place.
        case ALC_AES_MODE_SIV:
            sts = __build_aesSiv(aesInfo, keyInfo, ctx);
            break;

        default:
            break;
    }
    return (alc_error_t)sts.code();
}

// DEPRICIATED CIPHER BUILDER
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

// NEW AES BUILDER
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
        case ALC_AES_MODE_CBC:
            if (Cbc<aesni::EncryptCbc128, aesni::DecryptCbc128>::isSupported(
                    keyLen))
                sts = __build_aesCbc(pKey, keyLen, ctx);
            break;
        case ALC_AES_MODE_CFB:
            if (Cfb<aesni::EncryptCfb256, aesni::DecryptCfb256>::isSupported(
                    keyLen)) {
                sts = __build_aesCfb(pKey, keyLen, ctx);
            }
            break;
            // FIXME: GCM, XTS, CCM should be moved to AeadBuilder.
        case ALC_AES_MODE_XTS:
            if (Xts<aesni::EncryptXts128, aesni::DecryptXts128>::isSupported(
                    keyLen)) {
                sts = __build_aesXts(pKey, keyLen, ctx);
            }
            break;
        case ALC_AES_MODE_GCM:
            if (Gcm::isSupported(keyLen))
                sts = __build_GcmAead(pKey, keyLen, ctx);
            break;

        default:
            break;
    }
    return (alc_error_t)sts.code();
}

// NEW CIPHER BUILDER
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
