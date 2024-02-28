/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher/chacha20_build.hh"
#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuArchFeature;
using alcp::utils::CpuCipherAesFeatures;
using alcp::utils::CpuId;

#include <type_traits> /* for is_same_v<> */

namespace alcp::cipher {

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
__aes_wrapper_crypt_block(const void*  rCipher,
                          const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       currSrcLen,
                          Uint64       startBlockNum)
{
    Status e = StatusOk();

    auto ap = static_cast<CIPHERMODE*>(const_cast<void*>(rCipher));

    if constexpr (encrypt)
        e.update(ap->encryptBlocks(pSrc, pDest, currSrcLen, startBlockNum));
    else
        e.update(ap->decryptBlocks(pSrc, pDest, currSrcLen, startBlockNum));

    return !(e.ok() == 1);
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

    if constexpr (encrypt)
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

CpuCipherAesFeatures
getCpuCipherfeature()
{
    CpuCipherAesFeatures cpu_feature =
        CpuCipherAesFeatures::eReference; // If no arch features present,means
                                          // no acceleration, Fall back to
                                          // reference

    if (CpuId::cpuHasAesni()) {
        cpu_feature = CpuCipherAesFeatures::eAesni;

        if (CpuId::cpuHasVaes()) {
            cpu_feature = CpuCipherAesFeatures::eVaes256;

            if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
                cpu_feature = CpuCipherAesFeatures::eVaes512;
            }
        }
    }
    return cpu_feature;
}

CpuArchFeature
getCpuArchFeature()
{
    CpuArchFeature cpu_feature =
        CpuArchFeature::eReference; // If no arch features present,means
                                    // no acceleration, Fall back to
                                    // reference
    if (CpuId::cpuHasAvx2()) {
        cpu_feature = CpuArchFeature::eAvx2;

        if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
            cpu_feature = CpuArchFeature::eAvx512;
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
__build_aes_cipher_xts(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    // FIXME In future every non AEAD Cipher should also use this
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T1>(pKey, keyLen, ctx);
        ctx.encryptBlocks = __aes_wrapper_crypt_block<T1, true>;
        ctx.decryptBlocks = __aes_wrapper_crypt_block<T1, false>;
        ctx.setIv         = __aes_wrapperSetIv<T1>;
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T2>(pKey, keyLen, ctx);
        ctx.encryptBlocks = __aes_wrapper_crypt_block<T2, true>;
        ctx.decryptBlocks = __aes_wrapper_crypt_block<T2, false>;
        ctx.setIv         = __aes_wrapperSetIv<T2>;
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
__build_aes(const Uint8* pKey, const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    auto algo    = new CIPHERMODE(pKey, keyLen);
    ctx.m_cipher = static_cast<void*>(algo);
    ctx.decrypt  = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt  = __aes_wrapper<CIPHERMODE, true>;
#if 0
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
#endif
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
    auto algo = new AEADMODE(pKey, keyLen);

    ctx.m_cipher      = static_cast<void*>(algo);
    ctx.decryptUpdate = __aes_wrapperUpdate<AEADMODE, false>;
    ctx.encryptUpdate = __aes_wrapperUpdate<AEADMODE, true>;

    ctx.setAad = __aes_wrapperSetAad<AEADMODE>;
    ctx.setIv  = __aes_wrapperSetIv<AEADMODE>;
    ctx.getTag = __aes_wrapperGetTag<AEADMODE>;

    if constexpr (std::is_same_v<AEADMODE, Ccm>) {
        ctx.setTagLength = __aes_wrapperSetTagLength<AEADMODE>;
    }

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

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        /* FIXME: cipher request should fail invalid key length. At this
         * level only valid key length is passed.*/
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead<vaes512::GcmAEAD128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead<vaes512::GcmAEAD192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead<vaes512::GcmAEAD256>(pKey, keyLen, ctx);
        }
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        /* FIXME: cipher request should fail invalid key length. At this
         * level only valid key length is passed.*/
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead<vaes::GcmAEAD128>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead<vaes::GcmAEAD192>(pKey, keyLen, ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead<vaes::GcmAEAD256>(pKey, keyLen, ctx);
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

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eAesni) {
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

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();
    // cpu_feature                   = CpuCipherAesFeatures::eVaes256;
    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cfb<aesni::EncryptCfb128, DecryptCfb128>,
                           Cfb<aesni::EncryptCfb192, DecryptCfb192>,
                           Cfb<aesni::EncryptCfb256, DecryptCfb256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cfb<aesni::EncryptCfb128, DecryptCfb128>,
                           Cfb<aesni::EncryptCfb192, DecryptCfb192>,
                           Cfb<aesni::EncryptCfb256, DecryptCfb256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eAesni) {
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

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();
    // cpu_feature                   = CpuCipherFeaturesAes::eVaes256;
    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cbc<aesni::EncryptCbc128, DecryptCbc128>,
                           Cbc<aesni::EncryptCbc192, DecryptCbc192>,
                           Cbc<aesni::EncryptCbc256, DecryptCbc256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cbc<aesni::EncryptCbc128, DecryptCbc128>,
                           Cbc<aesni::EncryptCbc192, DecryptCbc192>,
                           Cbc<aesni::EncryptCbc256, DecryptCbc256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eAesni) {
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

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher_xts<Xts<EncryptXts128, DecryptXts128>,
                               Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher_xts<Xts<EncryptXts128, DecryptXts128>,
                               Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher_xts<Xts<EncryptXts128, DecryptXts128>,
                               Xts<EncryptXts256, DecryptXts256>>(
            pKey, keyLen, ctx);
    }

    return sts;
}

template<typename AEADMODE>
void
__build_aead_siv(const alc_key_info_t& encKey,
                 const alc_key_info_t& authKey,
                 Context&              ctx)
{
    auto algo    = new AEADMODE(encKey, authKey);
    ctx.m_cipher = static_cast<void*>(algo);
    ctx.decrypt  = __aes_wrapper<AEADMODE, false>;
    ctx.encrypt  = __aes_wrapper<AEADMODE, true>;

    ctx.setAad = __aes_wrapperSetAad<AEADMODE>;
    ctx.getTag = __aes_wrapperGetTag<AEADMODE>;

    ctx.finish = __aes_dtor<AEADMODE>;
}

template<typename T1, typename T2, typename T3>
void
__build_aes_siv(const alc_key_info_t& encKey,
                const alc_key_info_t& keyInfo,
                Context&              ctx)
{
    if (keyInfo.len == ALC_KEY_LEN_128) {
        __build_aead_siv<T1>(encKey, keyInfo, ctx);
    } else if (keyInfo.len == ALC_KEY_LEN_192) {
        __build_aead_siv<T2>(encKey, keyInfo, ctx);
    } else if (keyInfo.len == ALC_KEY_LEN_256) {
        __build_aead_siv<T3>(encKey, keyInfo, ctx);
    }
}

static Status
__build_aesSiv(const alc_cipher_aead_algo_info_t& aesInfo,
               const alc_key_info_t&              keyInfo,
               Context&                           ctx)
{
    Status sts = StatusOk();

    CpuCipherAesFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherAesFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherAesFeatures::eAesni) {
        using namespace aesni;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    }
    return sts;
}

// Non-AEAD Builder
alc_error_t
CipherBuilder::Build(const alc_cipher_info_t& cipherInfo, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherInfo.ci_type) {
        case ALC_CIPHER_TYPE_AES:
            err = AesBuilder::Build(
                cipherInfo.ci_algo_info, cipherInfo.ci_key_info, ctx);
            break;
        case ALC_CIPHER_TYPE_CHACHA20:
            err = chacha20::Chacha20Builder::Build(cipherInfo, ctx);
            break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}
template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_processInputWrapper(const void*  rCipher,
                               const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       len,
                               const Uint8* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<chacha20::ChaCha20<cpu_cipher_feature>*>(
        const_cast<void*>(rCipher));

    e = ap->processInput(pSrc, len, pDest);

    return e;
}
template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_FinishWrapper(const void* rCipher)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<const chacha20::ChaCha20<cpu_cipher_feature>*>(rCipher);
    delete ap;

    return e;
}

template<CpuArchFeature cpu_cipher_feature, bool is_encrypt>
static alc_error_t
__chacha20_Poly1305processInputWrapper(void*        rCipher,
                                       const Uint8* pSrc,
                                       Uint8*       pDest,
                                       Uint64       len,
                                       const Uint8* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);
    if constexpr (is_encrypt) {

        e = ap->encryptupdate(pSrc, len, pDest);
    } else {
        e = ap->decryptupdate(pSrc, len, pDest);
    }

    return e;
}

template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setIvWrapper(void*        rCipher,
                                Uint64       iv_length,
                                const Uint8* iv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->setIv(iv, iv_length);

    return e;
}

template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setTagLengthWrapper(void* rCipher, Uint64 tag_length)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->setTagLength(tag_length);

    return e;
}

template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setAADWrapper(void* rCipher, const Uint8* pAad, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->setAad(pAad, len);

    return e;
}

template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305getTagWrapper(void* rCipher, Uint8* pTag, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->getTag(pTag, len);

    return e;
}
template<CpuArchFeature cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305FinishWrapper(const void* rCipher)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<const chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(
            rCipher);

    delete ap;

    return e;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
__build_chacha20(const alc_cipher_info_t& cCipherAlgoInfo, Context& ctx)
{
    chacha20::ChaCha20<cpu_cipher_feature>* chacha =
        new chacha20::ChaCha20<cpu_cipher_feature>();
    ctx.m_cipher = chacha;
    if (chacha->setKey(cCipherAlgoInfo.ci_key_info.key,
                       cCipherAlgoInfo.ci_key_info.len / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (chacha->setIv(cCipherAlgoInfo.ci_algo_info.ai_iv,
                      cCipherAlgoInfo.ci_algo_info.iv_length / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
    ctx.encrypt = __chacha20_processInputWrapper<cpu_cipher_feature>;
    ctx.decrypt = __chacha20_processInputWrapper<cpu_cipher_feature>;
    ctx.finish  = __chacha20_FinishWrapper<cpu_cipher_feature>;

    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
__build_chacha20poly1305(const alc_cipher_aead_info_t& cCipherAlgoInfo,
                         Context&                      ctx)
{
    chacha20::ChaCha20Poly1305<cpu_cipher_feature>* chacha_poly1305 =
        new chacha20::ChaCha20Poly1305<cpu_cipher_feature>();
    ctx.m_cipher = chacha_poly1305;
    if (chacha_poly1305->setNonce(cCipherAlgoInfo.ci_algo_info.ai_iv,
                                  cCipherAlgoInfo.ci_algo_info.iv_length / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (chacha_poly1305->setKey(cCipherAlgoInfo.ci_key_info.key,
                                cCipherAlgoInfo.ci_key_info.len / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
    ctx.setIv = __chacha20_Poly1305setIvWrapper<cpu_cipher_feature>;

    ctx.setAad = __chacha20_Poly1305setAADWrapper<cpu_cipher_feature>;
    ctx.setTagLength =
        __chacha20_Poly1305setTagLengthWrapper<cpu_cipher_feature>;

    ctx.encryptUpdate =
        __chacha20_Poly1305processInputWrapper<cpu_cipher_feature, true>;
    ctx.decryptUpdate =
        __chacha20_Poly1305processInputWrapper<cpu_cipher_feature, false>;

    ctx.getTag = __chacha20_Poly1305getTagWrapper<cpu_cipher_feature>;
    ctx.finish = __chacha20_Poly1305FinishWrapper<cpu_cipher_feature>;
    return ALC_ERROR_NONE;
}
alc_error_t
chacha20::Chacha20Builder::Build(const alc_cipher_info_t& cCipherAlgoInfo,
                                 Context&                 ctx)
{

    CpuArchFeature cpu_cipher_feature = getCpuArchFeature();
    if (cpu_cipher_feature == CpuArchFeature::eAvx512) {
        __build_chacha20<CpuArchFeature::eAvx512>(cCipherAlgoInfo, ctx);
    } else {
        __build_chacha20<CpuArchFeature::eReference>(cCipherAlgoInfo, ctx);
    }

    return ALC_ERROR_NONE;
}

alc_error_t
chacha20::Chacha20Poly1305Builder::Build(
    const alc_cipher_aead_info_t& cCipherAlgoInfo, Context& ctx)
{

    CpuArchFeature cpu_cipher_feature = getCpuArchFeature();
    if (cpu_cipher_feature == CpuArchFeature::eAvx512) {
        return __build_chacha20poly1305<CpuArchFeature::eAvx512>(
            cCipherAlgoInfo, ctx);
    } else {
        return __build_chacha20poly1305<CpuArchFeature::eReference>(
            cCipherAlgoInfo, ctx);
    }

    return ALC_ERROR_NONE;
}

bool
chacha20::Chacha20Builder::Supported(const alc_cipher_algo_info_t ci_algo_info,
                                     const alc_key_info_t         ci_key_info)
{
    if (chacha20::ChaCha20<CpuArchFeature::eReference>::validateKey(
            ci_key_info.key, ci_key_info.len / 8)) {
        return false;
    } else if (chacha20::ChaCha20<CpuArchFeature::eReference>::validateIv(
                   ci_algo_info.ai_iv, ci_algo_info.iv_length / 8)) {
        return false;
    }
    return true;
}
alc_error_t
AesBuilder::Build(const alc_cipher_algo_info_t& aesInfo,
                  const alc_key_info_t&         keyInfo,
                  Context&                      ctx)
{
    Status sts = StatusOk();

    switch (aesInfo.ai_mode) {
        case ALC_AES_MODE_CTR:
            if (Ctr::isSupported(keyInfo.len))
                sts = __build_aesCtr(keyInfo.key, keyInfo.len, ctx);
            break;
        case ALC_AES_MODE_CBC:
            if (Cbc<aesni::EncryptCbc128, aesni::DecryptCbc128>::isSupported(
                    keyInfo.len))
                sts = __build_aesCbc(keyInfo.key, keyInfo.len, ctx);
            break;
        case ALC_AES_MODE_CFB:
            if (Cfb<aesni::EncryptCfb256, aesni::DecryptCfb256>::isSupported(
                    keyInfo.len)) {
                sts = __build_aesCfb(keyInfo.key, keyInfo.len, ctx);
            }
            break;
            // FIXME: GCM, XTS, CCM should be moved to AeadBuilder.
        case ALC_AES_MODE_XTS:
            if (Xts<aesni::EncryptXts128, aesni::DecryptXts128>::isSupported(
                    keyInfo.len)) {
                sts = __build_aesXts(keyInfo.key, keyInfo.len, ctx);
            }
            break;
        case ALC_AES_MODE_OFB:
            if (Ofb::isSupported(keyInfo.len))
                sts = __build_aes<Ofb>(keyInfo.key, keyInfo.len, ctx);
            break;

        default:
            break;
    }
    return (alc_error_t)sts.code();
}

// AEAD Builder
alc_error_t
CipherAeadBuilder::Build(const alc_cipher_aead_info_t& cipherInfo,
                         alcp::cipher::Context&        ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherInfo.ci_type) {
        case ALC_CIPHER_TYPE_AES:
            err = AesAeadBuilder::Build(
                cipherInfo.ci_algo_info, cipherInfo.ci_key_info, ctx);
            break;
        case ALC_CIPHER_TYPE_CHACHA20_POLY1305:
            err = chacha20::Chacha20Poly1305Builder::Build(cipherInfo, ctx);
            break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

alc_error_t
AesAeadBuilder::Build(const alc_cipher_aead_algo_info_t& cCipherAlgoInfo,
                      const alc_key_info_t&              keyInfo,
                      Context&                           ctx)
{
    Status sts = StatusOk();

    switch (cCipherAlgoInfo.ai_mode) {
        case ALC_AES_MODE_GCM:
            if (Gcm::isSupported(keyInfo.len))
                // FIXME: GCM Info is empty we need to do something about it
                sts = __build_GcmAead(keyInfo.key, keyInfo.len, ctx);
            break;
        case ALC_AES_MODE_SIV:
            // FIXME: Find a way to call the template without the argument
            if (CmacSiv<aesni::Ctr128>::isSupported(keyInfo.len))
                sts = __build_aesSiv(cCipherAlgoInfo, keyInfo, ctx);
            break;
        case ALC_AES_MODE_CCM:
            // FIXME: Rewrite below
            if (Ccm::isSupported(keyInfo.len))
                _build_aead<Ccm>(keyInfo.key, keyInfo.len, ctx);
            sts = StatusOk();
            break;
#if 0
        case ALC_AES_MODE_CCM:
            if (Ccm::isSupported(aesInfo, keyInfo))
                sts = __build_aes<Ccm>(aesInfo, keyInfo, ctx);
            break;
#endif
        default:
            break;
    }
    return (alc_error_t)sts.code();
}

bool
AesBuilder::Supported(const alc_cipher_algo_info_t ci_algo_info,
                      const alc_key_info_t         ci_key_info)
{
    // FIXME: Below all must be accessible via
    switch (ci_algo_info.ai_mode) {
        case ALC_AES_MODE_CBC:
            return Cbc<aesni::EncryptCbc128, aesni::DecryptCbc128>::isSupported(
                ci_key_info.len);
        case ALC_AES_MODE_OFB:
            return Ofb::isSupported(ci_key_info.len);
        case ALC_AES_MODE_CCM:
            return Ccm::isSupported(ci_key_info.len);
        case ALC_AES_MODE_CFB:
            return Cfb<aesni::EncryptCfb256, aesni::DecryptCfb256>::isSupported(
                ci_key_info.len);
        case ALC_AES_MODE_CTR:
            return Ctr::isSupported(ci_key_info.len);
        case ALC_AES_MODE_GCM:
            return Gcm::isSupported(ci_key_info.len);
        case ALC_AES_MODE_XTS:
            return Xts<aesni::EncryptXts128, aesni::DecryptXts128>::isSupported(
                ci_key_info.len);
        case ALC_AES_MODE_SIV:
            return CmacSiv<aesni::Ctr128>::isSupported(ci_key_info.len);
        default:
            return false;
    }
}

bool
CipherBuilder::Supported(alc_cipher_info_t& cinfo)
{
    switch (cinfo.ci_type) {
        case ALC_CIPHER_TYPE_AES:
            return AesBuilder::Supported(cinfo.ci_algo_info, cinfo.ci_key_info);
        case ALC_CIPHER_TYPE_CHACHA20:
            return chacha20::Chacha20Builder::Supported(cinfo.ci_algo_info,
                                                        cinfo.ci_key_info);
        default:
            return false;
    }
}

} // namespace alcp::cipher
