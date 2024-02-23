/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/chacha20_build.hh"
#include "alcp/utils/cpuid.hh"

#include "builder.hh"

using alcp::utils::CpuCipherFeatures;
using alcp::utils::CpuId;

#include <type_traits> /* for is_same_v<> */

namespace alcp::cipher {

using Context = alcp::cipher::Context;
using namespace alcp::base;

/* CIPHER CONTEXT INTERFACE BINDING */
/**
 * @brief CAPI Context Interface Binding for Generic Ciphers.
 *
 * Takes a cipher class and binds its functions to the Context
 * @tparam CIPHERMODE
 * @param keyLen    Length of the key
 * @param ctx       Context for the cipher
 */
template<typename CIPHERMODE>
void
_build_aes_cipher(const Uint64 keyLen, Context& ctx)
{
    CIPHERMODE* algo = new CIPHERMODE();

    ctx.m_cipher = static_cast<void*>(algo);

    ctx.decrypt = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt = __aes_wrapper<CIPHERMODE, true>;
    ctx.initKey = __aes_wrapperInitKey<CIPHERMODE>;

    ctx.finish = __aes_dtor<CIPHERMODE>;
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

template<typename AEADMODE>
void
_build_aead_wrapper(Context& ctx)
{
    auto algo = new AEADMODE(); //(pKey, keyLen);

    ctx.m_cipher      = static_cast<void*>(algo);
    ctx.decryptUpdate = __aes_wrapperUpdate<AEADMODE, false>;
    ctx.encryptUpdate = __aes_wrapperUpdate<AEADMODE, true>;

    ctx.setAad  = __aes_wrapperSetAad<AEADMODE>;
    ctx.setIv   = __aes_wrapperSetIv<AEADMODE>;
    ctx.initKey = __aes_wrapperInitKey<AEADMODE>;
    ctx.getTag  = __aes_wrapperGetTag<AEADMODE>;

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

// FIXMEL pKey and keyLen to be removed.
static Status
__build_GcmAead(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        /* FIXME: cipher request should fail invalid key length. At this
         * level only valid key length is passed.*/
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<vaes512::GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<vaes512::GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<vaes512::GcmAEAD256>(ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        /* FIXME: cipher request should fail invalid key length. At this
         * level only valid key length is passed.*/
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<vaes::GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<vaes::GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<vaes::GcmAEAD256>(ctx);
        }
    } else {

        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<aesni::GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<aesni::GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<aesni::GcmAEAD256>(ctx);
        }
    }
    return sts;
}

#if 0 // turning off SIV temporarily
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
    if (keyLen == ALC_KEY_LEN_128) {
        __build_aead_siv<T1>(encKey, keyInfo, ctx);
    } else if (keyLen == ALC_KEY_LEN_192) {
        __build_aead_siv<T2>(encKey, keyInfo, ctx);
    } else if (keyLen == ALC_KEY_LEN_256) {
        __build_aead_siv<T3>(encKey, keyInfo, ctx);
    }
}

static Status
__build_aesSiv(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_siv<CmacSiv<Ctr128>, CmacSiv<Ctr192>, CmacSiv<Ctr256>>(
            *aesInfo.ai_siv.xi_ctr_key, keyInfo, ctx);
    }
    return sts;
}
#endif

#if 0 // turning off poly and chacha temporarily
// poly and chacha

template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_processInputWrapper(const void*  rCipher,
                               const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       len,
                               const Uint8* pIv)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<const chacha20::ChaCha20<cpu_cipher_feature>*>(rCipher);

    e = ap->processInput(pSrc, len, pDest);

    return e;
}
template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_FinishWrapper(const void* rCipher)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<const chacha20::ChaCha20<cpu_cipher_feature>*>(rCipher);
    delete ap;

    return e;
}

template<CpuCipherFeatures cpu_cipher_feature, bool is_encrypt>
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

template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setKeyWrapper(void*        rCipher,
                                 Uint64       keyLen,
                                 const Uint8* pKey)
{
    alc_error_t e = ALC_ERROR_NONE;

    // auto ap =
    //  static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    // e = ap->initKey(keyLen, pKey);

    return e;
}

template<CpuCipherFeatures cpu_cipher_feature>
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

template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setTagLengthWrapper(void* rCipher, Uint64 tag_length)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->setTagLength(tag_length);

    return e;
}

template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305setAADWrapper(void* rCipher, const Uint8* pAad, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->setAad(pAad, len);

    return e;
}

template<CpuCipherFeatures cpu_cipher_feature>
static alc_error_t
__chacha20_Poly1305getTagWrapper(void* rCipher, Uint8* pTag, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap =
        static_cast<chacha20::ChaCha20Poly1305<cpu_cipher_feature>*>(rCipher);

    e = ap->getTag(pTag, len);

    return e;
}
template<CpuCipherFeatures cpu_cipher_feature>
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

template<CpuCipherFeatures cpu_cipher_feature>
alc_error_t
__build_chacha20(const alc_cipher_info_t& cCipherAlgoInfo, Context& ctx)
{
    chacha20::ChaCha20<cpu_cipher_feature>* chacha =
        new chacha20::ChaCha20<cpu_cipher_feature>();
    ctx.m_cipher = chacha;

#if 0
    if (chacha->setKey(cCipherAlgoInfo.ci_key,
                       cCipherAlgoInfo.ci_keyLen / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (chacha->setIv(cCipherAlgoInfo.ci_iv,
                      cCipherAlgoInfo.ci_algo_info.iv_length / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
#endif
    ctx.encrypt = __chacha20_processInputWrapper<cpu_cipher_feature>;
    ctx.decrypt = __chacha20_processInputWrapper<cpu_cipher_feature>;
    ctx.finish  = __chacha20_FinishWrapper<cpu_cipher_feature>;

    return ALC_ERROR_NONE;
}

template<CpuCipherFeatures cpu_cipher_feature>
alc_error_t
__build_chacha20poly1305(const alc_cipher_aead_info_t& cCipherAlgoInfo,
                         Context&                      ctx)
{
    chacha20::ChaCha20Poly1305<cpu_cipher_feature>* chacha_poly1305 =
        new chacha20::ChaCha20Poly1305<cpu_cipher_feature>();
    ctx.m_cipher = chacha_poly1305;

    // setNonce to be merged with setIv and setKey to be moved to different
    // C-API
#if 0
    if (chacha_poly1305->setNonce(cCipherAlgoInfo.ci_iv,
                                  cCipherAlgoInfo.ci_algo_info.iv_length / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }

    if (chacha_poly1305->setKey(cCipherAlgoInfo.ci_key,
                                cCipherAlgoInfo.ci_keyLen / 8)) {
        return ALC_ERROR_INVALID_ARG;
    }
#endif
    ctx.initKey = __chacha20_Poly1305setKeyWrapper<cpu_cipher_feature>;

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

    CpuCipherFeatures cpu_cipher_feature = getCpuCipherfeature();
    if (cpu_cipher_feature == CpuCipherFeatures::eVaes512) {
        __build_chacha20<CpuCipherFeatures::eVaes512>(cCipherAlgoInfo, ctx);
    } else {
        __build_chacha20<CpuCipherFeatures::eReference>(cCipherAlgoInfo, ctx);
    }

    return ALC_ERROR_NONE;
}

alc_error_t
chacha20::Chacha20Poly1305Builder::Build(
    const alc_cipher_aead_info_t& cCipherAlgoInfo, Context& ctx)
{

    CpuCipherFeatures cpu_cipher_feature = getCpuCipherfeature();
    if (cpu_cipher_feature == CpuCipherFeatures::eVaes512) {
        return __build_chacha20poly1305<CpuCipherFeatures::eVaes512>(
            cCipherAlgoInfo, ctx);
    } else {
        return __build_chacha20poly1305<CpuCipherFeatures::eReference>(
            cCipherAlgoInfo, ctx);
    }

    return ALC_ERROR_NONE;
}

bool
chacha20::Chacha20Builder::Supported(const alc_cipher_algo_info_t ci_algo_info,
                                     const alc_key_info_t         ci_key_info)
{
#if 0
    if (chacha20::ChaCha20<CpuCipherFeatures::eReference>::validateKey(
            ci_key, ci_keyLen / 8)) {
        return false;
    } else if (chacha20::ChaCha20<CpuCipherFeatures::eReference>::validateIv(
                   ci_iv, ci_algo_info.iv_length / 8)) {
        return false;
    }
#endif
    return true;
}

#endif

// AEAD Builder
alc_error_t
CipherAeadBuilder::Build(const alc_cipher_mode_t cipherMode,
                         const Uint64            keyLen,
                         alcp::cipher::Context&  ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (ALC_CIPHER_TYPE_AES) {
        case ALC_CIPHER_TYPE_AES:
            err = AesAeadBuilder::Build(cipherMode, keyLen, ctx);
            break;
        // case ALC_CIPHER_TYPE_CHACHA20_POLY1305:
        // err = chacha20::Chacha20Poly1305Builder::Build(cipherInfo, ctx);
        // break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

alc_error_t
AesAeadBuilder::Build(const alc_cipher_mode_t cipherMode,
                      const Uint64            keyLen,
                      Context&                ctx)
{
    Status sts = StatusOk();

    if (!Aes::isSupported(keyLen)) {
        return ALC_ERROR_INVALID_SIZE; // FIXME set appropriate sts
    }

    switch (cipherMode) {
        case ALC_AES_MODE_GCM:
            sts = __build_GcmAead(keyLen, ctx);
            break;
#if 0
        case ALC_AES_MODE_SIV:
                sts = __build_aesSiv(keyLen, ctx);
            break;
        case ALC_AES_MODE_CCM:
                _build_aead<Ccm>(keyLen, ctx);
            sts = StatusOk();
            break;
#endif
        default:
            break;
    }
    return (alc_error_t)sts.code();
}

} // namespace alcp::cipher
