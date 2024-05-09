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
#include "alcp/cipher/aes_xts.hh"

// FIXME: to be moved out
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/chacha20_build.hh"

#include "builder.hh"

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
    CIPHERMODE* algo = new CIPHERMODE(&(ctx.m_alcp_cipher_data));

    ctx.m_cipher = static_cast<void*>(algo);

    ctx.decrypt = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt = __aes_wrapper<CIPHERMODE, true>;
    ctx.init    = __aes_wrapperInit<CIPHERMODE>;

    ctx.finish = __aes_dtor<CIPHERMODE>;
}

// For XTS and Some modes
template<typename T1, typename T2>
void
__build_aes_cipher_xts(const Uint32 keyLen, Context& ctx)
{
    // FIXME In future every non AEAD Cipher should also use this
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T1>(keyLen, ctx);
        ctx.encryptBlocksXts = __aes_wrapper_crypt_block_xts<T1, true>;
        ctx.decryptBlocksXts = __aes_wrapper_crypt_block_xts<T1, false>;
        ctx.init             = __aes_wrapperInit<T1>;
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T2>(keyLen, ctx);
        ctx.encryptBlocksXts = __aes_wrapper_crypt_block_xts<T2, true>;
        ctx.decryptBlocksXts = __aes_wrapper_crypt_block_xts<T2, false>;
        ctx.init             = __aes_wrapperInit<T2>;
    }
}

template<typename T1, typename T2, typename T3>
void
__build_aes_cipher(const Uint32 keyLen, Context& ctx)
{
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T1>(keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_192) {
        _build_aes_cipher<T2>(keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T3>(keyLen, ctx);
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
__build_aes(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    auto algo    = new CIPHERMODE(&(ctx.m_alcp_cipher_data));
    ctx.m_cipher = static_cast<void*>(algo);
    ctx.decrypt  = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt  = __aes_wrapper<CIPHERMODE, true>;
    ctx.init     = __aes_wrapperInit<CIPHERMODE>;
    ctx.finish   = __aes_dtor<CIPHERMODE>;

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
__build_aesCtr(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
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
__build_aesCfb(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
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
__build_aesCbc(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    // cpu_feature                   = CpuCipherFeatures::eVaes256;
    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
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
__build_aesXts(const Uint32 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
    } else if (cpu_feature == CpuCipherFeatures::eAesni) {
        using namespace aesni;
        __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
    }

    return sts;
}

// Non-AEAD Builder
alc_error_t
CipherBuilder::Build(const alc_cipher_mode_t cipherMode,
                     const Uint64            keyLen,
                     Context&                ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherMode) { // can we avoid type ?
#if 1
        case ALC_CHACHA20:
            err = chacha20::Chacha20Builder::Build(cipherMode, keyLen, ctx);
            break;
#endif
        case ALC_AES_MODE_CBC:
        case ALC_AES_MODE_CTR:
        case ALC_AES_MODE_CFB:
        case ALC_AES_MODE_OFB:
        case ALC_AES_MODE_XTS:
            err = AesBuilder::Build(cipherMode, keyLen, ctx);
            break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
    }

    return err;
}

alc_error_t
AesBuilder::Build(const alc_cipher_mode_t cipherMode,
                  const Uint64            keyLen,
                  Context&                ctx)
{
    Status sts = StatusOk();

    if (!Aes::isSupported(keyLen)) {
        return ALC_ERROR_INVALID_SIZE; // FIXME set appropriate sts
    }

    ctx.m_prov_cipher_data.keyLen_in_bytes =
        keyLen / 8; // FIXME: provider data, can be removed

    ctx.m_alcp_cipher_data.alcp_keyLen_in_bytes =
        keyLen / 8; // keyLen_in_bytes is used to verify keyLen during setKey
    // call in init

    switch (cipherMode) {
        case ALC_AES_MODE_CTR:
            sts = __build_aesCtr(keyLen, ctx);
            break;
        case ALC_AES_MODE_CBC:
            sts = __build_aesCbc(keyLen, ctx);
            break;
        case ALC_AES_MODE_CFB:
            sts = __build_aesCfb(keyLen, ctx);
            break;
        case ALC_AES_MODE_XTS:
            sts = __build_aesXts(keyLen, ctx);
            break;
        case ALC_AES_MODE_OFB:
            sts = __build_aes<Ofb>(keyLen, ctx);
            break;
        default:
            break;
    }
    return (alc_error_t)sts.code();
}

bool
AesBuilder::Supported(const alc_cipher_mode_t cipherMode, const Uint64 keyLen)
{
    if (!Aes::isSupported(keyLen)) {
        return false;
    }

    switch (cipherMode) {
        case ALC_AES_MODE_CBC:
            return true;
        case ALC_AES_MODE_OFB:
            return true;
        case ALC_AES_MODE_CCM:
            return true;
        case ALC_AES_MODE_CFB:
            return true;
        case ALC_AES_MODE_CTR:
            return true;
        case ALC_AES_MODE_GCM:
            return true;
        case ALC_AES_MODE_XTS: // check required for 192 key size, which is not
                               // supported in xts
#if 0
            return Xts<aesni::EncryptXts128, aesni::DecryptXts128>::isSupported(
                keyLen);
#else
            return true;
#endif
        case ALC_AES_MODE_SIV:
            return true;
        default:
            return false;
    }
}

bool
CipherBuilder::Supported(const alc_cipher_mode_t cipherMode,
                         const Uint64            keyLen)
{
    // FIXME: remove ci_type dependency
    switch (cipherMode) // switch (cinfo.ci_type)
    {
        case ALC_CHACHA20:
            return chacha20::Chacha20Builder::Supported(cipherMode, keyLen);
        default:
            return AesBuilder::Supported(cipherMode, keyLen);
    }
}

} // namespace alcp::cipher
