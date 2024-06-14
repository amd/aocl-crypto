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
#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cfb.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/aes_ofb.hh"
#include "alcp/cipher/aes_xts.hh"

// FIXME: to be moved out
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
    ctx.decrypt  = __aes_wrapper<CIPHERMODE, false>;
    ctx.encrypt  = __aes_wrapper<CIPHERMODE, true>;
    ctx.init     = __aes_wrapperInit<CIPHERMODE>;
    ctx.finish   = __aes_dtor<CIPHERMODE>;
}

/**
 * @brief Builder specific to XTS Generic Cipher Mode
 *
 * Takes the params and builds the appropriate path given size info
 * @param keyLen    Length of the key
 * @param ctx       Context for the XTS Cipher Mode
 * @return Status
 */
template<typename T128, typename T256>
alc_error_t
__build_aes_cipher_xts(const Uint32 keyLen, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T128>(keyLen, ctx);
        ctx.encryptBlocksXts = __aes_wrapper_crypt_block_xts<T128, true>;
        ctx.decryptBlocksXts = __aes_wrapper_crypt_block_xts<T128, false>;
        ctx.init             = __aes_wrapperInit<T128>;
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T256>(keyLen, ctx);
        ctx.encryptBlocksXts = __aes_wrapper_crypt_block_xts<T256, true>;
        ctx.decryptBlocksXts = __aes_wrapper_crypt_block_xts<T256, false>;
        ctx.init             = __aes_wrapperInit<T256>;
    } else {
        err = ALC_ERROR_INVALID_SIZE;
    }
    return err;
}

template<typename T128, typename T192, typename T256>
alc_error_t
__build_aes_cipher(const Uint32 keyLen, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (keyLen == ALC_KEY_LEN_128) {
        _build_aes_cipher<T128>(keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_192) {
        _build_aes_cipher<T192>(keyLen, ctx);
    } else if (keyLen == ALC_KEY_LEN_256) {
        _build_aes_cipher<T256>(keyLen, ctx);
    } else {
        err = ALC_ERROR_INVALID_SIZE;
    }
    return err;
}

alc_error_t
CipherBuilder::Build(const alc_cipher_mode_t cipherMode,
                     const Uint64            keyLen,
                     Context&                ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (!Aes::isSupported(keyLen)) {
        return ALC_ERROR_INVALID_SIZE;
    }
    ctx.m_alcp_cipher_data.alcp_keyLen_in_bytes = keyLen / 8;

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();
    // support for eReference to be added
    if (!((cpu_feature == CpuCipherFeatures::eVaes512)
          || (cpu_feature == CpuCipherFeatures::eVaes256)
          || (cpu_feature == CpuCipherFeatures::eAesni))) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    switch (cipherMode) {
        case ALC_AES_MODE_CTR:
            if (cpu_feature == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                err = __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
                using namespace vaes;
                err = __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eAesni) {
                using namespace aesni;
                err = __build_aes_cipher<Ctr128, Ctr192, Ctr256>(keyLen, ctx);
            } else {
                return ALC_ERROR_NOT_SUPPORTED;
            }

            break;
        case ALC_AES_MODE_CBC:
            if (cpu_feature == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                err = __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
                using namespace vaes;
                err = __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eAesni) {
                using namespace aesni;
                err = __build_aes_cipher<Cbc128, Cbc192, Cbc256>(keyLen, ctx);
            } else {
                return ALC_ERROR_NOT_SUPPORTED;
            }
            break;
        case ALC_AES_MODE_CFB:
            if (cpu_feature == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                err = __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
                using namespace vaes;
                err = __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eAesni) {
                using namespace aesni;
                err = __build_aes_cipher<Cfb128, Cfb192, Cfb256>(keyLen, ctx);
            } else {
                return ALC_ERROR_NOT_SUPPORTED;
            }
            break;
        case ALC_AES_MODE_XTS:
            if (cpu_feature == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                err = __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
                using namespace vaes;
                err = __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
            } else if (cpu_feature == CpuCipherFeatures::eAesni) {
                using namespace aesni;
                err = __build_aes_cipher_xts<Xts128, Xts256>(keyLen, ctx);
            } else {
                return ALC_ERROR_NOT_SUPPORTED;
            }
            break;
        case ALC_AES_MODE_OFB:
            if ((cpu_feature == CpuCipherFeatures::eVaes512)
                || (cpu_feature == CpuCipherFeatures::eVaes256)
                || (cpu_feature == CpuCipherFeatures::eAesni)) {
                using namespace aesni;
                err = __build_aes_cipher<Ofb128, Ofb192, Ofb256>(keyLen, ctx);
            } else {
                return ALC_ERROR_NOT_SUPPORTED;
            }
            break;
        case ALC_CHACHA20:
            err = chacha20::Chacha20Builder::Build(cipherMode, keyLen, ctx);
            break;
        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

} // namespace alcp::cipher
