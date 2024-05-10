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
#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/utils/cpuid.hh"

#include "builder.hh"

using alcp::utils::CpuCipherFeatures;
using alcp::utils::CpuId;

#include <type_traits> /* for is_same_v<> */

namespace alcp::cipher {

using Context = alcp::cipher::Context;
using namespace alcp::base;

using alcp::cipher::chacha20::Chacha20Poly1305Builder;

template<typename AEADMODE>
void
_build_aead_wrapper(Context& ctx)
{
    auto algo = new AEADMODE(&(ctx.m_alcp_cipher_data));

    ctx.m_cipher      = static_cast<void*>(algo);
    ctx.decryptUpdate = __aes_wrapperUpdate<AEADMODE, false>;
    ctx.encryptUpdate = __aes_wrapperUpdate<AEADMODE, true>;

    ctx.setAad = __aes_wrapperSetAad<AEADMODE>;
    ctx.init   = __aes_wrapperInit<AEADMODE>;
    ctx.getTag = __aes_wrapperGetTag<AEADMODE>;

    if constexpr (std::is_same_v<AEADMODE, Ccm>) {
        ctx.setTagLength = __aes_wrapperSetTagLength<AEADMODE>;
    }

    if constexpr (std::is_base_of<Ccm, AEADMODE>::value) {
        ctx.setTagLength = __aes_wrapperSetTagLength<AEADMODE>;
    }

    ctx.finish = __aes_dtor<AEADMODE>;
}

/**
 * @brief Builder specific to GCM AEAD Mode with Dispatcher
 *
 * Takes the params and builds the appropriate path given size info
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
        using namespace vaes512;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<GcmAEAD256>(ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<GcmAEAD256>(ctx);
        }
    } else {
        using namespace aesni;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<GcmAEAD128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<GcmAEAD192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<GcmAEAD256>(ctx);
        }
    }
    return sts;
}

static Status
__build_CcmAead(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<CcmAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<CcmAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<CcmAead256>(ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<CcmAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<CcmAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<CcmAead256>(ctx);
        }
    } else {
        using namespace aesni;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<CcmAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<CcmAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<CcmAead256>(ctx);
        }
    }
    return sts;
}

static Status
__build_aesSiv(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<SivAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<SivAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<SivAead256>(ctx);
        }
    } else if (cpu_feature == CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<SivAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<SivAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<SivAead256>(ctx);
        }
    } else {
        using namespace aesni;
        if (keyLen == ALC_KEY_LEN_128) {
            _build_aead_wrapper<SivAead128>(ctx);
        } else if (keyLen == ALC_KEY_LEN_192) {
            _build_aead_wrapper<SivAead192>(ctx);
        } else if (keyLen == ALC_KEY_LEN_256) {
            _build_aead_wrapper<SivAead256>(ctx);
        }
    }
    return sts;
}

// AEAD Builder
alc_error_t
CipherAeadBuilder::Build(const alc_cipher_mode_t cipherMode,
                         const Uint64            keyLen,
                         alcp::cipher::Context&  ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (cipherMode) {
        case ALC_CHACHA20_POLY1305:
            err = Chacha20Poly1305Builder::Build(cipherMode, keyLen, ctx);
            break;
        case ALC_AES_MODE_GCM:
        case ALC_AES_MODE_CCM:
        case ALC_AES_MODE_SIV:
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

    ctx.m_alcp_cipher_data.alcp_keyLen_in_bytes =
        keyLen / 8; // keyLen_in_bytes is used to verify keyLen during setKey
    // call in init

    switch (cipherMode) {
        case ALC_AES_MODE_GCM:
            sts = __build_GcmAead(keyLen, ctx);
            break;
        case ALC_AES_MODE_SIV:
            sts = __build_aesSiv(keyLen, ctx);
            break;
        case ALC_AES_MODE_CCM:
            sts = __build_CcmAead(keyLen, ctx);
            break;
        default:
            break;
    }
    return (alc_error_t)sts.code();
}

} // namespace alcp::cipher
