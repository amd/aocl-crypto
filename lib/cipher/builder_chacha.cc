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

#include "alcp/cipher/chacha20_build.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {
// ChaCha Path

using Context = alcp::cipher::Context;
using namespace alcp::base;

template<typename CHACHA>
static alc_error_t
__chacha20_wrapperInit(void*        ctx,
                       const Uint8* pKey,
                       const Uint64 keyLen,
                       const Uint8* pIv,
                       Uint64       ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CHACHA*>(ctxp->m_cipher);

    e = ap->init(&(ctxp->m_cipher_data), pKey, keyLen / 8, pIv, ivLen);

    return e;
}

template<typename CHACHA>
static alc_error_t
__chacha20_encryptWrapper(void*        ctx,
                          const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CHACHA*>(ctxp->m_cipher);

    e = ap->encrypt(&(ctxp->m_cipher_data), pSrc, pDest, len);

    return e;
}

template<typename CHACHA>
static alc_error_t
__chacha20_decryptWrapper(void*        ctx,
                          const Uint8* pSrc,
                          Uint8*       pDest,
                          Uint64       len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CHACHA*>(ctxp->m_cipher);

    e = ap->decrypt(&(ctxp->m_cipher_data), pSrc, pDest, len);

    return e;
}

template<typename CHACHA>
static alc_error_t
__chacha20_processInputWrapper(void*        ctx,
                               const Uint8* pSrc,
                               Uint8*       pDest,
                               Uint64       len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CHACHA*>(ctxp->m_cipher);

    e = ap->processInput(pSrc, len, pDest);

    return e;
}

template<typename CHACHA>
static alc_error_t
__chacha20_FinishWrapper(const void* ctx)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<const cipher::Context*>(ctx);
    auto ap   = static_cast<const CHACHA*>(ctxp->m_cipher);
    delete ap;

    return e;
}

template<typename CHACHA>
alc_error_t
__build_chacha20(const alc_cipher_mode_t cipherMode,
                 const Uint64            keyLen,
                 Context&                ctx)
{
    CHACHA* chacha = new CHACHA();
    ctx.m_cipher   = chacha;

    ctx.init    = __chacha20_wrapperInit<CHACHA>;
    ctx.encrypt = __chacha20_encryptWrapper<CHACHA>;
    ctx.decrypt = __chacha20_decryptWrapper<CHACHA>;
    ctx.finish  = __chacha20_FinishWrapper<CHACHA>;

    return ALC_ERROR_NONE;
}

alc_error_t
chacha20::Chacha20Builder::Build(const alc_cipher_mode_t cipherMode,
                                 const Uint64            keyLen,
                                 Context&                ctx)
{
    CpuCipherFeatures cpu_cipher_feature = getCpuCipherfeature();
    if (cpu_cipher_feature == CpuCipherFeatures::eVaes512) {
        __build_chacha20<vaes512::ChaCha256>(cipherMode, keyLen, ctx);
    } else {
        __build_chacha20<ref::ChaCha256>(cipherMode, keyLen, ctx);
    }

    return ALC_ERROR_NONE;
}

bool
chacha20::Chacha20Builder::Supported(const alc_cipher_mode_t cipherMode,
                                     const Uint64            keyLen)
{
    if (cipherMode == ALC_CHACHA20 && keyLen == 256)
        return true;
    else
        return false;
}
} // namespace alcp::cipher