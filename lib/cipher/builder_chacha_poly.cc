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

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__chacha_poly_wrapperUpdate(void*        ctx,
                            const Uint8* pSrc,
                            Uint8*       pDest,
                            Uint64       len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);

    if constexpr (encrypt)
        e = ap->encryptUpdate(&(ctxp->m_cipher_data), pSrc, pDest, len);
    else
        e = ap->decryptUpdate(&(ctxp->m_cipher_data), pSrc, pDest, len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__chacha_poly_wrapperSetAad(void* ctx, const Uint8* pAad, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);

    e = ap->setAad(&(ctxp->m_cipher_data), pAad, len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__chacha_poly_wrapperInit(void*        ctx,
                          const Uint8* pKey,
                          const Uint64 keyLen,
                          const Uint8* pIv,
                          Uint64       ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);

    e = ap->init(&(ctxp->m_cipher_data), pKey, keyLen / 8, pIv, ivLen);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__chacha_poly_wrapperGetTag(void* ctx, Uint8* pTag, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);

    e = ap->getTag(&(ctxp->m_cipher_data), pTag, len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__chacha_poly_wrapperSetTagLength(void* ctx, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ctxp = static_cast<cipher::Context*>(ctx);
    auto ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);

    e = ap->setTagLength(&(ctxp->m_cipher_data), len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__chacha_poly_dtor(const void* ctx)
{
    alc_error_t e    = ALC_ERROR_NONE;
    auto        ctxp = static_cast<const cipher::Context*>(ctx);
    auto        ap   = static_cast<CIPHERMODE*>(ctxp->m_cipher);
    delete ap;
    return e;
}

template<typename AEADMODE>
void
_build_chach20_poly1305_wrapper(Context& ctx)
{
    auto algo = new AEADMODE(&(ctx.m_cipher_data));

    ctx.m_cipher      = static_cast<void*>(algo);
    ctx.decryptUpdate = __chacha_poly_wrapperUpdate<AEADMODE, false>;
    ctx.encryptUpdate = __chacha_poly_wrapperUpdate<AEADMODE, true>;

    ctx.setAad = __chacha_poly_wrapperSetAad<AEADMODE>;
    ctx.init   = __chacha_poly_wrapperInit<AEADMODE>;
    ctx.getTag = __chacha_poly_wrapperGetTag<AEADMODE>;

    ctx.setTagLength = __chacha_poly_wrapperSetTagLength<AEADMODE>;

    ctx.finish = __chacha_poly_dtor<AEADMODE>;
}

static Status
__build_ChaCha20_Poly1305Aead(const Uint64 keyLen, Context& ctx)
{
    Status sts = StatusOk();

    CpuCipherFeatures cpu_feature = getCpuCipherfeature();

    if (cpu_feature == CpuCipherFeatures::eVaes512) {
        using namespace chacha20::vaes512;
        _build_chach20_poly1305_wrapper<ChaCha20Poly1305AEAD>(ctx);
    } else {
        using namespace chacha20::ref;
        _build_chach20_poly1305_wrapper<ChaCha20Poly1305AEAD>(ctx);
    }
    return sts;
}

alc_error_t
chacha20::Chacha20Poly1305Builder::Build(const alc_cipher_mode_t cipherMode,
                                         const Uint64            keyLen,
                                         Context&                ctx)
{
    Status s = __build_ChaCha20_Poly1305Aead(keyLen, ctx);

    return s.code();
}

bool
chacha20::Chacha20Poly1305Builder::Supported(const alc_cipher_mode_t cipherMode,
                                             const Uint64            keyLen)
{
    if (cipherMode == ALC_CHACHA20_POLY1305 && keyLen == 256)
        return true;
    else
        return false;
}

} // namespace alcp::cipher