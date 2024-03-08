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
#pragma once

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuCipherFeatures;
using alcp::utils::CpuId;

namespace alcp::cipher {

using Context = alcp::cipher::Context;
using namespace alcp::base;

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapper(const void* rCipher, const Uint8* pSrc, Uint8* pDest, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<const CIPHERMODE*>(rCipher);

    if (encrypt)
        e = ap->encrypt(pSrc, pDest, len);
    else
        e = ap->decrypt(pSrc, pDest, len);

    return e;
}

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapper_crypt_block_xts(const void*  rCipher,
                              const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       currSrcLen,
                              Uint64       startBlockNum)
{
    Status e = StatusOk();

    auto ap = static_cast<CIPHERMODE*>(const_cast<void*>(rCipher));

    if constexpr (encrypt)
        e.update(ap->encryptBlocksXts(pSrc, pDest, currSrcLen, startBlockNum));
    else
        e.update(ap->decryptBlocksXts(pSrc, pDest, currSrcLen, startBlockNum));

    return !(e.ok() == 1);
}

template<typename CIPHERMODE, bool encrypt = true>
static alc_error_t
__aes_wrapperUpdate(void* rCipher, const Uint8* pSrc, Uint8* pDest, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    if constexpr (encrypt)
        e = ap->encryptUpdate(pSrc, pDest, len);
    else
        e = ap->decryptUpdate(pSrc, pDest, len);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_wrapperSetIv(void* rCipher, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->setIv(pIv, ivLen);

    return e;
}

template<typename CIPHERMODE>
static alc_error_t
__aes_wrapperInit(void*        rCipher,
                  const Uint8* pKey,
                  const Uint64 keyLen,
                  const Uint8* pIv,
                  Uint64       ivLen)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<CIPHERMODE*>(rCipher);

    e = ap->init(pKey, keyLen, pIv, ivLen);

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
getCpuCipherfeature();

} // namespace alcp::cipher