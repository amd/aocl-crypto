/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/rsa.h"
#include "alcp/rsa.hh"

namespace alcp::rsa {

class Context
{
  public:
    void* m_rsa    = nullptr;
    void* m_digest = nullptr;
    void* m_mgf    = nullptr;
    alc_error_t (*encryptPublicFn)(void*        pRsaHandle,
                                   const Uint8* pText,
                                   Uint64       textSize,
                                   Uint8*       pEncText);

    alc_error_t (*decryptPrivateFn)(void*        pRsaHandle,
                                    const Uint8* pEncText,
                                    Uint64       encSize,
                                    Uint8*       pText);

    alc_error_t (*encryptPublicOaepFn)(void*        pRsaHandle,
                                       const Uint8* pText,
                                       Uint64       textSize,
                                       const Uint8* label,
                                       Uint64       labelSize,
                                       const Uint8* pSeed,
                                       Uint8*       pEncText);

    alc_error_t (*decryptPrivateOaepFn)(void*        pRsaHandle,
                                        const Uint8* pEncText,
                                        Uint64       encSize,
                                        const Uint8* label,
                                        Uint64       labelSize,
                                        Uint8*       pText,
                                        Uint64&      textSize);

    alc_error_t (*signPrivatePssFn)(void*        pRsaHandle,
                                    bool         check,
                                    const Uint8* pText,
                                    Uint64       textSize,
                                    const Uint8* salt,
                                    Uint64       saltSize,
                                    Uint8*       pSignedBuff);

    alc_error_t (*verifyPublicPssFn)(void*        pRsaHandle,
                                     const Uint8* pText,
                                     Uint64       textSize,
                                     const Uint8* pSignedBuff);

    alc_error_t (*signPrivatePkcsv15Fn)(void*        pRsaHandle,
                                        bool         check,
                                        const Uint8* pText,
                                        Uint64       textSize,
                                        Uint8*       pSignedBuff);

    alc_error_t (*verifyPublicPkcsv15Fn)(void*        pRsaHandle,
                                         const Uint8* pText,
                                         Uint64       textSize,
                                         const Uint8* pSignedBuff);

    alc_error_t (*signPrivatePkcsv15WithoutHashFn)(void*        pRsaHandle,
                                                   const Uint8* pText,
                                                   Uint64       textSize,
                                                   Uint8*       decrypText);

    alc_error_t (*verifyPublicPkcsv15WithoutHashFn)(void*        pRsaHandle,
                                                    const Uint8* pText,
                                                    Uint64       textSize,
                                                    const Uint8* psignedText);

    alc_error_t (*signPrivatePssWithoutHashFn)(void*        pRsaHandle,
                                               const Uint8* pHash,
                                               Uint64       hashSize,
                                               const Uint8* salt,
                                               Uint64       saltSize,
                                               Uint8*       pSignedBuff);

    alc_error_t (*verifyPublicPssWithoutHashFn)(void*        pRsaHandle,
                                                const Uint8* pHash,
                                                Uint64       hashSize,
                                                const Uint8* pSignedBuff);

    alc_error_t (*encryptPublicPkcsv15Fn)(void*        pRsaHandle,
                                          const Uint8* pText,
                                          Uint64       textSize,
                                          Uint8*       pEncryptText,
                                          const Uint8* randomPad);

    alc_error_t (*decryptPrivatePkcsv15Fn)(void*        pRsaHandle,
                                           const Uint8* encryptedText,
                                           Uint8*       decrypText,
                                           Uint64*      textSize);

    Uint64 (*getKeySize)(void* pRsaHandle);

    alc_error_t (*getPublickey)(void* pRsaHandle, RsaPublicKey& publicKey);

    alc_error_t (*setPublicKey)(void*        pRsaHandle,
                                const Uint64 exponent,
                                const Uint8* mod,
                                const Uint64 size);
    alc_error_t (*setPublicKeyAsBignum)(void*         pRsaHandle,
                                        const BigNum* exponent,
                                        const BigNum* pModulus);

    alc_error_t (*setPrivateKey)(void*        pRsaHandle,
                                 const Uint8* dp,
                                 const Uint8* dq,
                                 const Uint8* p,
                                 const Uint8* q,
                                 const Uint8* qinv,
                                 const Uint8* mod,
                                 const Uint64 size);

    alc_error_t (*setPrivateKeyAsBignum)(void*         pRsaHandle,
                                         const BigNum* dp,
                                         const BigNum* dq,
                                         const BigNum* p,
                                         const BigNum* q,
                                         const BigNum* qinv,
                                         const BigNum* mod);

    void (*setDigest)(void* pRsaHandle, digest::IDigest* digest);
    void (*setMgf)(void* pRsaHandle, digest::IDigest* digest);

    alc_error_t (*finish)(void*);

    alc_error_t (*reset)(void*);

    alc_error_t (*duplicate)(Context* srcCtx, Context* destCtx);
};

} // namespace alcp::rsa
