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

#include "config.h"

#include "alcp/base.hh"
#include "alcp/cipher_aead.h"

#include <array>
#include <cstdint>
#include <functional>
#include <iostream>

namespace alcp { namespace cipher {
    // Different implementation of crypt class required based on ISA support in
    // hardware
    class Crypter
    {
      public:
        virtual ~Crypter()                      = default;
        virtual alc_error_t decrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len) = 0;
        virtual alc_error_t encrypt(const Uint8* pSrt,
                                    Uint8*       pDrc,
                                    Uint64       len) = 0;
        virtual alc_error_t finish(const void*) = 0;
    };

    class CipherInterface : public Crypter
    {

      public:
        virtual ~CipherInterface() = default;

        // Set key & iv
        virtual alc_error_t init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen) = 0;
    };

    // Additional Authentication functionality used for AEAD schemes
    class CipherAuth
    {
      public:
        virtual ~CipherAuth()                                        = default;
        virtual alc_error_t setAad(const Uint8* pAad, Uint64 aadLen) = 0;
        virtual alc_error_t getTag(Uint8* pTag, Uint64 tagLen)       = 0;

        /* setPlaintextLength and setTageLength to be one single api */
        /* setLength(void*ctx, typeofLen, Uint64 len) */
        virtual alc_error_t setTagLength(Uint64 tagLen) = 0;
    };

    class CipherAEADInterface
        : public virtual CipherInterface // cipherInterface class
        , public virtual CipherAuth // authenication class - optional based on
                                    // cipher mode
    {
      public:
        virtual ~CipherAEADInterface() = default;
    };

}} // namespace alcp::cipher