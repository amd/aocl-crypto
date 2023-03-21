/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher.h"

#include <array>
#include <cstdint>
#include <functional>
#include <iostream>

namespace alcp {
namespace cipher {
    typedef alc_error_t(Operation)(const Uint8* pSrc,
                                   Uint8*       pDst,
                                   Uint64       len,
                                   const Uint8* pIv) const;

    class IEncrypter
    {
      public:
        virtual alc_error_t encrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len,
                                    const Uint8* pIv) const = 0;

        /*
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
        Uint64       inputLen,
        Uint8*       pOutput,
        Uint64*      pOutputLen) = 0;*/

      protected:
        virtual ~IEncrypter() {}
        IEncrypter() {}

        std::function<alc_error_t(const void*  rCipher,
                                  const Uint8* pSrc,
                                  Uint8*       pDst,
                                  Uint64       len,
                                  const Uint8* pIv)>
            m_encrypt_fn;

      private:
    };

    class IDecrypter
    {
      public:
        virtual alc_error_t decrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len,
                                    const Uint8* pIv) const = 0;

      protected:
        virtual ~IDecrypter() {}
        IDecrypter() {}

        std::function<alc_error_t(const void*  rCipher,
                                  const Uint8* pSrc,
                                  Uint8*       pDst,
                                  Uint64       len,
                                  const Uint8* pIv)>
            m_decrypt_fn;

      private:
    };

    class IEncryptUpdater
    {
      public:
        virtual alc_error_t encryptUpdate(const Uint8* pSrc,
                                          Uint8*       pDst,
                                          Uint64       len,
                                          const Uint8* pIv) = 0;

      protected:
        virtual ~IEncryptUpdater() {}
        IEncryptUpdater() {}

        std::function<alc_error_t(const void*  rCipher,
                                  const Uint8* pSrc,
                                  Uint8*       pDst,
                                  Uint64       len,
                                  const Uint8* pIv)>
            m_encryptUpdate_fn;
    };

    class IDecryptUpdater
    {
      public:
        virtual alc_error_t decryptUpdate(const Uint8* pSrc,
                                          Uint8*       pDst,
                                          Uint64       len,
                                          const Uint8* pIv) = 0;

      protected:
        virtual ~IDecryptUpdater() {}
        IDecryptUpdater() {}

        std::function<alc_error_t(const void*  rCipher,
                                  const Uint8* pSrc,
                                  Uint8*       pDst,
                                  Uint64       len,
                                  const Uint8* pIv)>
            m_decryptUpdate_fn;
    };

} // namespace cipher

class Cipher
{

  public:
    virtual ~Cipher() {}

    /**
     * @brief           Checks if a given algorithm is supported
     * @note           Function  checks for algorithm and its
     *                  configuration for supported options
     * @param   pCipherInfo  Pointer to Cipher information
     * @return          'true' if the given configuration/cipher is
     * supported 'false' otherwise
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) = 0;

  protected:
    Cipher() {}

    // private:
    // alc_cipher_type_t m_cipher_type;
};

class ICipher
    : public cipher::IDecrypter
    , public cipher::IEncrypter
{
  public:
    ICipher() {}

  protected:
    virtual ~ICipher() {}
};

/**
 * @brief ICypherUpdater  - Class useful when stride of data is not
 *                    aligned to natural size of the algorithm
 * @note
 */
class ICipherUpdater
    : public cipher::IDecryptUpdater
    , public cipher::IEncryptUpdater
{
  public:
    ICipherUpdater() {}

  protected:
    virtual ~ICipherUpdater() {}
};

} // namespace alcp
