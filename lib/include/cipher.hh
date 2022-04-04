/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#ifndef _INCLUDE_CIPHER_HH_
#define _INCLUDE_CIPHER_HH_ 2

#include <array>
#include <cstdint>
#include <functional>

#include "alcp/cipher.h"

#include "error.hh"
#include "types.hh"

namespace alcp {

namespace cipher {
    typedef alc_error_t(Operation)(const Uint8* pSrc,
                                   Uint8*       pDst,
                                   Uint64       len,
                                   const Uint8* pIv) const;

} // namespace cipher

class EncryptInterface
{
  public:
    virtual alc_error_t encrypt(const Uint8* pSrc,
                                Uint8*       pDst,
                                Uint64       len,
                                const Uint8* pIv) const = 0;

  protected:
    virtual ~EncryptInterface() {}
    EncryptInterface() {}

    std::function<alc_error_t(const void*  rCipher,
                              const Uint8* pSrc,
                              Uint8*       pDst,
                              Uint64       len,
                              const Uint8* pIv)>
        m_encrypt_fn;

  private:
};

class DecryptInterface
{
  public:
    virtual alc_error_t decrypt(const Uint8* pSrc,
                                Uint8*       pDst,
                                Uint64       len,
                                const Uint8* pIv) const = 0;

  protected:
    virtual ~DecryptInterface() {}
    DecryptInterface() {}

    std::function<alc_error_t(const void*  rCipher,
                              const Uint8* pSrc,
                              Uint8*       pDst,
                              Uint64       len,
                              const Uint8* pIv)>
        m_decrypt_fn;

  private:
};

class EncryptUpdateInterface
{
  public:
    virtual cipher::Operation encryptUpdate = 0;
    virtual cipher::Operation encryptFinal  = 0;

  protected:
    virtual ~EncryptUpdateInterface() {}
};

class DecryptUpdateInterface
{
  public:
    virtual cipher::Operation decryptUpdate = 0;
    virtual cipher::Operation decryptFinal  = 0;

  protected:
    virtual ~DecryptUpdateInterface() {}
    DecryptUpdateInterface() {}
};

class Cipher
{
  public:
    Cipher(alc_cipher_info_p pCipherInfo) {}
    virtual ~Cipher() {}

    /**
     * \brief           Checks if a given algorithm is supported
     * \notes           Function  checks for algorithm and its
     *                  configuration for supported options
     * \param   pCipherInfo  Pointer to Cipher information
     * \return          'true' if the given configuration/cipher is supported
     *                  'false' otherwise
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err)
#if 1
        = 0;
#else
    {
        Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
        return false;
    }
#endif

  protected:
    Cipher() {}

    static bool isVaesAvailable()
    {
        // FIXME: call cpuid::isVaesAvailable()
        static bool s_vaes_available = false;
        return s_vaes_available;
    }

    /*
     * \brief  Checks if VAESNI feature is enabled
     */
    static bool isAesniAvailable()
    {
        /*
         * FIXME: call cpuid::isAesniAvailable() initialize
         */
        static bool s_aesni_available = true;
        return s_aesni_available;
    }

  //private:
    //alc_cipher_type_t m_cipher_type;
};

class BlockCipherInterface
    : public DecryptInterface
    , public EncryptInterface
{
  public:
    BlockCipherInterface() {}
};

class BlockCipher
    : public Cipher
    , public BlockCipherInterface
{
  public:
    BlockCipher() {}

  protected:
  private:
};

#if 0
class StreamCipher : public Cipher
                   , public StreamCipherInterfacd
{
  public:
};
#endif

namespace cipher {
    // Cipher& FindCipher(alc_cipher_info_t& cipherInfo) { return nullptr; }
} // namespace cipher

} // namespace alcp

#endif /* _INCLUDE_CIPHER_HH_ */
