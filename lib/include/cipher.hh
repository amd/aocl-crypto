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

#ifndef _INCLUDE_CIPHER_HH_
#define _INCLUDE_CIPHER_HH_ 2

#include <array>
#include <cstdint>
#include <functional>

#include "alcp/cipher.h"

#include "error.hh"

namespace alcp {

namespace cipher {

    typedef alc_error_t(CipherFunction)(const uint8_t* pSrc,
                                        uint8_t*       pDst,
                                        uint64_t       len,
                                        const uint8_t* pKey,
                                        const uint8_t* pIv);
} // namespace cipher

class Encrypter
{
  public:
    virtual cipher::CipherFunction encrypt = 0;

  protected:
    virtual ~Encrypter() {}
};

class Decrypter
{
  public:
#if 0
    virtual alc_error_t decrypt(const uint8_t* pSrc,
                                uint8_t*       pDst,
                                const uint8_t* pKey,
                                uint64_t       len) = 0;
#else
    virtual cipher::CipherFunction decrypt = 0;
#endif

  protected:
    virtual ~Decrypter() {}
};

class EncryptUpdater
{
  public:
    virtual cipher::CipherFunction encryptUpdate = 0;
    virtual cipher::CipherFunction encryptFinal  = 0;

  protected:
    virtual ~EncryptUpdater() {}
};

class DecryptUpdater
{
  public:
    virtual cipher::CipherFunction decryptUpdate = 0;
    virtual cipher::CipherFunction decryptFinal  = 0;

  protected:
    virtual ~DecryptUpdater() {}

  private:
    DecryptUpdater() {}
};

class Cipher
{
  protected:
    Cipher() {}
    virtual ~Cipher() {}

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

  public:
    /*
     * TODO: This probably not needed, Look into removing this
     *
     * we should not allow the memory for the
     * object to be allocated outside the library, this will complicate things.
     *
     */
    // virtual uint64_t getContextSize(const alc_cipher_info_p pCipherInfo,
    //                              alc_error_t&            err) = 0;
};

class BlockCipher
    : public Cipher
    //    , public Encrypter
    , public Decrypter
{};

class StreamCipher
    : public Cipher
    , public EncryptUpdater
    , public DecryptUpdater
{};

} // namespace alcp

#endif /* _INCLUDE_CIPHER_HH_ */
