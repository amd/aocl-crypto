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

#ifndef _CIPHER_AES_HH_
#define _CIPHER_AES_HH_ 2

#include "alcp/cipher.h"

// #include "algorithm.hh"
#include "alcp/base.hh"
#include "alcp/cipher.hh"
#include "alcp/cipher/rijndael.hh"
#include "alcp/utils/bits.hh"

#include <immintrin.h>
#include <wmmintrin.h>

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)

namespace alcp::cipher {

using Status = alcp::base::Status;

/*
 * @brief       AES (Advanced Encryption Standard)
 *
 * @note       AES is currently same as Rijndael, This may be renamed to
 *              other as well in the future.
 *
 * TODO: We need to move the exception to an init() function. as the constructor
 * is notes fully complete, and exception would cause destructor to be called on
 * object that is not fully constructed
 */
class Aes : public Rijndael
{
  public:
    // iv info for all modes
    const Uint8* m_iv    = NULL;
    Uint64       m_ivLen = 0;
    // rounds based on keysize
    Uint32 m_nrounds = 0;
    // expanded keys
    const Uint8* m_enc_key  = {};
    const Uint8* m_dec_key  = {};
    bool         m_isIvset  = false;
    bool         m_isKeyset = false;

    Aes()
        : Rijndael()
    {}

  protected:
    virtual ~Aes() {}

    // FIXME:
    // Without CMAC-SIV extending AES, we cannot access it with protected,
    // Please change to protected if needed in future
  public:
    alc_error_t init(const Uint8* pKey,
                     const Uint64 keyLen,
                     const Uint8* pIv,
                     const Uint64 ivLen);

    static bool isSupported(const Uint32 keyLen)
    {
        if ((keyLen == ALC_KEY_LEN_128) || (keyLen == ALC_KEY_LEN_192)
            || (keyLen == ALC_KEY_LEN_256)) {
            return true;
        }
        return false;
    }

    alc_error_t setKey(const Uint8* pKey, const Uint64 keyLen);
    alc_error_t setIv(const Uint8* pIv, const Uint64 ivLen);
    void        getKey()
    {
        m_enc_key = getEncryptKeys();
        m_dec_key = getDecryptKeys();
        m_nrounds = getRounds();
    }

  protected:
    ALCP_API_EXPORT virtual Status setMode(alc_cipher_mode_t mode);

  protected:
    alc_cipher_mode_t m_mode;
    void*             m_this;
};

// class  for all AES cipher modes
#define AES_CLASS_GEN(CHILD_NEW, PARENT1, PARENT2)                             \
    class ALCP_API_EXPORT CHILD_NEW                                            \
        : PARENT1                                                              \
        , PARENT2                                                              \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(){};                                                         \
        ~CHILD_NEW(){};                                                        \
                                                                               \
      public:                                                                  \
        virtual alc_error_t encrypt(const Uint8* pPlainText,                   \
                                    Uint8*       pCipherText,                  \
                                    Uint64       len) const final;                   \
                                                                               \
        virtual alc_error_t decrypt(const Uint8* pCipherText,                  \
                                    Uint8*       pPlainText,                   \
                                    Uint64       len) const final;                   \
    };

AES_CLASS_GEN(Ofb, public Aes, public ICipher)

// class  for all AEAD cipher modes
#define AEAD_CLASS_GEN(CHILD_NEW, PARENT1)                                     \
    class ALCP_API_EXPORT CHILD_NEW : PARENT1                                  \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW() {}                                                         \
        ~CHILD_NEW() {}                                                        \
                                                                               \
      public:                                                                  \
        virtual alc_error_t encryptUpdate(const Uint8* pInput,                 \
                                          Uint8*       pOutput,                \
                                          Uint64       len);                         \
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,            \
                                          Uint8*       pPlainText,             \
                                          Uint64       len);                         \
    };

} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
