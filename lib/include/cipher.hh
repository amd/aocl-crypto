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
#include <array>
#include <cstdint>
#include <functional>

#include "alcp/cipher.h"
#ifdef ALCP_ENABLE_AOCL_CPUID
#include "alci/cpu_features.h"
#endif

#include "error.hh"
#include "types.hh"

#include <functional>
#include <iostream>

namespace alcp {
namespace cipher {
    typedef alc_error_t(Operation)(const Uint8* pSrc,
                                   Uint8*       pDst,
                                   Uint64       len,
                                   const Uint8* pIv) const;
    typedef enum
    {
        AVX512_DQ = 1,
        AVX512_F,
        AVX512_BW,
    } avx512_flags_t;

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
     * \brief           Checks if a given algorithm is supported
     * \notes           Function  checks for algorithm and its
     *                  configuration for supported options
     * \param   pCipherInfo  Pointer to Cipher information
     * \return          'true' if the given configuration/cipher is
     * supported 'false' otherwise
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
#ifdef ALCP_ENABLE_AOCL_CPUID
        static bool s_vaes_available = (alc_cpu_has_vaes() > 0);
#else
        static bool s_vaes_available     = false;
#endif
        return s_vaes_available;
    }

    static bool isAvx512Has(cipher::avx512_flags_t flag)
    {
// static bool s_vaes_available = (alc_cpu_has_vaes() > 0);
#ifdef ALCP_ENABLE_AOCL_CPUID
        static bool s_avx512f_available  = (alc_cpu_has_avx512f() > 0);
        static bool s_avx512dq_available = (alc_cpu_has_avx512dq() > 0);
        static bool s_avx512bw_available = (alc_cpu_has_avx512bw() > 0);
#else
        static bool s_avx512f_available  = false;
        static bool s_avx512dq_available = false;
        static bool s_avx512bw_available = false;
#endif
        switch (flag) {
            case cipher::AVX512_DQ:
                return s_avx512dq_available;
            case cipher::AVX512_F:
                return s_avx512f_available;
            case cipher::AVX512_BW:
                return s_avx512bw_available;
        }
        return false;
    }

    /*
     * \brief  Checks if VAESNI feature is enabled
     */
    static bool isAesniAvailable()
    {
#ifdef ALCP_ENABLE_AOCL_CPUID
        static bool s_aesni_available = (alc_cpu_has_aes() > 0);
#else
        static bool s_aesni_available    = true;
#endif
        return s_aesni_available;
    }

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
 * @notes
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
