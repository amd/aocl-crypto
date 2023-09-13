/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"

#include "alcp/cipher/aes.hh"

#include "alcp/cipher/cipher_wrapper.hh"

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher {

#define MAX_NUM_512_BLKS 16
#define LOCAL_TABLE      1

/*
 * @brief        AES Encryption in GCM(Galois Counter mode)
 * @note        TODO: Move this to a aes_Gcm.hh or other
 */
class ALCP_API_EXPORT Gcm
    : public Aes
    , cipher::IDecryptUpdater
    , cipher::IEncryptUpdater
{

  public:
    const Uint8* m_enc_key = {};
    const Uint8* m_dec_key = {};
    Uint32       m_nrounds = 0;

    __m128i m_reverse_mask_128 =
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    const Uint8* m_iv    = nullptr;
    Uint64       m_len   = 0;
    Uint64       m_ivLen = 12; // default 12 bytes or 96bits

  public:
    explicit Gcm(const Uint8* pKey, const Uint32 keyLen)
        : Aes(pKey, keyLen)
    {
        m_enc_key = getEncryptKeys();
        m_dec_key = getDecryptKeys();
        m_nrounds = getRounds();
    }

    ~Gcm() {}

  public:
    static bool isSupported(const Uint32 keyLen)
    {
        if ((keyLen == ALC_KEY_LEN_128) || (keyLen == ALC_KEY_LEN_192)
            || (keyLen == ALC_KEY_LEN_256)) {
            return true;
        }
        return false;
    }
};

class ALCP_API_EXPORT GcmAuth : public GcmAuthData
{
  public:
    Uint64  m_tagLen = 0;
    __m128i m_tag_128; // Uint8 m_tag[16];
    Uint64  m_additionalDataLen     = 0;
    Uint64  m_isHashSubKeyGenerated = false;

#if LOCAL_TABLE
    /* precomputed hash table memory when located locally in encrypt or
    decrypt modules gives better performance for larger block sizes (>8192
    bytes )*/
    __attribute__((aligned(64))) Uint64 m_hashSubkeyTable[8];
#else
    __attribute__((aligned(64))) Uint64 m_hashSubkeyTable[MAX_NUM_512_BLKS * 8];
#endif

    /**
     * @brief Get a copy of the Tag
     *
     * @param pOutput Memory to write tag into
     * @param len     Length of the tag in bytes
     * @return alc_error_t Error code
     */
    virtual alc_error_t getTag(Uint8* pOutput, Uint64 len) = 0;

    /**
     * @brief Set the Iv in bytes
     *
     * @param len Length of IV in bytes
     * @param pIv Address to read the IV from
     * @return alc_error_t Error code
     */
    virtual alc_error_t setIv(Uint64 len, const Uint8* pIv) = 0;

    /**
     * @brief Set the Additional Data in bytes
     *
     * @param pInput Address to Read Additional Data from
     * @param len Length of Additional Data in Bytes
     * @return alc_error_t
     */
    virtual alc_error_t setAad(const Uint8* pInput, Uint64 len) = 0;

  public:
    GcmAuth() {}

    ~GcmAuth() {}
};

namespace vaes512 {

    class ALCP_API_EXPORT GcmGhash
        : public Gcm
        , public GcmAuth
    {
      public:
        explicit GcmGhash(const Uint8* pKey, const Uint32 keyLen)
            : Gcm(pKey, keyLen)
        {
        }

        ~GcmGhash() {}

        /**
         * @brief Get a copy of the Tag
         *
         * @param pOutput Memory to write tag into
         * @param len     Length of the tag in bytes
         * @return alc_error_t Error code
         */
        virtual alc_error_t getTag(Uint8* pOutput, Uint64 len);

        /**
         * @brief Set the Iv in bytes
         *
         * @param len Length of IV in bytes
         * @param pIv Address to read the IV from
         * @return alc_error_t Error code
         */
        virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

        /**
         * @brief Set the Additional Data in bytes
         *
         * @param pInput Address to Read Additional Data from
         * @param len Length of Additional Data in Bytes
         * @return alc_error_t
         */
        virtual alc_error_t setAad(const Uint8* pInput, Uint64 len);
    };

    class ALCP_API_EXPORT GcmAEAD128 : public GcmGhash
    {
      public:
        explicit GcmAEAD128(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD128() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

    class ALCP_API_EXPORT GcmAEAD192 : public GcmGhash
    {

      public:
        explicit GcmAEAD192(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD192() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

    class ALCP_API_EXPORT GcmAEAD256 : public GcmGhash
    {

      public:
        explicit GcmAEAD256(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD256() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

} // namespace vaes512

// duplication of vaes512 namespace to be avoided.
namespace aesni {
    class ALCP_API_EXPORT GcmGhash
        : public Gcm
        , public GcmAuth
    {
      public:
        explicit GcmGhash(const Uint8* pKey, const Uint32 keyLen)
            : Gcm(pKey, keyLen)
        {
        }

        ~GcmGhash() {}

        /**
         * @brief Get a copy of the Tag
         *
         * @param pOutput Memory to write tag into
         * @param len     Length of the tag in bytes
         * @return alc_error_t Error code
         */
        virtual alc_error_t getTag(Uint8* pOutput, Uint64 len);

        /**
         * @brief Set the Iv in bytes
         *
         * @param len Length of IV in bytes
         * @param pIv Address to read the IV from
         * @return alc_error_t Error code
         */
        virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

        /**
         * @brief Set the Additional Data in bytes
         *
         * @param pInput Address to Read Additional Data from
         * @param len Length of Additional Data in Bytes
         * @return alc_error_t
         */
        virtual alc_error_t setAad(const Uint8* pInput, Uint64 len);
    };

    class ALCP_API_EXPORT GcmAEAD128 : public GcmGhash
    {
      public:
        explicit GcmAEAD128(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD128() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

    class ALCP_API_EXPORT GcmAEAD192 : public GcmGhash
    {

      public:
        explicit GcmAEAD192(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD192() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

    class ALCP_API_EXPORT GcmAEAD256 : public GcmGhash
    {

      public:
        explicit GcmAEAD256(const Uint8* pKey, const Uint32 keyLen)
            : GcmGhash(pKey, keyLen)
        {
        }

        ~GcmAEAD256() {}

      public:
        /**
         * @brief   GCM Encrypt Operation
         *
         * @param   pInput      Pointer to input buffer
         *                          (plainText or Additional data)
         * @param   pOuput          Pointer to encrypted buffer
         *                          when pointer NULL, input is additional data
         * @param   len             Len of input buffer
         *                          (plainText or Additional data)
         * @param   pIv             Pointer to Initialization Vector @return
         * @return alc_error_t
         */
        virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv) override;

        /**
         * @brief   GCM Decrypt Operation
         *
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                          Uint8*       pPlainText,
                                          Uint64       len,
                                          const Uint8* pIv) override;
    };

} // namespace aesni

} // namespace alcp::cipher
