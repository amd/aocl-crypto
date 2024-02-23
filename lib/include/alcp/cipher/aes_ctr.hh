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

#include "alcp/error.h"

#include "alcp/cipher/aes.hh"

#include "alcp/cipher/cipher_wrapper.hh"

#include <cstdint>
#include <immintrin.h>
namespace alcp::cipher {

/*
 * @brief        AES Encryption in Ctr(Counter mode)
 * @note        TODO: Move this to a aes_Ctr.hh or other
 */
class ALCP_API_EXPORT Ctr : public Aes
{
  public:
    const Uint8* m_enc_key = {};
    const Uint8* m_dec_key = {};
    Uint32       m_nrounds = 0;

    Ctr() { Aes::setMode(ALC_AES_MODE_CTR); };
    ~Ctr() {}

    // FIXME: keep getKey and remove SetKey
    void getKey()
    {
        m_enc_key = getEncryptKeys();
        m_dec_key = getDecryptKeys();
        m_nrounds = getRounds();
    }

    Status setKey(const Uint8* pUserKey, Uint64 len)
    {
        Status s = Aes::setKey(pUserKey, len);
        if (s.ok()) {
            m_enc_key = getEncryptKeys();
            m_dec_key = getDecryptKeys();
            m_nrounds = getRounds();
        }
        return s;
    }
};

namespace vaes512 {
    class ALCP_API_EXPORT Ctr128
        : public Ctr
        , public ICipher
    {
      public:
        Ctr128(){};
        ~Ctr128(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr192
        : public Ctr
        , public ICipher
    {
      public:
        Ctr192(){};
        ~Ctr192(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr256
        : public Ctr
        , public ICipher
    {
      public:
        Ctr256(){};
        ~Ctr256(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

} // namespace vaes512

// duplicate of vaes512 namespace, to be removed
namespace vaes {
    class ALCP_API_EXPORT Ctr128
        : public Ctr
        , public ICipher
    {
      public:
        Ctr128(){};
        ~Ctr128(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr192
        : public Ctr
        , public ICipher
    {
      public:
        Ctr192(){};
        ~Ctr192(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr256
        : public Ctr
        , public ICipher
    {
      public:
        Ctr256(){};
        ~Ctr256(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

} // namespace vaes

// duplicate of vaes512 namespace, to be removed
namespace aesni {
    class ALCP_API_EXPORT Ctr128
        : public Ctr
        , public ICipher
    {
      public:
        Ctr128(){};
        ~Ctr128(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr192
        : public Ctr
        , public ICipher
    {
      public:
        Ctr192(){};
        ~Ctr192(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

    class ALCP_API_EXPORT Ctr256
        : public Ctr
        , public ICipher
    {
      public:
        Ctr256(){};
        ~Ctr256(){};

      public:
        /**
         * @brief   CTR Encrypt Operation
         * @note
         * @param   pPlainText      Pointer to output buffer
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t encrypt(const Uint8* pPlainText,
                                    Uint8*       pCipherText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;

        /**
         * @brief   CTR Decrypt Operation
         * @note
         * @param   pCipherText     Pointer to encrypted buffer
         * @param   pPlainText      Pointer to output buffer
         * @param   len             Len of plain and encrypted text
         * @param   pIv             Pointer to Initialization Vector
         * @return  alc_error_t     Error code
         */
        virtual alc_error_t decrypt(const Uint8* pCipherText,
                                    Uint8*       pPlainText,
                                    Uint64       len,
                                    const Uint8* pIv) const final;
    };

} // namespace aesni

namespace aes {

    using namespace aesni;
    using namespace vaes;

    template<typename T>
    Uint64 ctrBlk(const T*       p_in_x,
                  T*             p_out_x,
                  Uint64         blocks,
                  const __m128i* pkey128,
                  const Uint8*   pIv,
                  int            nRounds,
                  Uint8          factor)
    {
        T a1, a2, a3, a4;
        T b1, b2, b3, b4;
        T c1, c2, c3, c4, swap_ctr;
        T one_lo, one_x, two_x, three_x, four_x;

        ctrInit(
            &c1, pIv, &one_lo, &one_x, &two_x, &three_x, &four_x, &swap_ctr);

        Uint64 blockCount4 = 4 * factor;
        Uint64 blockCount2 = 2 * factor;
        Uint64 blockCount1 = factor;

        for (; blocks >= blockCount4; blocks -= blockCount4) {

            c2 = alcp_add_epi64(c1, one_x);
            c3 = alcp_add_epi64(c1, two_x);
            c4 = alcp_add_epi64(c1, three_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);
            a3 = alcp_loadu(p_in_x + 2);
            a4 = alcp_loadu(p_in_x + 3);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);
            b3 = alcp_shuffle_epi8(c3, swap_ctr);
            b4 = alcp_shuffle_epi8(c4, swap_ctr);

            AesEncrypt(&b1, &b2, &b3, &b4, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);
            a3 = alcp_xor(b3, a3);
            a4 = alcp_xor(b4, a4);

            // increment counter
            c1 = alcp_add_epi64(c1, four_x);

            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);
            alcp_storeu(p_out_x + 2, a3);
            alcp_storeu(p_out_x + 3, a4);

            p_in_x += 4;
            p_out_x += 4;
        }

        for (; blocks >= blockCount2; blocks -= blockCount2) {
            c2 = alcp_add_epi64(c1, one_x);

            a1 = alcp_loadu(p_in_x);
            a2 = alcp_loadu(p_in_x + 1);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            b2 = alcp_shuffle_epi8(c2, swap_ctr);

            AesEncrypt(&b1, &b2, pkey128, nRounds);

            a1 = alcp_xor(b1, a1);
            a2 = alcp_xor(b2, a2);

            // increment counter
            c1 = alcp_add_epi64(c1, two_x);
            alcp_storeu(p_out_x, a1);
            alcp_storeu(p_out_x + 1, a2);

            p_in_x += 2;
            p_out_x += 2;
        }

        for (; blocks >= blockCount1; blocks -= blockCount1) {
            a1 = alcp_loadu(p_in_x);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi64(c1, one_x);

            alcp_storeu(p_out_x, a1);

            p_in_x += 1;
            p_out_x += 1;
        }

        // residual block=1 when factor = 2, load and store only lower half.

        for (; blocks != 0; blocks--) {
            a1 = alcp_loadu_128(p_in_x);

            // re-arrange as per spec
            b1 = alcp_shuffle_epi8(c1, swap_ctr);
            AesEncrypt(&b1, pkey128, nRounds);
            a1 = alcp_xor(b1, a1);

            // increment counter
            c1 = alcp_add_epi64(c1, one_lo);

            alcp_storeu_128(p_out_x, a1);
            p_in_x  = (T*)(((__uint128_t*)p_in_x) + 1);
            p_out_x = (T*)(((__uint128_t*)p_out_x) + 1);
        }
        return blocks;
    }

} // namespace aes
} // namespace alcp::cipher
