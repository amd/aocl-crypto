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

#include "alcp/cipher.h"
#include "alcp/cipher.hh"

#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher {

#define UNROLL_2 _Pragma("GCC unroll 2")
#define UNROLL_8 _Pragma("GCC unroll 8")
#define UNROLL_4 _Pragma("GCC unroll 4")

typedef struct _alc_gcm_local_data
{
    // gcm specific params
    Int32 m_num_512blks_precomputed;
    Int32 m_num_256blks_precomputed;

    __m128i m_hash_subKey_128;
    __m128i m_gHash_128;
    __m128i m_counter_128;

    __m128i m_reverse_mask_128;

    Uint64* m_pHashSubkeyTable_global;

    __m128i m_tag_128;
    Uint64  m_additionalDataLen;

    _alc_cipher_gcm_data_t m_gcm;

} alc_gcm_local_data_t;

// class generator with interface
#define CIPHER_CLASS_GEN_(CHILD_NEW, PARENT, INTERFACE, KEYLEN_IN_BYTES)       \
    class ALCP_API_EXPORT CHILD_NEW                                            \
        : public PARENT                                                        \
        , public INTERFACE                                                     \
                                                                               \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW()                                                            \
            : PARENT(KEYLEN_IN_BYTES)                                          \
        {}                                                                     \
        ~CHILD_NEW() = default;                                                \
                                                                               \
      public:                                                                  \
        alc_error_t encrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pPlainText,                     \
                            Uint8*             pCipherText,                    \
                            Uint64             len) override;                              \
                                                                               \
        alc_error_t decrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pCipherText,                    \
                            Uint8*             pPlainText,                     \
                            Uint64             len) override;                              \
    };

// class generator  for all ciphers
#define CIPHER_CLASS_GEN(CHILD_NEW, PARENT)                                    \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
                                                                               \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx = nullptr)                            \
            : PARENT(ctx){};                                                   \
        ~CHILD_NEW(){};                                                        \
                                                                               \
      public:                                                                  \
        alc_error_t encrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pPlainText,                     \
                            Uint8*             pCipherText,                    \
                            Uint64             len);                                       \
                                                                               \
        alc_error_t decrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pCipherText,                    \
                            Uint8*             pPlainText,                     \
                            Uint64             len);                                       \
    };

#define CIPHER_CLASS_GEN_DOUBLE(CHILD_NEW, PARENT1, PARENT2)                   \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT2                           \
    {                                                                          \
      private:                                                                 \
        PARENT1* ctrobj;                                                       \
                                                                               \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
            : PARENT2(ctx)                                                     \
        {                                                                      \
            ctrobj = new PARENT1(ctx);                                         \
            /*ctrobj->setMode(ALC_AES_MODE_SIV);*/                             \
        }                                                                      \
        ~CHILD_NEW() { delete ctrobj; }                                        \
                                                                               \
      public:                                                                  \
        alc_error_t encrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pInput,                         \
                            Uint8*             pOutput,                        \
                            Uint64             len);                                       \
        alc_error_t decrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pCipherText,                    \
                            Uint8*             pPlainText,                     \
                            Uint64             len);                                       \
    };

// Macro to generate cipher authentication class
#define AEAD_AUTH_CLASS_GEN(CHILD_NEW, PARENT)                                 \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
            : PARENT(ctx)                                                      \
        {}                                                                     \
        ~CHILD_NEW() {}                                                        \
                                                                               \
        alc_error_t getTag(alc_cipher_data_t* ctx,                             \
                           Uint8*             pOutput,                         \
                           Uint64             tagLen);                                     \
        alc_error_t setAad(alc_cipher_data_t* ctx,                             \
                           const Uint8*       pInput,                          \
                           Uint64             aadLen);                                     \
        alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength);    \
    };

#define CRYPT_WRAPPER_FUNC(                                                    \
    CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, PKEY, NUM_ROUNDS, IS_ENC)             \
    alc_error_t CLASS_NAME::WRAPPER_FUNC(alc_cipher_data_t* ctx,               \
                                         const Uint8*       pinput,            \
                                         Uint8*             pOutput,           \
                                         Uint64             len)               \
    {                                                                          \
        alc_error_t err = ALC_ERROR_NONE;                                      \
        m_isEnc_aes     = IS_ENC;                                              \
        err = FUNC_NAME(pinput, pOutput, len, PKEY, NUM_ROUNDS, m_pIv_aes);    \
        return err;                                                            \
    }

} // namespace alcp::cipher
