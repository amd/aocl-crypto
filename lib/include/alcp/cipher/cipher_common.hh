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

namespace alcp::cipher {

// class generator  for all ciphers
#define CIPHER_CLASS_GEN(CHILD_NEW, PARENT)                                    \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
                                                                               \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
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

// Macro to generate cipher authentication class
#define AEAD_AUTH_CLASS_GEN(CHILD_NEW, PARENT)                                 \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
            : PARENT(ctx){};                                                   \
        ~CHILD_NEW() {}                                                        \
                                                                               \
        alc_error_t getTag(alc_cipher_data_t* ctx,                             \
                           Uint8*             pOutput,                         \
                           Uint64             tagLen);                                     \
        alc_error_t init(alc_cipher_data_t* ctx,                               \
                         const Uint8*       pKey,                              \
                         Uint64             keyLen,                            \
                         const Uint8*       pIv,                               \
                         Uint64             ivLen);                                        \
        alc_error_t setAad(alc_cipher_data_t* ctx,                             \
                           const Uint8*       pInput,                          \
                           Uint64             aadLen);                                     \
        alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength);    \
    };

#define AEAD_CLASS_GEN_DOUBLE(CHILD_NEW, PARENT1, PARENT2)                     \
    class ALCP_API_EXPORT CHILD_NEW                                            \
        : private PARENT1                                                      \
        , public PARENT2                                                       \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx);                                     \
        ~CHILD_NEW() {}                                                        \
                                                                               \
      public:                                                                  \
        alc_error_t init(alc_cipher_data_t* ctx,                               \
                         const Uint8*       pKey,                              \
                         Uint64             keyLen,                            \
                         const Uint8*       pIv,                               \
                         Uint64             ivLen)                             \
        {                                                                      \
            return PARENT2::init(ctx, pKey, keyLen, pIv, ivLen);               \
        }                                                                      \
        alc_error_t encrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pInput,                         \
                            Uint8*             pOutput,                        \
                            Uint64             len);                                       \
        alc_error_t decrypt(alc_cipher_data_t* ctx,                            \
                            const Uint8*       pCipherText,                    \
                            Uint8*             pPlainText,                     \
                            Uint64             len);                                       \
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
