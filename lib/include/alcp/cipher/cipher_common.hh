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

#ifndef _CIPHER_CIPHER_COMMON_HH_
#define _CIPHER_CIPHER_COMMON_HH_ 2

#include "alcp/cipher.h"

#include "alcp/cipher.hh"
#include "alcp/cipher/aes.hh"

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
        alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength)     \
        {                                                                      \
            return ALC_ERROR_NONE;                                             \
        }                                                                      \
    };

#if 0 // WIP
class Cipher : public Aes // and other non-aes ciphers
{

  public:
    Cipher(alc_cipher_data_t* ctx) {}
    ~Cipher() {}

  public:
    alc_error_t encrypt(alc_cipher_data_t* ctx,
                        const Uint8*       pPlainText,
                        Uint8*             pCipherText,
                        Uint64             len){};

    alc_error_t decrypt(alc_cipher_data_t* ctx,
                        const Uint8*       pCipherText,
                        Uint8*             pPlainText,
                        Uint64             len){};
};
#endif

} // namespace alcp::cipher

#endif /* _CIPHER_CIPHER_COMMON_HH_ */