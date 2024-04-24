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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include "alcp/cipher/chacha20.hh"
#include "alcp/mac/poly1305.hh"

namespace alcp::cipher::chacha20 {

#define CHACHA_POLY_AEAD_AUTH_CLASS_GEN(CHILD_NEW, PARENT)                     \
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

#define AEAD_CLASS_GEN(CHILD_NEW, PARENT)                                      \
    class ALCP_API_EXPORT CHILD_NEW : public PARENT                            \
    {                                                                          \
      public:                                                                  \
        CHILD_NEW(alc_cipher_data_t* ctx)                                      \
            : PARENT(ctx){};                                                   \
        ~CHILD_NEW() {}                                                        \
                                                                               \
      public:                                                                  \
        alc_error_t encryptUpdate(alc_cipher_data_t* ctx,                      \
                                  const Uint8*       pInput,                   \
                                  Uint8*             pOutput,                  \
                                  Uint64             len);                                 \
        alc_error_t decryptUpdate(alc_cipher_data_t* ctx,                      \
                                  const Uint8*       pCipherText,              \
                                  Uint8*             pPlainText,               \
                                  Uint64             len);                                 \
    };

// These will be used to store the length of the ciphertext
union len_input_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

union len_aad_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

using utils::CpuArchFeature;

template<class ChaChaKey,
         CpuCipherFeatures cpu_cipher_feature = CpuCipherFeatures::eDynamic>
class ALCP_API_EXPORT ChaCha20Poly1305
    : public ChaChaKey
    , public alcp::mac::poly1305::Poly1305<CpuArchFeature::eDynamic>
{
  private:
    Uint8               m_poly1305_key[32]{};
    const Uint8         m_zero_padding[16]{};
    len_input_processed m_len_input_processed{};
    len_aad_processed   m_len_aad_processed{};

  public: // Need to be protected
    alc_error_t setIv(const Uint8* iv, Uint64 ivLen);
    alc_error_t setKey(const Uint8 key[], Uint64 keylen);

  public:
    ChaCha20Poly1305() = default;
    ChaCha20Poly1305(alc_cipher_data_t* ctx);
    alc_error_t init(alc_cipher_data_t* ctx,
                     const Uint8*       pKey,
                     Uint64             keyLen,
                     const Uint8*       pIv,
                     Uint64             ivLen);
    alc_error_t setAad(const Uint8* pInput, Uint64 len);

    // Depending on the context(encrypt/decrypt) the inputBuffer and
    // outputBuffer will switch between ciphertext and plaintext buffers
    template<bool is_encrypt>
    alc_error_t processInput(const Uint8 inputBuffer[],
                             Uint64      bufferLength,
                             Uint8       outputBuffer[]);
    alc_error_t encryptupdate(const Uint8 plaintext[],
                              Uint64      plaintextLength,
                              Uint8       ciphertext[]);
    alc_error_t decryptupdate(const Uint8 ciphertext[],
                              Uint64      ciphertextLength,
                              Uint8       plaintext[]);
    alc_error_t setTagLength(Uint64 tagLength);

    alc_error_t getTag(Uint8* pOutput, Uint64 len);
};

namespace vaes512 {
    // CHACHA_POLY_AEAD_AUTH_CLASS_GEN(
    //     ChaCha20Poly1305Hash,
    //     ChaCha20Poly1305<CpuCipherFeatures::eVaes512, ChaCha256>);
    class ALCP_API_EXPORT ChaCha20Poly1305Hash
        : public ChaCha20Poly1305<ChaCha256, CpuCipherFeatures::eVaes512>
    {
      public:
        ChaCha20Poly1305Hash(alc_cipher_data_t* ctx)
            : ChaCha20Poly1305<ChaCha256, CpuCipherFeatures::eVaes512>(ctx){};
        ~ChaCha20Poly1305Hash() {}

        alc_error_t getTag(alc_cipher_data_t* ctx,
                           Uint8*             pOutput,
                           Uint64             tagLen);
        alc_error_t init(alc_cipher_data_t* ctx,
                         const Uint8*       pKey,
                         Uint64             keyLen,
                         const Uint8*       pIv,
                         Uint64             ivLen);
        alc_error_t setAad(alc_cipher_data_t* ctx,
                           const Uint8*       pInput,
                           Uint64             aadLen);
        alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength);
    };
    AEAD_CLASS_GEN(ChaCha20Poly1305AEAD, ChaCha20Poly1305Hash);
} // namespace vaes512

namespace ref {
    // CHACHA_POLY_AEAD_AUTH_CLASS_GEN(
    //     ChaCha20Poly1305Hash,
    //     ChaCha20Poly1305<CpuCipherFeatures::eReference, ChaCha256>);
    class ALCP_API_EXPORT ChaCha20Poly1305Hash
        : public ChaCha20Poly1305<ChaCha256, CpuCipherFeatures::eReference>
    {
      public:
        ChaCha20Poly1305Hash(alc_cipher_data_t* ctx)
            : ChaCha20Poly1305<ChaCha256, CpuCipherFeatures::eReference>(ctx){};
        ~ChaCha20Poly1305Hash() {}

        alc_error_t getTag(alc_cipher_data_t* ctx,
                           Uint8*             pOutput,
                           Uint64             tagLen);
        alc_error_t init(alc_cipher_data_t* ctx,
                         const Uint8*       pKey,
                         Uint64             keyLen,
                         const Uint8*       pIv,
                         Uint64             ivLen);
        alc_error_t setAad(alc_cipher_data_t* ctx,
                           const Uint8*       pInput,
                           Uint64             aadLen);
        alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength);
    };
    AEAD_CLASS_GEN(ChaCha20Poly1305AEAD, ChaCha20Poly1305Hash);
} // namespace ref

} // namespace alcp::cipher::chacha20