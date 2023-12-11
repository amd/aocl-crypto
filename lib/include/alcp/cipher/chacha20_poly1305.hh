/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/chacha20.hh"
#include "alcp/mac/poly1305.hh"

using namespace alcp::cipher::chacha20;
namespace alcp::cipher::chacha20 {

union len_ciphertext_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};

union len_aad_processed
{
    Uint64 u64 = 0;
    Uint8  u8[8];
};
template<CpuCipherFeatures cpu_cipher_feature = CpuCipherFeatures::eDynamic>
class ChaCha20Poly1305
    : public ChaCha20<cpu_cipher_feature>
    , public alcp::mac::poly1305::Poly1305
{
  private:
    Uint8 m_poly1305_key[32] = {};

    // Uint64 m_len_ciphertext_processed = 0;
    len_ciphertext_processed m_len_ciphertext_processed{};
    len_aad_processed        m_len_aad_processed{};

    // Uint64 m_len_aad_processed = 0;

    const Uint8 m_zero_padding[16]{};

  public:
    alc_error_t setNonce(const Uint8* nonce, Uint64 nonce_length);
    alc_error_t setKey(const Uint8 key[], Uint64 keylen);
    alc_error_t setAad(const Uint8* pInput, Uint64 len);
    template<bool is_encrypt>
    alc_error_t processInput(const Uint8 plaintext[],
                             Uint64      plaintext_length,
                             Uint8       ciphertext[]);
    alc_error_t encryptupdate(const Uint8 plaintext[],
                              Uint64      plaintext_length,
                              Uint8       ciphertext[]);
    alc_error_t decryptupdate(const Uint8 ciphertext[],
                              Uint64      ciphertext_length,
                              Uint8       plaintext[]);
    alc_error_t setTagLength(Uint64 tag_length);

    alc_error_t getTag(Uint8* pOutput, Uint64 len);
};

} // namespace alcp::cipher::chacha20