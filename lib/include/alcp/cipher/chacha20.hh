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

#include "alcp/base.hh"
#include "alcp/error.h"
#include "alcp/utils/cpuid.hh"

namespace alcp::cipher::chacha20 {
using utils::CpuCipherFeatures;
using utils::CpuId;

static constexpr Uint32 Chacha20Constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};
#define CHACHA20_BLOCK_SIZE 64

template<CpuCipherFeatures cpu_cipher_feature = CpuCipherFeatures::eDynamic>
class ALCP_API_EXPORT ChaCha20
{
    // Key Length of Chacha20 is fixed as 256 bits
    static constexpr Uint64 cMKeylen = 256 / 8;
    // array to store the key
    alignas(16) Uint8 m_key[cMKeylen];

    static constexpr Uint64 cMIvlen     = (128 / 8);
    static constexpr int    cMBlockSize = CHACHA20_BLOCK_SIZE;

  protected:
    alignas(16) Uint8 m_iv[cMIvlen];

  public:
    /**
     * @brief Method to set the Chacha20 Key.
     * @param [in] key Chacha20 key for encryption/decryption
     * @param [in] keylen keylength of the Chacha20 Key in bytes . It must be 16
     * bytes.
     * @return Error code
     */
    alc_error_t setKey(const Uint8 key[], Uint64 keylen);

    /**
     * @brief Method to set the Chacha20 Iv.
     * @param [in] iv Chacha20 iv for encryption/decryption
     * @param [in] ivlen Length of the Chacha20 iv provided in bytes. Iv length
     * must be 16 bytes.
     * @return Error code
     */
    alc_error_t setIv(const Uint8 iv[], Uint64 ivlen);

    /**
     * @brief Encryption/Decryption function of Chacha20 Algorithm taking
     * plaintext/ciphertext as input and produces the output. Both Encrypt and
     * Decrypt uses the same function as Chacha20 encrypt and decrypt path is
     * same.
     * @param [in] plaintext Input to the Chacha20 Algorithm
     * @param [in] plaintext_length Input/Output Length of the provided
     * plaintext/ciphertext
     * @param [out] ciphertext Output from the Chacha20 Algorithm
     * @return
     */
    alc_error_t processInput(const Uint8 plaintext[],
                             Uint64      plaintext_length,
                             Uint8       ciphertext[]);

    /**
     * @brief Validates Chacha20 Key and returns an error code for invalid Key.
     * @param [in] key Chacha20 key for encryption/decryption
     * @param [in] keylen keylength of the Chacha20 Key in bytes . It must be 16
     * bytes.
     * @return Error code
     */
    static alc_error_t validateKey(const Uint8* key, Uint64 keylen);
    /**
     * @brief Validates Chacha20 Iv and returns an error code for invalid Iv.
     * @param [in] iv Chacha20 iv for encryption/decryption
     * @param [in] ivlen ivlength of the Chacha20 Iv in bytes . It must be 16
     * bytes.
     * @return Error code
     */
    static alc_error_t validateIv(const Uint8 iv[], Uint64 iVlen);

    /**
     * @brief Get the Chacha20 Keystream of @ref key_stream_length for the
     * provided key and iv
     * @param [out] output_key_stream Buffer for storing the key stream
     * @param [in] key_stream_length Length of the keystream required.
     * @return
     */
    alc_error_t getKeyStream(Uint8  output_key_stream[],
                             Uint64 key_stream_length);
};

} // namespace alcp::cipher::chacha20
