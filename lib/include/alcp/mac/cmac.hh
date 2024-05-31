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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once
#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "mac.hh"
#include <immintrin.h>
#include <memory>

// Low overhead union which allows __m128i registers to be represented in
// multiple formats to improve the debugging capability
union reg_128
{
    __m128i reg;
    Uint64  u64[2];
    Uint32  u32[4];
    Uint16  u16[8];
    Uint8   u8[16];
};

namespace alcp::mac {
class Cmac final
    : public IMac
    , public cipher::Aes
{
  public:
    ALCP_API_EXPORT Cmac();
    ALCP_API_EXPORT ~Cmac();
    ALCP_API_EXPORT Cmac(const Cmac& cmac);
    /**
     * @brief Update CMAC with plaintext Message
     *
     * @param pMsgBuf   Plaintext Message Buffer bytes to be updated
     * @param size      Size of the Plaintext Message Buffer in bytes
     */
    ALCP_API_EXPORT Status update(const Uint8 pMsgBuf[], Uint64 size) override;

    /**
     * @brief Update CMAC Key
     *
     * @param key   pointer to CMAC Key to be used
     * @param keyLen   Length of the key in bytes
     */
    ALCP_API_EXPORT Status init(const Uint8 key[], Uint64 keyLen);

    /**
     * @brief Reset CMAC. After resetting update can be called by the same key
     */
    ALCP_API_EXPORT Status reset() override;
    /**
     * @brief Call Finalize to copy the digest
     *
     * @param pMsgBuf   cmac buffer
     * @param size      Size of the cmac in bytes
     */
    ALCP_API_EXPORT Status finalize(Uint8 pMsgBuf[], Uint64 size) override;

  private:
    void                 getSubkeys();
    static constexpr int cAESBlockSize = 16;
    alignas(16) Uint8 m_k1[cAESBlockSize]{};
    alignas(16) Uint8 m_k2[cAESBlockSize]{};

    // Pointer to expanded keys
    const Uint8* m_encrypt_keys = nullptr;
    // Number of Aes Rounds based set based on the key
    int m_rounds{ 0 };

    // Temporary Storage Buffer to keep the plaintext data for processing
    alignas(16) Uint8 m_storage_buffer[cAESBlockSize]{};
    // No. of bytes of valid data currently stored in n_storage_buffer
    int m_storage_buffer_offset{ 0 };

    // Temporary Buffer to storage Encryption Result
    alignas(16) Uint32 m_temp_enc_result_32[cAESBlockSize / 4]{};
    Uint8* m_temp_enc_result_8 = reinterpret_cast<Uint8*>(m_temp_enc_result_32);

    // Variable to keep track of whether CMAC has been finalized or not
    bool m_finalized = false;
};

namespace avx2 {

    ALCP_API_EXPORT void get_subkeys(Uint8       k1[],
                                     Uint8       k2[],
                                     const Uint8 encrypt_keys[],
                                     const int   cNRounds);
    ALCP_API_EXPORT void load_and_left_shift_1(const Uint8 input[],
                                               Uint8       output[]);

    ALCP_API_EXPORT void update(const Uint8  plaintext[],
                                Uint8        storage_buffer[],
                                const Uint8  cEncryptKeys[],
                                Uint8        temp_enc_result[],
                                Uint32       rounds,
                                const Uint32 cNBlocks);

    ALCP_API_EXPORT void finalize(Uint8              m_storage_buffer[],
                                  unsigned int       m_storage_buffer_offset,
                                  const unsigned int cBlockSize,
                                  const Uint8        cSubKey1[],
                                  const Uint8        cSubKey2[],
                                  const Uint32       cRounds,
                                  Uint8              m_temp_enc_result[],
                                  const Uint8        cEncryptKeys[]);

} // namespace avx2
} // namespace alcp::mac