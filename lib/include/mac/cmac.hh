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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once
#include "alcp/alcp.h"
#include "mac.hh"
#include <immintrin.h>
#include <memory>

// Low overhead union which allows __m128i registers to be represented in
// multiple formats to improve the debugging capability
union reg_128
{
    __m128i  reg;
    uint64_t u64[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t  u8[16];
};

namespace alcp::mac {
class Cmac final : public Mac
{
  public:
    Cmac();
    /**
     * @brief CMAC Constructor
     *
     * @param cinfo   Cipher Information about the cipher algorithm used in CMAC
     * @param keyInfo CMAC Key Information
     */
    Cmac(const alc_cipher_info_t& cinfo, const alc_key_info_t& keyInfo);
    ~Cmac();
    /**
     * @brief Update CMAC with plaintext Message
     *
     * @param pMsgBuf   Plaintext Message Buffer bytes to be updated
     * @param size      Size of the Plaintext Message Buffer in bytes
     */
    alcp::base::Status update(const Uint8* pMsgBuf, Uint64 size) override;

    /**
     * @brief Finish CMAC. Other calls are not valid after finish
     */
    void finish() override;

    /**
     * @brief Reset CMAC. After resetting update can be called by the same key
     */
    alcp::base::Status reset() override;
    /**
     * @brief Finalize CMAC with any remaining data. After Finalize call Mac can
     * be copied using copy function
     *
     * @param pMsgBuf   Plaintext Message Buffer bytes remaining to be updated
     * @param size      Size of the Plaintext Message Buffer in bytes
     */
    alcp::base::Status finalize(const Uint8* pMsgBuf, Uint64 size) override;
    /**
     * @brief Copy MAC to memory pointer by buff . Should be called only after
     * Mac has been Finalized.
     *
     * @param buff      Output Buffer to which Mac will be copied
     * @param size      Size of the buffer in bytes. Should be greater than or
     * equal to 16.
     */
    alcp::base::Status copy(Uint8* buff, Uint32 size);

  private:
    class Impl;
    std::unique_ptr<Impl> m_pImpl;
    const Impl*           pImpl() const { return m_pImpl.get(); }
    Impl*                 pImpl() { return m_pImpl.get(); }
};

namespace avx2 {
    void processChunk(Uint8*       temp_enc_result,
                      Uint8*       storage_buffer,
                      const Uint8* encrypt_keys,
                      const int    n_rounds);

    void get_subkeys(std::vector<Uint8>& k1,
                     std::vector<Uint8>& k2,
                     const Uint8*        encrypt_keys,
                     const int           n_rounds);
    void load_and_left_shift_1(const Uint8* input, Uint8* output);

} // namespace avx2
} // namespace alcp::mac