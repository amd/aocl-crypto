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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include "alcp/base.hh"

namespace alcp::mac::poly1305::reference {

class Poly1305Ref
{
  public:
    Poly1305Ref() = default;

  private:
    static const Uint32 m_cAccSize_bytes = 40;
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;
    static const Uint32 m_limbs          = 5;

    alignas(64) Uint8 m_msg_buffer[m_cMsgSize_bytes]                    = {};
    alignas(64) Uint64 m_accumulator[m_cAccSize_bytes / sizeof(Uint64)] = {};
    alignas(64) Uint64 m_key[m_cKeySize_bytes / sizeof(Uint64)]         = {};
    alignas(64) Uint64 m_r[m_limbs]                                     = {};
    alignas(64) Uint64 m_s[m_limbs - 1]                                 = {};
    Uint64 m_msg_buffer_len                                             = {};
    bool   m_finalized                                                  = false;

  public:
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return alc_error_t/Result of the operation
     */
    alc_error_t init(const Uint8 key[], Uint64 keyLen);
    /**
     * @brief Given message, updates internal state processing the message
     * @param pMsg  Byte addressible message
     * @param msgLen  Length of message in bytes
     * @return alc_error_t/Result of the operation
     */
    alc_error_t update(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief finishes internal state processing
     * @param digest Copy the digest/mac to given buffer
     * @param length Length of the buffer to copy into
     * @return alc_error_t/Result of the operation
     */
    alc_error_t finish(Uint8 digest[], Uint64 length);
    /**
     * @brief Resets the temporary buffers without clearing key
     * @return alc_error_t/Result of the operation
     */
    alc_error_t reset();
};

} // namespace alcp::mac::poly1305::reference
