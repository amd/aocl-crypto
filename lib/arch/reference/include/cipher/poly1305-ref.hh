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

// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/bn.h>

#include "alcp/base.hh"
#include "alcp/mac/poly1305.hh"

namespace alcp::mac::poly1305::reference {

void
debug_dump(std::string str, BIGNUM* z);

class Poly1305BNRefState
{
  private:
    static const Uint32 m_cAccSize = 18;
    static const Uint32 m_cKeySize = 32;
    static const Uint32 m_cMsgSize = 16;

  protected:
    Uint8  m_accumulator[m_cAccSize] = {};
    Uint8  m_key[m_cKeySize]         = {};
    Uint8  m_msg_buffer[m_cMsgSize]  = {};
    Uint64 m_msg_buffer_len          = {};
    bool   m_finalized               = false;

    // Temp Bignums
    BN_CTX* m_bn_temp_ctx = nullptr;
    BIGNUM *m_key_bn = nullptr, *m_a_bn = nullptr, *m_r_bn = nullptr,
           *m_s_bn = nullptr, *m_p_bn = nullptr;

  public:
    Poly1305BNRefState() = default;
    ~Poly1305BNRefState()
    {
        std::fill(m_accumulator, m_accumulator + m_cAccSize, 0);
        std::fill(m_key, m_key + m_cKeySize, 0);
        std::fill(m_msg_buffer, m_msg_buffer + m_cMsgSize, 0);
        if (m_key_bn != nullptr) {
            BN_free(m_key_bn);
            m_key_bn = nullptr; // Clearing memory pointer
        }
        if (m_a_bn != nullptr) {
            BN_free(m_a_bn);
            m_a_bn = nullptr;
        }
        if (m_r_bn != nullptr) {
            BN_free(m_r_bn);
            m_r_bn = nullptr;
        }
        if (m_s_bn != nullptr) {
            BN_free(m_s_bn);
            m_s_bn = nullptr;
        }
        if (m_p_bn != nullptr) {
            BN_free(m_p_bn);
            m_p_bn = nullptr;
        }
        if (m_bn_temp_ctx != nullptr) {
            BN_CTX_free(m_bn_temp_ctx);
            m_bn_temp_ctx = nullptr;
        }
        m_finalized = false;
    }
};

class Poly1305RefState
{
  private:
    static const Uint32 m_cAccSize_bytes = 40;
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;

  protected:
    alignas(64) Uint64 m_accumulator[m_cAccSize_bytes / sizeof(Uint64)] = {};
    alignas(64) Uint64 m_key[m_cKeySize_bytes / sizeof(Uint64)]         = {};
    alignas(64) Uint8 m_msg_buffer[m_cMsgSize_bytes]                    = {};
    Uint64 m_msg_buffer_len                                             = {};
    bool   m_finalized                                                  = false;

  public:
    Poly1305RefState() = default;
    void resetState()
    {
        std::fill(m_accumulator,
                  m_accumulator + m_cAccSize_bytes / sizeof(Uint64),
                  0);
        std::fill(m_msg_buffer, m_msg_buffer + m_cMsgSize_bytes, 0);
        m_msg_buffer_len = 0;
        m_finalized      = false;
    }
    ~Poly1305RefState()
    {
        std::fill(m_key, m_key + m_cKeySize_bytes / sizeof(Uint64), 0);
        resetState();
    }
};

class Poly1305Common
{
  protected:
    alignas(64) const Uint8 cP[17] = { 0x03, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xfb };

  public:
    void clamp_rev(Uint8 in[16]);
    void clamp(Uint8 in[16]);
};

class Poly1305BNRef
    : public IPoly1305
    , public Poly1305Common
    , public Poly1305BNRefState
{
  public:
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return Status/Result of the operation
     */
    Status init(const Uint8 key[], Uint64 keyLen);
    /**
     * @brief Do the actual Poly1305 operation.
     * @param pMsg Byte addressible message
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    Status blk(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief Given message, updates internal state processing the message
     * @param pMsg  Byte addressible message
     * @param msgLen  Length of message in bytes
     * @return Status/Result of the operation
     */
    Status update(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief
     * @param pMsg Given message, finishes internal state processing the
     * message.
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    Status finish(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief
     * @param digest Copy the digest/mac to given buffer
     * @param length Length of the buffer to copy into
     * @return Status/Result of the operation
     */
    Status copy(Uint8 digest[], Uint64 length);
    /**
     * @brief Resets the temporary buffers without clearing key
     * @return Status/Result of the operation
     */
    Status reset();
};

class Poly1305Ref
    : public IPoly1305
    , public Poly1305Common
    , public Poly1305RefState
{
  public:
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return Status/Result of the operation
     */
    Status init(const Uint8 key[], Uint64 keyLen);
    /**
     * @brief Do the actual Poly1305 operation.
     * @param pMsg Byte addressible message
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    Uint64 blk(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief Given message, updates internal state processing the message
     * @param pMsg  Byte addressible message
     * @param msgLen  Length of message in bytes
     * @return Status/Result of the operation
     */
    Status update(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief
     * @param pMsg Given message, finishes internal state processing the
     * message.
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    Status finish(const Uint8 pMsg[], Uint64 msgLen);
    /**
     * @brief
     * @param digest Copy the digest/mac to given buffer
     * @param length Length of the buffer to copy into
     * @return Status/Result of the operation
     */
    Status copy(Uint8 digest[], Uint64 len);
    /**
     * @brief Resets the temporary buffers without clearing key
     * @return Status/Result of the operation
     */
    Status reset();
};

} // namespace alcp::mac::poly1305::reference
