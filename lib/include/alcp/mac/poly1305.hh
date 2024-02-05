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
#include <openssl/bn.h>

#include "alcp/base.hh"
#include "alcp/mac/mac.hh"

namespace alcp::mac::poly1305 {
class ALCP_API_EXPORT IPoly1305
{
  public:
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return Status/Result of the operation
     */
    virtual Status init(const Uint8 key[], Uint64 keyLen) = 0;
    /**
     * @brief Given message, updates internal state processing the message
     * @param pMsg  Byte addressible message
     * @param msgLen  Length of message in bytes
     * @return Status/Result of the operation
     */
    virtual Status update(const Uint8 pMsg[], Uint64 msgLen) = 0;
    /**
     * @brief
     * @param pMsg Given message, finishes internal state processing the
     * message.
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    virtual Status finish(const Uint8 pMsg[], Uint64 msgLen) = 0;
    /**
     * @brief
     * @param digest Copy the digest/mac to given buffer
     * @param length Length of the buffer to copy into
     * @return Status/Result of the operation
     */
    virtual Status copy(Uint8 digest[], Uint64 len) = 0;
    /**
     * @brief Resets the temporary buffers without clearing key
     * @return Status/Result of the operation
     */
    virtual Status reset() = 0;
    virtual ~IPoly1305()   = default;
};

class ALCP_API_EXPORT Poly1305 : public Mac
{
  private:
    std::unique_ptr<IPoly1305> poly1305_impl;

  public:
    /**
     * @brief Given message, updates internal state processing the message
     * @param pMsg  Byte addressible message
     * @param msgLen  Length of message in bytes
     * @return  Status/Result of the operation
     */
    Status update(const Uint8 pMsg[], Uint64 msgLen) override;
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return Status/Result of the operation
     */
    Status setKey(const Uint8 key[], Uint64 len);
    /**
     * @brief Resets the temporary buffers without clearing key
     * @return Status/Result of the operation
     */
    Status reset() override;
    /**
     * @brief
     * @param pMsg Given message, finalizes internal state processing the
     * message.
     * @param msgLen Length of message in bytes
     * @return Status/Result of the operation
     */
    Status finalize(const Uint8 pMsg[], Uint64 msgLen) override;
    /**
     * @brief
     * @param digest Copy the digest/mac to given buffer
     * @param length Length of the buffer to copy into
     * @return Status/Result of the operation
     */
    Status copy(Uint8 digest[], Uint64 length);
    /**
     * @brief Cleanup the buffers and marks end of a context
     */
    void finish() override;
    // Uint8* macUpdate(const Uint8 msg[], const Uint8 key[], Uint64
    // msgLen);
    Poly1305();
    virtual ~Poly1305() = default;
};
} // namespace alcp::mac::poly1305