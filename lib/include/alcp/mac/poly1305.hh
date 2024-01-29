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

#include <openssl/bn.h>

#include "alcp/base.hh"
#include "alcp/mac/mac.hh"

#define USE_OLD_IMPL 0

namespace alcp::mac::poly1305 {
class ALCP_API_EXPORT IPoly1305
{
  public:
    virtual Status init(const Uint8 key[], Uint64 keyLen)    = 0;
    virtual Status update(const Uint8 pMsg[], Uint64 msgLen) = 0;
    virtual Status finish(const Uint8 pMsg[], Uint64 msgLen) = 0;
    virtual Status copy(Uint8 digest[], Uint64 len)          = 0;
    virtual Status reset()                                   = 0;
};

class ALCP_API_EXPORT Poly1305 : public Mac
{
  private:
#if USE_OLD_IMPL
    Uint8   m_accumulator[18] = {};
    Uint8   m_key[32];
    BIGNUM *m_key_bn = nullptr, *m_a_bn = nullptr, *m_r_bn = nullptr,
           *m_s_bn = nullptr, *m_p_bn = nullptr;
    Uint8   m_msg_buffer[16];
    Uint64  m_msg_buffer_len = {};
    BN_CTX* m_bn_temp_ctx    = nullptr;
    bool    m_finalized      = false;
#else
    std::unique_ptr<IPoly1305> poly1305_impl;
#endif

    Uint8 m_p[17] = { 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb };
    void  clamp(Uint8 in[16]);

  public:
    Status blk(const Uint8 pMsg[], Uint64 msgLen);
    Status update(const Uint8 pMsg[], Uint64 msgLen) override;
    /**
     * @brief Sets the Key and Initializes the state of Poly1305
     * @param key - Key to use for Poly1305
     * @param len - Key Length 32 Byte, anything else wont work
     * @return Status
     */
    Status setKey(const Uint8 key[], Uint64 len);
    Status reset() override;
    Status finalize(const Uint8 pMsg[], Uint64 msgLen) override;
    Status copy(Uint8 digest[], Uint64 length);
    void   finish() override;
    // Uint8* macUpdate(const Uint8 msg[], const Uint8 key[], Uint64
    // msgLen);
    Poly1305();
    virtual ~Poly1305();
};
} // namespace alcp::mac::poly1305