/*
 * Copyright (C) 2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest.hh"

namespace alcp::digest {

#define MAX_BUFFERS 128

template<alc_digest_len_t digest_len>
class Sha2MB final : public IDigest
{
    static_assert(ALC_DIGEST_LEN_224 == digest_len
                  || ALC_DIGEST_LEN_256 == digest_len);

  public:
    ALCP_INTERNAL_CPP_EXPORT Sha2MB()  = default;
    ALCP_INTERNAL_CPP_EXPORT ~Sha2MB() = default;

  public:
    // IDigest interface implementation
    ALCP_INTERNAL_CPP_EXPORT void init(void) override;
    ALCP_INTERNAL_CPP_EXPORT alc_error_t update(const Uint8* pBuf,
                                                Uint64       size) override;
    ALCP_INTERNAL_CPP_EXPORT alc_error_t finalize(Uint8* pBuf,
                                                  Uint64 size) override;

    // Multibuffer-specific methods
    ALCP_INTERNAL_CPP_EXPORT void set_blocks(Uint64 blocks);
    ALCP_INTERNAL_CPP_EXPORT void set_state(const Uint32 state[8]);
    ALCP_INTERNAL_CPP_EXPORT alc_error_t flush(const Uint8** ppMsgBuf,
                                               const Uint64  numBuffers,
                                               const Uint64  msgLen);
    ALCP_INTERNAL_CPP_EXPORT alc_error_t dequeue(Uint8**      ppDstBuf,
                                                 const Uint64 numBuffers,
                                                 const Uint64 digestLen);

  private:
    alignas(64) Uint32 m_hash[8]{};
    const Uint8** m_buffers     = nullptr;
    Uint64        m_msg_len     = UINT64_MAX;
    Uint64        m_num_buffers = 0;
    Uint64        m_blocks      = UINT64_MAX;
};

typedef Sha2MB<ALC_DIGEST_LEN_224> Sha224MB;
typedef Sha2MB<ALC_DIGEST_LEN_256> Sha256MB;

} // namespace alcp::digest
