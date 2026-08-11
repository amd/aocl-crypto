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

#include <memory>

#include "alcp/digest.hh"

namespace alcp::mac {

class HmacMB final
{
  public:
    HmacMB()  = default;
    ~HmacMB() = default;

  public:
    alc_error_t init(const Uint8*      pKey,
                                     Uint64            keyLen,
                                     alc_digest_mode_t digest_mode);
    alc_error_t flush(const Uint8** ppMsgBuf,
                                      const Uint64  numBuffers,
                                      const Uint64  msgLen);
    alc_error_t dequeue(Uint8**      ppDstBuf,
                                        const Uint64 numBuffers);

  private:
    template<typename DIGEST_TYPE>
    alc_error_t precompute_hash();

    template<typename DIGEST_MB_TYPE>
    alc_error_t process_buffers(Uint8** ppDstBuf, const Uint64 numBuffers);

  private:
    alc_digest_mode_t    m_digest_mode        = ALC_SHA2_256;
    const Uint8*         m_key                = nullptr;
    Uint64               m_key_len            = UINT64_MAX;
    const Uint8**        m_buffers            = nullptr;
    Uint64               m_msg_len            = UINT64_MAX;
    Uint64               m_num_buffers        = 0;
    Uint64               m_block_size_bytes   = 0;
    Uint64               m_digest_size_bytes  = 0;
    static constexpr int cMaxBlockLengthBytes = 144;

    // Pre-computed hash states for optimization
    alignas(64) Uint32 m_hash_after_ipad[8]{};
    alignas(64) Uint32 m_hash_after_opad[8]{};

    // Reusable digest objects to avoid repeated allocations
    std::unique_ptr<alcp::digest::IDigest> m_digest_sb;
    std::unique_ptr<alcp::digest::IDigest> m_digest_mb;
};

} // namespace alcp::mac
