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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include <alcp/base.hh>
#include <algorithm>

namespace alcp::mac::poly1305 {
struct Poly1305State26
{
  private:
    static const Uint32 cHornorFactor    = 5;
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;
    static const Uint32 cLimbsAligned    = 8; // To create aligned memory
    static const Uint32 cLimbs           = 5;

  public:
    alignas(64) Uint64 r[cLimbsAligned][cHornorFactor];
    alignas(64) Uint64 s[cLimbsAligned][cHornorFactor];
    alignas(64) Uint64 a[cLimbsAligned];
    alignas(64) Uint64 key[m_cKeySize_bytes / sizeof(Uint64)] = {};
    alignas(64) Uint8 msg_buffer[m_cMsgSize_bytes];
    Uint64 msg_buffer_len;
    bool   finalized;

    void reset()
    {
        std::fill(a, a + cLimbsAligned, 0);
        std::fill(msg_buffer, msg_buffer + m_cMsgSize_bytes, 0);
        msg_buffer_len = 0;
        finalized      = false;
    }

    Poly1305State26()
    {
        std::fill(key, key + (m_cKeySize_bytes / sizeof(Uint64)), 0);
        std::fill(&r[0][0], &r[0][0] + (cLimbsAligned * cHornorFactor), 0);
        std::fill(&s[0][0], &s[0][0] + (cLimbsAligned * cHornorFactor), 0);
        std::fill(a, a + cLimbsAligned, 0);
        std::fill(msg_buffer, msg_buffer + m_cMsgSize_bytes, 0);
        msg_buffer_len = 0;
        finalized      = false;
    }

    ~Poly1305State26()
    {
        std::fill(key, key + (m_cKeySize_bytes / sizeof(Uint64)), 0);
        std::fill(&r[0][0], &r[0][0] + (cLimbsAligned * cHornorFactor), 0);
        std::fill(&s[0][0], &s[0][0] + (cLimbsAligned * cHornorFactor), 0);
        msg_buffer_len = 0;
        finalized      = false;
        reset();
    }
}; // namespace alcp::mac::poly1305

struct Poly1305State44
{
  private:
    static const Uint32 cHornorFactor    = 5;
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;
    static const Uint32 cLimbsAligned    = 8; // To create aligned memory
    static const Uint32 cLimbs           = 5;

  public:
    alignas(64) Uint64 r[3], r2[3], r3[3], r4[3], r5[3], r6[3], r7[3], r8[3];
    alignas(64) Uint64 s[3];
    alignas(64) Uint64 acc0[8], acc1[8], acc2[8];
    alignas(64) Uint64 key[m_cKeySize_bytes / sizeof(Uint64)] = {};
    alignas(64) Uint8 msg_buffer[m_cMsgSize_bytes];
    Uint64 msg_buffer_len;
    bool   finalized;
    bool   fold = false; // Everything starts as folded

    void reset()
    {
        std::fill(acc0, acc0 + 8, 0);
        std::fill(acc1, acc1 + 8, 0);
        std::fill(acc2, acc2 + 8, 0);
        std::fill(msg_buffer, msg_buffer + m_cMsgSize_bytes, 0);
        msg_buffer_len = 0;
        finalized      = false;
    }

    Poly1305State44()
    {
        std::fill(acc0, acc0 + 8, 0);
        std::fill(acc1, acc1 + 8, 0);
        std::fill(acc2, acc2 + 8, 0);
        std::fill(key, key + (m_cKeySize_bytes / sizeof(Uint64)), 0);
        std::fill(msg_buffer, msg_buffer + m_cMsgSize_bytes, 0);
        msg_buffer_len = 0;
        finalized      = false;
    }

    ~Poly1305State44()
    {
        std::fill(key, key + (m_cKeySize_bytes / sizeof(Uint64)), 0);
        msg_buffer_len = 0;
        finalized      = false;
        reset();
    }
}; // namespace alcp::mac::poly1305
} // namespace alcp::mac::poly1305