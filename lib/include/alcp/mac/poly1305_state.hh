/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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
#include <alcp/mac/poly1305_common.hh>
#include <algorithm>

namespace alcp::mac::poly1305 {

struct Poly1305State44
{
  private:
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;
    static const Uint32 cLimbs           = 3;
    static const Uint32 cSize512         = 512 / 8;

  public:
    alignas(64) Uint64 r[cLimbs], r2[cLimbs], r3[cLimbs], r4[cLimbs],
        r5[cLimbs], r6[cLimbs], r7[cLimbs], r8[cLimbs], r16[cLimbs];
    alignas(64) Uint64 s[cLimbs];
    alignas(64) Uint64 acc0[cSize512], acc1[cSize512], acc2[cSize512];
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
        reset();
    }
}; // namespace alcp::mac::poly1305

struct alignas(64) Poly1305State26x4
{
    static constexpr Uint32 cKeySize_bytes = 32;
    static constexpr Uint32 cMsgSize_bytes = 16;

    alignas(32) Uint64 r1_pack[5][4];
    alignas(32) Uint64 r1_s[4][4];

    alignas(32) Uint64 r4_pack[5][4];
    alignas(32) Uint64 r4_s[4][4];

    // r^8 power tables (and 5*r variants) for the dual x8 stream loop, packed
    // for aligned vector loads.
    alignas(32) Uint64 r8_pack[5][4];
    alignas(32) Uint64 r8_s[4][4];

    alignas(32) Uint64 rp_pack[5][4];
    alignas(32) Uint64 rp_s[4][4];

    // Stream-A fold powers [r^8, r^7, r^6, r^5] (and 5*r variants) for merging
    // the two x8 streams back to one accumulator.
    alignas(32) Uint64 r8p_pack[5][4];
    alignas(32) Uint64 r8p_s[4][4];

    alignas(32) Uint64 acc[5][4];

    alignas(32) Uint64 acc_scalar[5];

    Uint32 s_key[4];

    alignas(16) Uint8 msg_buffer[cMsgSize_bytes];
    Uint64            msg_buffer_len;

    bool finalized;
    // True when the SIMD accumulator (acc) is live; false means acc_scalar is
    // authoritative.
    bool fold;
    bool powers_computed;
    bool powers8_computed;

    /*
     * keep_powers defaults to true: a same-key reset (init/update/finalize/
     * reset reuse) keeps the key-derived r-power tables. init() passes false
     * because a new key invalidates them.
     */
    void reset(bool keep_powers = true)
    {
        // acc[][] is left untouched: fold=false guarantees it is overwritten
        // before any read, and zeroing it here cost ~44% on small messages.
        acc_scalar[0]   = 0;
        acc_scalar[1]   = 0;
        acc_scalar[2]   = 0;
        acc_scalar[3]   = 0;
        acc_scalar[4]   = 0;
        msg_buffer_len  = 0;
        finalized       = false;
        fold            = false;
        if (!keep_powers) {
            powers_computed  = false;
            powers8_computed = false;
        }
    }

    Poly1305State26x4()
    {
        std::fill_n(&r1_pack[0][0], 5 * 4, 0);
        std::fill_n(&r1_s[0][0], 4 * 4, 0);
        std::fill_n(&r4_pack[0][0], 5 * 4, 0);
        std::fill_n(&r4_s[0][0], 4 * 4, 0);
        std::fill_n(&r8_pack[0][0], 5 * 4, 0);
        std::fill_n(&r8_s[0][0], 4 * 4, 0);
        std::fill_n(&rp_pack[0][0], 5 * 4, 0);
        std::fill_n(&rp_s[0][0], 4 * 4, 0);
        std::fill_n(&r8p_pack[0][0], 5 * 4, 0);
        std::fill_n(&r8p_s[0][0], 4 * 4, 0);
        std::fill_n(s_key, 4, 0);
        reset(false);
    }

    ~Poly1305State26x4()
    {
        // Non-elidable wipe of all key-derived material (a plain std::fill
        // would be a droppable dead store).
        poly1305_secure_clear(r1_pack, sizeof(r1_pack));
        poly1305_secure_clear(r1_s, sizeof(r1_s));
        poly1305_secure_clear(r4_pack, sizeof(r4_pack));
        poly1305_secure_clear(r4_s, sizeof(r4_s));
        poly1305_secure_clear(r8_pack, sizeof(r8_pack));
        poly1305_secure_clear(r8_s, sizeof(r8_s));
        poly1305_secure_clear(rp_pack, sizeof(rp_pack));
        poly1305_secure_clear(rp_s, sizeof(rp_s));
        poly1305_secure_clear(r8p_pack, sizeof(r8p_pack));
        poly1305_secure_clear(r8p_s, sizeof(r8p_s));
        poly1305_secure_clear(acc, sizeof(acc));
        poly1305_secure_clear(acc_scalar, sizeof(acc_scalar));
        poly1305_secure_clear(s_key, sizeof(s_key));
    }
};

} // namespace alcp::mac::poly1305
