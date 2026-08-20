/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include <algorithm>

namespace alcp::mac::poly1305 {

/*
 * Common Poly1305 helpers shared across all implementations (Zen3/Zen4/reference).
 */

// Limb layout for the 130-bit accumulator.
template<int NLIMBS, int LIMB_BITS, int LAST_LIMB_BITS = LIMB_BITS>
struct LimbLayout
{
    static constexpr int    nlimbs         = NLIMBS;
    static constexpr int    limb_bits      = LIMB_BITS;
    static constexpr int    last_limb_bits = LAST_LIMB_BITS;
    static constexpr Uint64 mask_low_limb  = (1ULL << LIMB_BITS) - 1;
    static constexpr Uint64 mask_last_limb = (1ULL << LAST_LIMB_BITS) - 1;
    static constexpr Uint64 wrap_factor    = 5; // 2^130 mod (2^130 - 5)
    // Position of the 2^128 full-block pad bit within the top limb.
    static constexpr Uint64 high_pad_bit = 1ULL << (128 - (NLIMBS - 1) * LIMB_BITS);
};

using Radix26 = LimbLayout<5, 26>;          // AVX2 / Zen3 path
using Radix44 = LimbLayout<3, 44, 42>;      // AVX-512 / Zen4 path

/*
 * Zero secret material through a volatile pointer so the compiler cannot drop
 * it as a dead store before the memory is freed.
 */
inline void
poly1305_secure_clear(void* p, Uint64 len)
{
    volatile Uint8* vp = static_cast<volatile Uint8*>(p);
    while (len-- > 0) {
        *vp++ = 0;
    }
}

static inline void
poly1305_clamp_r(Uint8 r[16])
{
    // Clear the top 4 bits of bytes 3, 7, 11, 15 ...
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    // ... and the bottom 2 bits of bytes 4, 8, 12.
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[12] &= 0xfc;
}

static inline void
poly1305_pad_partial_block(Uint8* buf, Uint64 used)
{
    buf[used] = 0x01;
    std::fill(buf + used + 1, buf + 16, 0);
}

} // namespace alcp::mac::poly1305
