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
#include "alcp/mac/poly1305_state.hh"

namespace alcp::mac::poly1305 {

// Same radix-26 kernel, built in two arch tiers from poly1305_avx2_kernel.cc.inc:
//   avx2:: -> portable AVX2 build, safe on any AVX2 CPU
//   zen3:: -> Zen3-tuned build of the same kernel
namespace avx2 {

void
poly1305_init(Poly1305State26x4& state, const Uint8 key[32]);

bool
poly1305_update(Poly1305State26x4& state, const Uint8* msg, Uint64 len);

bool
poly1305_finalize(Poly1305State26x4& state, Uint8* digest, Uint64 len);

} // namespace avx2

namespace zen3 {

void
poly1305_init(Poly1305State26x4& state, const Uint8 key[32]);

bool
poly1305_update(Poly1305State26x4& state, const Uint8* msg, Uint64 len);

bool
poly1305_finalize(Poly1305State26x4& state, Uint8* digest, Uint64 len);

} // namespace zen3

} // namespace alcp::mac::poly1305
