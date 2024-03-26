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

#include "alcp/base.hh"
#include "alcp/mac/poly1305_state.hh"

namespace alcp::mac::poly1305::zen4 {

Status
init(const Uint8 key[],           // Input key
     Uint64      keyLen,          // Key Length
     Uint64      accumulator[],   // Output Accumulator
     Uint64      processed_key[], // Output Key
     Uint64      r[10],           // Authentication Key
     Uint64      s[8],            // Addicitive Key
     bool        finalized);             // Finalization indicator

Status
update(Uint64      key[],
       const Uint8 pMsg[],
       Uint64      msgLen,
       Uint64      accumulator[],
       Uint8       m_msg_buffer[16],
       Uint64&     m_msg_buffer_len,
       Uint64      r[10],
       Uint64      s[8],
       bool        finalized);

Status
finish(Uint64      key[],
       const Uint8 pMsg[],
       Uint64      msgLen,
       Uint64      accumulator[],
       Uint8       msg_buffer[16],
       Uint64&     msg_buffer_len,
       Uint64      r[10],
       Uint64      s[8],
       bool&       finalized);

Status
copy(Uint8 digest[], Uint64 len, Uint64 accumulator[], bool m_finalized);

void
poly1305_init_radix44(Poly1305State44& state, const Uint8 key[32]);

void
poly1305_update_radix44(Poly1305State44& state, const Uint8* pMsg, Uint64 len);

void
poly1305_finalize_radix44(Poly1305State44& state,
                          const Uint8*     pMsg,
                          Uint64           len);

void
poly1305_copy_radix44(Poly1305State44& state, Uint8* digest, Uint64 digest_len);

} // namespace alcp::mac::poly1305::zen4