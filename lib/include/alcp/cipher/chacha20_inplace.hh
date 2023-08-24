/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include <alcp/types.h>
// inline Uint32
// RotateLeft(Uint32 value, Uint32 count);

inline void
QuarterRound(Uint32& a, Uint32& b, Uint32& c, Uint32& d);

inline void
QuarterRoundState(Uint32               state[16],
                  const unsigned short index1,
                  const unsigned short index2,
                  const unsigned short index3,
                  const unsigned short index4);

inline void
inner_block(Uint32 state[16]);

inline void
add_state(Uint32 state1[16], Uint32 state2[16]);
inline int
SetKey(Uint32 m_state[16], const Uint8* key, Uint64 keylen);
inline int
SetNonce(Uint32 m_state[16], const Uint8* nonce, Uint64 noncelen);
inline int
SetCounter(Uint32 m_state[16], Uint32 counter);

inline int
CreateInitialState(Uint32 state[16],
                   Uint8* key,
                   Uint64 keylen,
                   Uint32 counter,
                   Uint8* nonce,
                   Uint64 noncelen);

int
ProcessInput(Uint32       m_state[16],
             Uint8*       key,
             Uint64       keylen,
             Uint32       counter,
             Uint8*       nonce,
             Uint64       noncelen,
             const Uint8* plaintext,
             Uint64       plaintext_length,
             Uint8*       ciphertext);