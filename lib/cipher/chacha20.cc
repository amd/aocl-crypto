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

#include "alcp/cipher/chacha20.hh"
#include "chacha20_inplace.cc.inc"

namespace alcp::cipher {

int
ChaCha20::setKey(Uint8* key, Uint64 keylen)
{
    return SetKey(m_state, key, keylen);
}

int
ChaCha20::setNonce(Uint8* nonce, Uint64 noncelen)
{
    return SetNonce(m_state, nonce, noncelen);
}

int
ChaCha20::setCounter(Uint32 counter)
{
    return SetCounter(m_state, counter);
}
int
ChaCha20::createInitialState(
    Uint8* key, Uint64 keylen, Uint32 counter, Uint8* nonce, Uint64 noncelen)
{
    return CreateInitialState(m_state, key, keylen, counter, nonce, noncelen);
}

int
ChaCha20::processInput(Uint8* key,
                       Uint64 keylen,
                       Uint32 counter,
                       Uint8* nonce,
                       Uint64 noncelen,
                       Uint8* plaintext,
                       Uint64 plaintext_length,
                       Uint8* ciphertext)
{
    return zen4::ProcessInput(m_state,
                              key,
                              keylen,
                              counter,
                              nonce,
                              noncelen,
                              plaintext,
                              plaintext_length,
                              ciphertext);
}

} // namespace alcp::cipher
