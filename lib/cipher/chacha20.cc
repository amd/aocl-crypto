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
#include <algorithm>
namespace alcp::cipher {
ChaCha20::ChaCha20()
{
    m_state[0] = Chacha20Constants[0];
    m_state[1] = Chacha20Constants[1];
    m_state[2] = Chacha20Constants[2];
    m_state[3] = Chacha20Constants[3];
}
int
ChaCha20::setKey(const Uint8* key, Uint64 keylen)
{

#if 0
    std::copy(key, key + 8, m_key);
    std::copy(key + 8, key + 16, m_key + 8);

    std::reverse_copy(key + 16, key + 24, m_key + 16);

    std::reverse_copy(key + 24, key + 32, m_key + 24);
#else
    memcpy(m_key, key, keylen);
#endif

    return SetKey(m_state, key, keylen);
}

int
ChaCha20::setIv(const Uint8* iv, Uint64 ivlen)
{
    memcpy(m_iv, iv, ivlen);
    return SetIv(m_state, iv, ivlen);
}

int
ChaCha20::processInput(const Uint8* plaintext,
                       Uint64       plaintext_length,
                       Uint8*       ciphertext)
{

#if 1
    return zen4::ProcessInput(m_state,
                              m_key,
                              m_keylen,
                              m_iv,
                              m_ivlen,
                              plaintext,
                              plaintext_length,
                              ciphertext);
#else
    return ProcessInput(m_state,
                        m_key,
                        m_keylen,
                        m_iv,
                        m_ivlen,
                        plaintext,
                        plaintext_length,
                        ciphertext);
#endif
}

void
ChaCha20::displayState()
{
    display_state(m_state);
}

} // namespace alcp::cipher
