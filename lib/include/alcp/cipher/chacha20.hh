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

#pragma once

#include <alcp/types.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/bn.h>

namespace alcp::cipher::zen4 {
#include "alcp/cipher/chacha20_inplace.hh"
} // namespace alcp::cipher::zen4

namespace alcp::cipher {

class ChaCha20
{

  public:
    static constexpr Uint32 Chacha20Constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    Uint32 m_state[16];

    ChaCha20();

    static constexpr Uint64 m_keylen = 256 / 8;
    Uint8                   m_key[m_keylen];

    static constexpr Uint64 m_ivlen = (128 / 8);
    Uint8                   m_iv[m_ivlen];

    Uint32 m_counter;

    void displayState();

    int setKey(const Uint8* key, Uint64 keylen);

    int setIv(const Uint8* iv, Uint64 ivlen);

    int processInput(const Uint8* plaintext,
                     Uint64       plaintext_length,
                     Uint8*       ciphertext);
};

} // namespace alcp::cipher
