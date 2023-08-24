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

inline void
display_state(Uint32 state[16])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(8)
                      << +state[i * 4 + j] << " ";
        }
        std::cout << std::endl;
    }
}

class ChaCha20
{
  public:
    Uint32 m_state[16] = {
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
    };

    void displayState() { display_state(m_state); }

    inline int setKey(Uint8* key, Uint64 keylen);

    inline int setNonce(Uint8* nonce, Uint64 noncelen);

    inline int setCounter(Uint32 counter);

    int createInitialState(Uint8* key,
                           Uint64 keylen,
                           Uint32 counter,
                           Uint8* nonce,
                           Uint64 noncelen);

    int processInput(Uint8* key,
                     Uint64 keylen,
                     Uint32 counter,
                     Uint8* nonce,
                     Uint64 noncelen,
                     Uint8* plaintext,
                     Uint64 plaintext_length,
                     Uint8* ciphertext);
};

} // namespace alcp::cipher
