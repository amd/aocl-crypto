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
#include <cstring>
#include <iomanip>
#include <iostream>
#define UNROLL_8 _Pragma("GCC unroll 2")

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
inline Uint32
RotateLeft(Uint32 value, Uint32 count)
{
    return value << count | value >> (32 - count);
}

inline void
QuarterRound(Uint32& a, Uint32& b, Uint32& c, Uint32& d)
{
    a += b;
    d ^= a;
    d = RotateLeft(d, 16);
    c += d;
    b ^= c;
    b = RotateLeft(b, 12);
    a += b;
    d ^= a;
    d = RotateLeft(d, 8);
    c += d;
    b ^= c;
    b = RotateLeft(b, 7);
}

inline void
QuarterRoundState(Uint32               state[16],
                  const unsigned short index1,
                  const unsigned short index2,
                  const unsigned short index3,
                  const unsigned short index4)
{

    QuarterRound(state[index1], state[index2], state[index3], state[index4]);
}

inline void
inner_block(Uint32 state[16])
{
    QuarterRoundState(state, 0, 4, 8, 12);
    QuarterRoundState(state, 1, 5, 9, 13);
    QuarterRoundState(state, 2, 6, 10, 14);
    QuarterRoundState(state, 3, 7, 11, 15);
    std::cout << "After Row Round" << std::endl;
    display_state(state);
    std::cout << std::endl;
    QuarterRoundState(state, 0, 5, 10, 15);
    QuarterRoundState(state, 1, 6, 11, 12);
    QuarterRoundState(state, 2, 7, 8, 13);
    QuarterRoundState(state, 3, 4, 9, 14);
    std::cout << "After Column Round" << std::endl;
    display_state(state);
    std::cout << std::endl;
}

inline void
add_state(Uint32 state1[16], Uint32 state2[16])
{
    for (int i = 0; i < 16; i++) {
        state2[i] = state1[i] + state2[i];
    }
}
inline int
SetKey(Uint32 m_state[16], const Uint8* key, Uint64 keylen)
{
    if ((keylen != (256 / 8))) {
        return 0;
    }
    memcpy(m_state + 4, key, keylen);
    return 1;
}
inline int
SetIv(Uint32* m_state, const Uint8* iv, Uint64 ivlen)
{
    if (ivlen != 16) {
        return 0;
    }
    memcpy(m_state + 12, iv, ivlen);
    return 1;
}
inline int
CreateInitialState(Uint32 state[16],
                   Uint8* key,
                   Uint64 keylen,
                   Uint8* iv,
                   Uint64 ivlen,
                   Uint32 counter)
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    //  state = constants | key | counter | nonce
    if (!SetKey(state, key, keylen)) {
        return 0;
    };
    if (!SetIv(state, iv, ivlen)) {
        return 0;
    };
    state[12] = counter;
    return 1;
}

int
ProcessInput(Uint32       m_state[16],
             Uint8*       key,
             Uint64       keylen,
             Uint8*       iv,
             Uint64       ivlen,
             const Uint8* plaintext,
             Uint64       plaintext_length,
             Uint8*       ciphertext)
{
    Uint64 n_blocks = plaintext_length / 64;
    if (plaintext_length - n_blocks * 64 > 0) {
        n_blocks++;
    }
    const Uint32 initial_counter = m_state[12];
    UNROLL_8
    for (Uint64 blocks = 0; blocks < plaintext_length; blocks += 64) {
        CreateInitialState(
            m_state, key, keylen, iv, ivlen, initial_counter + blocks / 64);
        Uint32 working_state[16];
        memcpy(working_state, m_state, sizeof(working_state));
        for (int i = 0; i < 10; i++) {
            inner_block(working_state);
        }
        std::cout << "Block" << blocks << std::endl;
        display_state(working_state);
        std::cout << std::endl;
        add_state(working_state, m_state);
        auto   p_state                 = reinterpret_cast<Uint8*>(m_state);
        auto   processed_message_bytes = blocks;
        Uint64 bytes_to_xor = plaintext_length - processed_message_bytes;

        auto p_cipher_text = ciphertext + processed_message_bytes;
        auto p_plain_text  = plaintext + processed_message_bytes;
        bytes_to_xor       = bytes_to_xor < 64 ? bytes_to_xor : 64;
        for (Uint64 i = 0; i < bytes_to_xor; i++) {
            *(p_cipher_text + i) = *(p_plain_text + i) ^ p_state[i];
        }
        processed_message_bytes += bytes_to_xor;
    }
    return 0;
}