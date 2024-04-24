/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/error.h"
#include "alcp/utils/bits.hh"
#include <cstring>
#include <iomanip>
#include <iostream>
namespace alcp::cipher::chacha20 {
using alcp::utils::RotateLeft;
inline void
DisplayState(Uint32 state[16])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(8)
                      << +state[i * 4 + j] << " ";
        }
        std::cout << std::endl;
    }
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
                  const unsigned short cIndex1,
                  const unsigned short cIndex2,
                  const unsigned short cIndex3,
                  const unsigned short cIndex4)
{

    QuarterRound(
        state[cIndex1], state[cIndex2], state[cIndex3], state[cIndex4]);
}

inline void
InnerBlock(Uint32 state[16])
{
    QuarterRoundState(state, 0, 4, 8, 12);
    QuarterRoundState(state, 1, 5, 9, 13);
    QuarterRoundState(state, 2, 6, 10, 14);
    QuarterRoundState(state, 3, 7, 11, 15);
    QuarterRoundState(state, 0, 5, 10, 15);
    QuarterRoundState(state, 1, 6, 11, 12);
    QuarterRoundState(state, 2, 7, 8, 13);
    QuarterRoundState(state, 3, 4, 9, 14);
}

inline void
AddState(Uint32 state1[16], Uint32 state2[16])
{
    for (int i = 0; i < 16; i++) {
        state2[i] = state1[i] + state2[i];
    }
}

inline alc_error_t
ValidateKey(const Uint8* key, Uint64 keylen)
{
    if (key == NULL || (keylen != (256 / 8))) {
        return ALC_ERROR_INVALID_ARG;
    }
    return ALC_ERROR_NONE;
}
inline alc_error_t
SetKey(Uint32 state[16], const Uint8* key, Uint64 keylen)
{
    alc_error_t err = ValidateKey(key, keylen);
    if (alcp_is_error(err)) {
        return err;
    }
    memcpy(state + 4, key, keylen);
    return ALC_ERROR_NONE;
}
inline alc_error_t
ValidateIv(const Uint8 iv[], Uint64 iVlen)
{
    if (iv == NULL || (iVlen != 16)) {
        return ALC_ERROR_INVALID_ARG;
    }
    return ALC_ERROR_NONE;
}
inline alc_error_t
SetIv(Uint32 state[16], const Uint8 iv[], Uint64 ivlen)
{
    alc_error_t err = ValidateIv(iv, ivlen);
    if (alcp_is_error(err)) {
        return err;
    }
    memcpy(state + 12, iv, ivlen);
    return ALC_ERROR_NONE;
}
inline alc_error_t
CreateInitialState(Uint32      state[16],
                   const Uint8 key[],
                   Uint64      keylen,
                   const Uint8 iv[],
                   Uint64      ivlen,
                   Uint32      counter)
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    //  state = constants | key | counter | nonce
    alc_error_t err = SetKey(state, key, keylen);
    if (alcp_is_error(err)) {
        return err;
    };
    err = SetIv(state, iv, ivlen);
    if (alcp_is_error(err)) {
        return err;
    };
    state[12] = counter;
    return ALC_ERROR_NONE;
}

alc_error_t
ProcessInput(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             const Uint8 plaintext[],
             Uint8       ciphertext[],
             Uint64      blocks,
             int         remBytes)
{
    Uint64 plaintextLength = (blocks * 64) + remBytes;
    Uint64 n_blocks        = blocks;
    if (remBytes) {
        n_blocks++;
    }
    const Uint32 cInitialCounter = *(reinterpret_cast<const Uint32*>(iv));
    Uint32       state[16];
    for (Uint64 blocks = 0; blocks < plaintextLength; blocks += 64) {
        CreateInitialState(
            state, key, keylen, iv, ivlen, cInitialCounter + blocks / 64);
        Uint32 working_state[16];
        memcpy(working_state, state, sizeof(working_state));
        for (int i = 0; i < 10; i++) {
            InnerBlock(working_state);
        }
        AddState(working_state, state);
        auto   p_state                 = reinterpret_cast<Uint8*>(state);
        auto   processed_message_bytes = blocks;
        Uint64 bytes_to_xor = plaintextLength - processed_message_bytes;

        auto p_cipher_text = ciphertext + processed_message_bytes;
        auto p_plain_text  = plaintext + processed_message_bytes;
        bytes_to_xor       = bytes_to_xor < 64 ? bytes_to_xor : 64;
        for (Uint64 i = 0; i < bytes_to_xor; i++) {
            *(p_cipher_text + i) = *(p_plain_text + i) ^ p_state[i];
        }
        processed_message_bytes += bytes_to_xor;
    }
    return ALC_ERROR_NONE;
}
} // namespace alcp::cipher::chacha20