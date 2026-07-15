/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#include "alcp/utils/endian.hh"
#include <algorithm>
#include <iomanip>
#include <iostream>

namespace alcp::cipher {

using alcp::utils::LoadLittleEndian;
using alcp::utils::RotateLeft;
using alcp::utils::StoreLittleEndian;

// This file provides scalar ChaCha20 block construction for the
// reference implementation and for callers that need exactly one
// 64-byte block. It uses the internal ChaCha256T layout: a 32-byte
// key and a 16-byte IV where the first IV word is the block counter.
// Helpers here are internal to the cipher translation unit that
// includes this file; they do not add public API surface.

// ChaCha20 in this file operates on the 256-bit-key, 16-byte-IV form used by
// the internal cipher object. The IV buffer stores the 32-bit block counter in
// the first word followed by the remaining nonce words.
static constexpr Uint64 cKeyBytes   = 256 / 8;
static constexpr Uint64 cIvBytes    = 128 / 8;
static constexpr Uint64 cBlockBytes = 64;

// Debug helper that prints the 16-word state in matrix order. It is
// kept local to the scalar implementation and is not used on hot paths.
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

// Apply one ChaCha20 quarter round to four state words. The operation sequence
// is the cipher ARX primitive: addition, XOR and fixed-distance rotations.
// The rotation distances (16, 12, 8, 7) are fixed by the cipher specification.
inline void
QuarterRound(Uint32& a, Uint32& b, Uint32& c, Uint32& d)
{
    a += b;
    d ^= a;
    d = RotateLeft(d, 16U);
    c += d;
    b ^= c;
    b = RotateLeft(b, 12U);
    a += b;
    d ^= a;
    d = RotateLeft(d, 8U);
    c += d;
    b ^= c;
    b = RotateLeft(b, 7U);
}

// Apply a quarter round to four indexed words in a 16-word ChaCha20 state.
// This wrapper is retained for callers/tests that address rounds by indices.
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

// Apply one ChaCha20 inner block: four column rounds followed by four diagonal
// rounds. ProcessInput and generateBlockWords call this ten times to perform
// the twenty ChaCha20 rounds for a keystream block.
inline void
InnerBlock(Uint32 state[16])
{
    QuarterRound(state[0], state[4], state[8], state[12]);
    QuarterRound(state[1], state[5], state[9], state[13]);
    QuarterRound(state[2], state[6], state[10], state[14]);
    QuarterRound(state[3], state[7], state[11], state[15]);
    QuarterRound(state[0], state[5], state[10], state[15]);
    QuarterRound(state[1], state[6], state[11], state[12]);
    QuarterRound(state[2], state[7], state[8], state[13]);
    QuarterRound(state[3], state[4], state[9], state[14]);
}

// Add the original state into the working state. This feed-forward step is what
// turns the transformed state into the final ChaCha20 keystream block.
inline void
AddState(Uint32 state1[16], Uint32 state2[16])
{
    for (Uint32 i = 0; i < 16; i++) {
        state2[i] = state1[i] + state2[i];
    }
}

// Validate a ChaCha20-256 key as exposed by the cipher API. This
// helper receives key length in bits; state builders below use byte counts.
inline alc_error_t
ValidateKey(const Uint8* key, Uint64 keylen)
{
    if (key == NULL || (keylen != 256)) {
        return ALC_ERROR_INVALID_ARG;
    }
    return ALC_ERROR_NONE;
}

// Copy a validated 256-bit key into state words 4..11 using little-endian
// loads. The state stores words, not raw bytes, so direct byte copying would
// make behavior depend on host byte order.
inline alc_error_t
SetKey(Uint32 state[16], const Uint8* key, Uint64 keylen)
{
    alc_error_t err = ValidateKey(key, keylen);
    if (alcp_is_error(err)) {
        return err;
    }
    for (Uint32 i = 0; i < 8; i++) {
        state[4 + i] = LoadLittleEndian<Uint32>(key + (i * sizeof(Uint32)));
    }
    return ALC_ERROR_NONE;
}

// Validate the 16-byte IV layout used by this internal ChaCha20 path: one
// 32-bit counter word followed by nonce words.
inline alc_error_t
ValidateIv(const Uint8 iv[], Uint64 iVlen)
{
    if (iv == NULL || (iVlen != 16)) {
        return ALC_ERROR_INVALID_ARG;
    }
    return ALC_ERROR_NONE;
}

// Copy the IV into state words 12..15 using little-endian loads. The caller may
// pass an explicit counter to CreateInitialState(), which overwrites state[12]
// after the IV words are loaded.
inline alc_error_t
SetIv(Uint32 state[16], const Uint8 iv[], Uint64 ivlen)
{
    alc_error_t err = ValidateIv(iv, ivlen);
    if (alcp_is_error(err)) {
        return err;
    }
    for (Uint32 i = 0; i < 4; i++) {
        state[12 + i] = LoadLittleEndian<Uint32>(iv + (i * sizeof(Uint32)));
    }
    return ALC_ERROR_NONE;
}

// Construct the 16-word ChaCha20 initial state:
//   constants | 256-bit key | 32-bit counter | nonce words
// The explicit counter parameter lets the block-processing loop derive each
// successive block counter without mutating the caller-owned IV buffer.
inline alc_error_t
CreateInitialState(Uint32      state[16],
                   const Uint8 key[],
                   Uint64      keylen,
                   const Uint8 iv[],
                   Uint64      ivlen,
                   Uint32      counter)
{
    if (state == nullptr || key == nullptr || iv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (keylen != cKeyBytes || ivlen != cIvBytes) {
        return ALC_ERROR_INVALID_ARG;
    }

    // The first four words are the ChaCha20 constant string represented as
    // little-endian 32-bit words.
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Words 4..11 are the 256-bit key. Loading through LoadLittleEndian<Uint32>() keeps the
    // state layout independent of native CPU byte order.
    for (Uint32 i = 0; i < 8; i++) {
        state[4 + i] = LoadLittleEndian<Uint32>(key + (i * sizeof(Uint32)));
    }
    // Words 12..15 come from the IV buffer. The first word is replaced by
    // the explicit counter below so callers can process successive blocks
    // without modifying the IV stored in the cipher object.
    for (Uint32 i = 0; i < 4; i++) {
        state[12 + i] = LoadLittleEndian<Uint32>(iv + (i * sizeof(Uint32)));
    }

    // state[12] is the block counter; state[13..15] remain nonce words.
    state[12] = counter;
    return ALC_ERROR_NONE;
}

// Generate one 64-byte ChaCha20 keystream block as sixteen 32-bit words. The
// function copies the initial state to a working state, applies twenty rounds,
// then adds the original state back in. The output remains in word form so
// callers can XOR full words before handling any partial tail bytes.
inline alc_error_t
generateBlockWords(const Uint8* pKey,
                   const Uint8* pIv,
                   Uint32       counter,
                   Uint32       blockWords[16])
{
    if (blockWords == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    Uint32      state[16];
    alc_error_t err =
        CreateInitialState(state, pKey, cKeyBytes, pIv, cIvBytes, counter);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // ChaCha20 rounds transform a working copy. The original initial state is
    // still needed for the final feed-forward addition below.
    Uint32 workingState[16];
    std::copy(state, state + 16, workingState);

    // Ten inner blocks are twenty ChaCha20 rounds: each inner block is one
    // column-round group and one diagonal-round group.
    for (int i = 0; i < 10; i++) {
        InnerBlock(workingState);
    }
    for (Uint32 i = 0; i < 16; i++) {
        blockWords[i] = workingState[i] + state[i];
    }

    // The caller receives only blockWords; the intermediate state copies are
    // no longer needed after the feed-forward addition.
    std::fill(state, state + 16, 0);
    std::fill(workingState, workingState + 16, 0);
    return ALC_ERROR_NONE;
}

// XOR up to one ChaCha20 block of input with a generated keystream block. Full
// 32-bit words use little-endian word loads/stores, and the final partial word
// is handled byte-by-byte so callers can use the same helper for full blocks and
// tails. The helper does not retain unused keystream; each call is independent
// and identified by its explicit block counter.
inline alc_error_t
xorBlock(const Uint8* pKey,
         const Uint8* pIv,
         Uint32       counter,
         const Uint8* pInput,
         Uint8*       pOutput,
         Uint64       bytesToXor)
{
    if (pInput == nullptr || pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    // The helper produces exactly one keystream block per call, so requests
    // longer than a block must come from the multi-block iterator, not from
    // this entry point. Guard the contract explicitly.
    if (bytesToXor > cBlockBytes) {
        return ALC_ERROR_INVALID_ARG;
    }

    Uint32      blockWords[16];
    alc_error_t err = generateBlockWords(pKey, pIv, counter, blockWords);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Most inputs are word-aligned in length. Process full 32-bit words using
    // the same little-endian conversion used for state construction.
    const Uint64 wordsToXor = bytesToXor / sizeof(Uint32);
    for (Uint64 i = 0; i < wordsToXor; i++) {
        const Uint32 msg = LoadLittleEndian<Uint32>(pInput + (i * sizeof(Uint32)));
        StoreLittleEndian(pOutput + (i * sizeof(Uint32)), msg ^ blockWords[i]);
    }

    const Uint64 bytesDone = wordsToXor * sizeof(Uint32);
    // For non-block-multiple tails, materialize only the next keystream word
    // and XOR the required bytes from it.
    if (bytesDone < bytesToXor) {
        Uint8 keyStreamWord[sizeof(Uint32)];
        StoreLittleEndian(keyStreamWord, blockWords[wordsToXor]);
        for (Uint64 i = bytesDone; i < bytesToXor; i++) {
            pOutput[i] = pInput[i] ^ keyStreamWord[i - bytesDone];
        }
    }

    // The generated block is consumed by this call and is not retained for
    // later updates.
    std::fill(blockWords, blockWords + 16, 0);
    return ALC_ERROR_NONE;
}

// Convenience wrapper for callers that already know the request is exactly
// one complete ChaCha20 block. The counter is read from the first 32-bit word
// of the IV buffer, matching the layout used by the generic ProcessInput().
inline alc_error_t
xorOneBlock(const Uint8* pKey,
            const Uint8* pIv,
            const Uint8* pInput,
            Uint8*       pOutput)
{
    if (pIv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    return xorBlock(pKey, pIv, LoadLittleEndian<Uint32>(pIv), pInput, pOutput, cBlockBytes);
}

// Generic scalar ChaCha20 processing for any number of complete blocks plus an
// optional tail. The counter is taken from the IV and incremented by block
// index; the IV itself is not modified. The keylen and ivlen parameters are
// kept for the existing internal signature; this ChaCha256T path uses the
// fixed key and IV sizes declared above when constructing each block.
//
// `inline`: this .inc is #included by both chacha20.cc and the chacha20 unit
// test, so the definition needs inline linkage to be included in multiple
// translation units without a duplicate-definition error.
inline alc_error_t
ProcessInput(const Uint8 key[],
             Uint64      keylen,
             const Uint8 iv[],
             Uint64      ivlen,
             const Uint8 plaintext[],
             Uint8       ciphertext[],
             Uint64      blocks,
             int         remBytes)
{
    if (key == nullptr || iv == nullptr || plaintext == nullptr
        || ciphertext == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (keylen != cKeyBytes || ivlen != cIvBytes) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (remBytes < 0 || remBytes >= static_cast<int>(cBlockBytes)) {
        return ALC_ERROR_INVALID_ARG;
    }

    Uint64 plaintextLength =
        (blocks * cBlockBytes) + static_cast<Uint64>(remBytes);
    // Read the starting block counter once from the IV. The IV buffer itself
    // is not mutated by this loop; per-iteration counters are derived from
    // this snapshot plus the current block index.
    const Uint32 cInitialCounter = LoadLittleEndian<Uint32>(iv);
    for (Uint64 processed = 0; processed < plaintextLength;
         processed += cBlockBytes) {
        Uint64 bytesToXor = plaintextLength - processed;

        // The final iteration may be a tail shorter than one block. Use the
        // same one-block helper and limit the XOR length for that last call.
        bytesToXor        = bytesToXor < cBlockBytes
                         ? bytesToXor
                         : cBlockBytes;
        const Uint32 counter =
            cInitialCounter
            + static_cast<Uint32>(processed / cBlockBytes);
        alc_error_t err = xorBlock(key,
                                   iv,
                                   counter,
                                   plaintext + processed,
                                   ciphertext + processed,
                                   bytesToXor);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }
    return ALC_ERROR_NONE;
}
} // namespace alcp::cipher
