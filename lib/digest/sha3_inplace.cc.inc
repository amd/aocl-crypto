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

#ifdef COMPILER_IS_GCC
#define UNROLL_5 _Pragma("GCC unroll 5")
#define UNROLL_6 _Pragma("GCC unroll 6")
#else
#define UNROLL_5
#define UNROLL_6
#endif

static constexpr Uint64 cNumRounds = 24;

// x : x xord , y : ycord , round : round num
constexpr int
ycord(int x, int y, int round)
{
    if (round > 1) {
        return ycord(x, (x + 2 * y) % cDim, round - 1);
    }
    return (x + 2 * y) % cDim;
}

__attribute__((
    aligned(64))) static constexpr Uint64 cRoundConstants[cNumRounds] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static inline void
updateState(
    Uint64& a, Uint64& b, Uint64& c, Uint64& d, Uint64& e, uint64_t B[cDim])
{
    // A[Ni+1(x, y)T] = B[x] ⊕ ((NOT B[x + 1]) AND B[x + 2])
    a = B[0] ^ (~B[1] & B[2]);
    b = B[1] ^ (~B[2] & B[3]);
    c = B[2] ^ (~B[3] & B[4]);
    d = B[3] ^ (~B[4] & B[0]);
    e = B[4] ^ (~B[0] & B[1]);
}

static inline void
updateInterState(uint64_t C[cDim], uint64_t D[cDim], Uint64 state[cDim][cDim])
{

    // for x = 0 to 4 do
    // C[x] = A[Ni(x, 0)T] ⊕ A[Ni(x, 1)T] ⊕ A[Ni(x, 2)T] ⊕ A[Ni(x, 3)T]
    // ⊕ A[Ni(x, 4)T]
    UNROLL_5 for (int j = 0; j < cDim; j++)
    {
        C[j] =
            state[0][j] ^ state[1][j] ^ state[2][j] ^ state[3][j] ^ state[4][j];
    }

    // for x = 0 to 4 do
    // D[x] = C[x − 1] ⊕ ROT(C[x + 1], 1)
    D[0] = C[4] ^ RotateLeft(C[1], 1);
    D[1] = C[0] ^ RotateLeft(C[2], 1);
    D[2] = C[1] ^ RotateLeft(C[3], 1);
    D[3] = C[2] ^ RotateLeft(C[4], 1);
    D[4] = C[3] ^ RotateLeft(C[0], 1);
}

// This is based on section 2.5 of "Keccak implementation overview"

static inline void
fFunction(Uint64 state[cDim][cDim])
{
    uint64_t B[cDim], C[cDim], D[cDim];

    UNROLL_6
    for (Uint64 i = 0; i < cNumRounds; i += 4) {

        // round 1
        updateInterState(C, D, state);

        // for y = 0 to 4 do
        // for x = 0 to 4 do
        // B[x + 2y] = ROT((A[Ni+1(x, y)T] ⊕ D[x]),r[N(x, y)T])
        // end for
        // for x = 0 to 4 do
        // A[Ni+1(x, y)T] = B[x] ⊕ ((NOT B[x + 1]) AND B[x + 2])
        // end for
        // end for

        // Hardcode indexing is used to prevent the modulo and A[Ni+1(x,
        // y)T] operations for better performance

        // The matrix N has order 4, so ater every 4 rounds the state
        // matrix will contain the state without transposition and we
        // can use the same code starting round 5

        // B[x + 2y] = ROT((A[Ni+1(x, y)T] ⊕ D[x]),r[N(x, y)T])
        B[ycord(0, 0, 1)] = state[ycord(0, 0, 1)][0] ^ D[0];
        B[ycord(1, 0, 1)] = RotateLeft(state[ycord(1, 0, 1)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 0, 1)][1]);
        B[ycord(2, 0, 1)] = RotateLeft(state[ycord(2, 0, 1)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 0, 1)][2]);
        B[ycord(3, 0, 1)] = RotateLeft(state[ycord(3, 0, 1)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 0, 1)][3]);
        B[ycord(4, 0, 1)] = RotateLeft(state[ycord(4, 0, 1)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 0, 1)][4]);

        updateState(state[ycord(0, 0, 1)][0],
                    state[ycord(1, 0, 1)][1],
                    state[ycord(2, 0, 1)][2],
                    state[ycord(3, 0, 1)][3],
                    state[ycord(4, 0, 1)][4],
                    B);

        B[ycord(0, 1, 1)] = RotateLeft(state[ycord(0, 1, 1)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 1, 1)][0]);
        B[ycord(1, 1, 1)] = RotateLeft(state[ycord(1, 1, 1)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 1, 1)][1]);
        B[ycord(2, 1, 1)] = RotateLeft(state[ycord(2, 1, 1)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 1, 1)][2]);
        B[ycord(3, 1, 1)] = RotateLeft(state[ycord(3, 1, 1)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 1, 1)][3]);
        B[ycord(4, 1, 1)] = RotateLeft(state[ycord(4, 1, 1)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 1, 1)][4]);

        updateState(state[ycord(0, 1, 1)][0],
                    state[ycord(1, 1, 1)][1],
                    state[ycord(2, 1, 1)][2],
                    state[ycord(3, 1, 1)][3],
                    state[ycord(4, 1, 1)][4],
                    B);

        B[ycord(0, 2, 1)] = RotateLeft(state[ycord(0, 2, 1)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 2, 1)][0]);
        B[ycord(1, 2, 1)] = RotateLeft(state[ycord(1, 2, 1)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 2, 1)][1]);
        B[ycord(2, 2, 1)] = RotateLeft(state[ycord(2, 2, 1)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 2, 1)][2]);
        B[ycord(3, 2, 1)] = RotateLeft(state[ycord(3, 2, 1)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 2, 1)][3]);
        B[ycord(4, 2, 1)] = RotateLeft(state[ycord(4, 2, 1)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 2, 1)][4]);

        updateState(state[ycord(0, 2, 1)][0],
                    state[ycord(1, 2, 1)][1],
                    state[ycord(2, 2, 1)][2],
                    state[ycord(3, 2, 1)][3],
                    state[ycord(4, 2, 1)][4],
                    B);

        B[ycord(0, 3, 1)] = RotateLeft(state[ycord(0, 3, 1)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 3, 1)][0]);
        B[ycord(1, 3, 1)] = RotateLeft(state[ycord(1, 3, 1)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 3, 1)][1]);
        B[ycord(2, 3, 1)] = RotateLeft(state[ycord(2, 3, 1)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 3, 1)][2]);
        B[ycord(3, 3, 1)] = RotateLeft(state[ycord(3, 3, 1)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 3, 1)][3]);
        B[ycord(4, 3, 1)] = RotateLeft(state[ycord(4, 3, 1)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 3, 1)][4]);

        updateState(state[ycord(0, 3, 1)][0],
                    state[ycord(1, 3, 1)][1],
                    state[ycord(2, 3, 1)][2],
                    state[ycord(3, 3, 1)][3],
                    state[ycord(4, 3, 1)][4],
                    B);

        B[ycord(0, 4, 1)] = RotateLeft(state[ycord(0, 4, 1)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 4, 1)][0]);
        B[ycord(1, 4, 1)] = RotateLeft(state[ycord(1, 4, 1)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 4, 1)][1]);
        B[ycord(2, 4, 1)] = RotateLeft(state[ycord(2, 4, 1)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 4, 1)][2]);
        B[ycord(3, 4, 1)] = RotateLeft(state[ycord(3, 4, 1)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 4, 1)][3]);
        B[ycord(4, 4, 1)] = RotateLeft(state[ycord(4, 4, 1)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 4, 1)][4]);

        updateState(state[ycord(0, 4, 1)][0],
                    state[ycord(1, 4, 1)][1],
                    state[ycord(2, 4, 1)][2],
                    state[ycord(3, 4, 1)][3],
                    state[ycord(4, 4, 1)][4],
                    B);

        // A[0, 0] = A[0, 0] ⊕ RC[i]
        state[0][0] ^= cRoundConstants[i];

        // Rest of the 3 rounds are repitition
        // of the formualae of first round

        // round 2
        updateInterState(C, D, state);

        B[ycord(0, 0, 1)] = state[ycord(0, 0, 2)][0] ^ D[0];
        B[ycord(1, 0, 1)] = RotateLeft(state[ycord(1, 0, 2)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 0, 1)][1]);
        B[ycord(2, 0, 1)] = RotateLeft(state[ycord(2, 0, 2)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 0, 1)][2]);
        B[ycord(3, 0, 1)] = RotateLeft(state[ycord(3, 0, 2)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 0, 1)][3]);
        B[ycord(4, 0, 1)] = RotateLeft(state[ycord(4, 0, 2)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 0, 1)][4]);

        updateState(state[ycord(0, 0, 2)][0],
                    state[ycord(1, 0, 2)][1],
                    state[ycord(2, 0, 2)][2],
                    state[ycord(3, 0, 2)][3],
                    state[ycord(4, 0, 2)][4],
                    B);

        B[ycord(0, 1, 1)] = RotateLeft(state[ycord(0, 1, 2)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 1, 1)][0]);
        B[ycord(1, 1, 1)] = RotateLeft(state[ycord(1, 1, 2)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 1, 1)][1]);
        B[ycord(2, 1, 1)] = RotateLeft(state[ycord(2, 1, 2)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 1, 1)][2]);
        B[ycord(3, 1, 1)] = RotateLeft(state[ycord(3, 1, 2)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 1, 1)][3]);
        B[ycord(4, 1, 1)] = RotateLeft(state[ycord(4, 1, 2)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 1, 1)][4]);

        updateState(state[ycord(0, 1, 2)][0],
                    state[ycord(1, 1, 2)][1],
                    state[ycord(2, 1, 2)][2],
                    state[ycord(3, 1, 2)][3],
                    state[ycord(4, 1, 2)][4],
                    B);

        B[ycord(0, 2, 1)] = RotateLeft(state[ycord(0, 2, 2)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 2, 1)][0]);
        B[ycord(1, 2, 1)] = RotateLeft(state[ycord(1, 2, 2)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 2, 1)][1]);
        B[ycord(2, 2, 1)] = RotateLeft(state[ycord(2, 2, 2)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 2, 1)][2]);
        B[ycord(3, 2, 1)] = RotateLeft(state[ycord(3, 2, 2)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 2, 1)][3]);
        B[ycord(4, 2, 1)] = RotateLeft(state[ycord(4, 2, 2)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 2, 1)][4]);

        updateState(state[ycord(0, 2, 2)][0],
                    state[ycord(1, 2, 2)][1],
                    state[ycord(2, 2, 2)][2],
                    state[ycord(3, 2, 2)][3],
                    state[ycord(4, 2, 2)][4],
                    B);

        B[ycord(0, 3, 1)] = RotateLeft(state[ycord(0, 3, 2)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 3, 1)][0]);
        B[ycord(1, 3, 1)] = RotateLeft(state[ycord(1, 3, 2)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 3, 1)][1]);
        B[ycord(2, 3, 1)] = RotateLeft(state[ycord(2, 3, 2)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 3, 1)][2]);
        B[ycord(3, 3, 1)] = RotateLeft(state[ycord(3, 3, 2)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 3, 1)][3]);
        B[ycord(4, 3, 1)] = RotateLeft(state[ycord(4, 3, 2)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 3, 1)][4]);

        updateState(state[ycord(0, 3, 2)][0],
                    state[ycord(1, 3, 2)][1],
                    state[ycord(2, 3, 2)][2],
                    state[ycord(3, 3, 2)][3],
                    state[ycord(4, 3, 2)][4],
                    B);

        B[ycord(0, 4, 1)] = RotateLeft(state[ycord(0, 4, 2)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 4, 1)][0]);
        B[ycord(1, 4, 1)] = RotateLeft(state[ycord(1, 4, 2)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 4, 1)][1]);
        B[ycord(2, 4, 1)] = RotateLeft(state[ycord(2, 4, 2)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 4, 1)][2]);
        B[ycord(3, 4, 1)] = RotateLeft(state[ycord(3, 4, 2)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 4, 1)][3]);
        B[ycord(4, 4, 1)] = RotateLeft(state[ycord(4, 4, 2)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 4, 1)][4]);

        updateState(state[ycord(0, 4, 2)][0],
                    state[ycord(1, 4, 2)][1],
                    state[ycord(2, 4, 2)][2],
                    state[ycord(3, 4, 2)][3],
                    state[ycord(4, 4, 2)][4],
                    B);

        state[0][0] ^= cRoundConstants[i + 1];

        // round 3
        updateInterState(C, D, state);

        B[ycord(0, 0, 1)] = state[ycord(0, 0, 3)][0] ^ D[0];
        B[ycord(1, 0, 1)] = RotateLeft(state[ycord(1, 0, 3)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 0, 1)][1]);
        B[ycord(2, 0, 1)] = RotateLeft(state[ycord(2, 0, 3)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 0, 1)][2]);
        B[ycord(3, 0, 1)] = RotateLeft(state[ycord(3, 0, 3)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 0, 1)][3]);
        B[ycord(4, 0, 1)] = RotateLeft(state[ycord(4, 0, 3)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 0, 1)][4]);

        updateState(state[ycord(0, 0, 3)][0],
                    state[ycord(1, 0, 3)][1],
                    state[ycord(2, 0, 3)][2],
                    state[ycord(3, 0, 3)][3],
                    state[ycord(4, 0, 3)][4],
                    B);

        B[ycord(0, 1, 1)] = RotateLeft(state[ycord(0, 1, 3)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 1, 1)][0]);
        B[ycord(1, 1, 1)] = RotateLeft(state[ycord(1, 1, 3)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 1, 1)][1]);
        B[ycord(2, 1, 1)] = RotateLeft(state[ycord(2, 1, 3)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 1, 1)][2]);
        B[ycord(3, 1, 1)] = RotateLeft(state[ycord(3, 1, 3)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 1, 1)][3]);
        B[ycord(4, 1, 1)] = RotateLeft(state[ycord(4, 1, 3)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 1, 1)][4]);

        updateState(state[ycord(0, 1, 3)][0],
                    state[ycord(1, 1, 3)][1],
                    state[ycord(2, 1, 3)][2],
                    state[ycord(3, 1, 3)][3],
                    state[ycord(4, 1, 3)][4],
                    B);

        B[ycord(0, 2, 1)] = RotateLeft(state[ycord(0, 2, 3)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 2, 1)][0]);
        B[ycord(1, 2, 1)] = RotateLeft(state[ycord(1, 2, 3)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 2, 1)][1]);
        B[ycord(2, 2, 1)] = RotateLeft(state[ycord(2, 2, 3)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 2, 1)][2]);
        B[ycord(3, 2, 1)] = RotateLeft(state[ycord(3, 2, 3)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 2, 1)][3]);
        B[ycord(4, 2, 1)] = RotateLeft(state[ycord(4, 2, 3)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 2, 1)][4]);

        updateState(state[ycord(0, 2, 3)][0],
                    state[ycord(1, 2, 3)][1],
                    state[ycord(2, 2, 3)][2],
                    state[ycord(3, 2, 3)][3],
                    state[ycord(4, 2, 3)][4],
                    B);

        B[ycord(0, 3, 1)] = RotateLeft(state[ycord(0, 3, 3)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 3, 1)][0]);
        B[ycord(1, 3, 1)] = RotateLeft(state[ycord(1, 3, 3)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 3, 1)][1]);
        B[ycord(2, 3, 1)] = RotateLeft(state[ycord(2, 3, 3)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 3, 1)][2]);
        B[ycord(3, 3, 1)] = RotateLeft(state[ycord(3, 3, 3)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 3, 1)][3]);
        B[ycord(4, 3, 1)] = RotateLeft(state[ycord(4, 3, 3)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 3, 1)][4]);

        updateState(state[ycord(0, 3, 3)][0],
                    state[ycord(1, 3, 3)][1],
                    state[ycord(2, 3, 3)][2],
                    state[ycord(3, 3, 3)][3],
                    state[ycord(4, 3, 3)][4],
                    B);

        B[ycord(0, 4, 1)] = RotateLeft(state[ycord(0, 4, 3)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 4, 1)][0]);
        B[ycord(1, 4, 1)] = RotateLeft(state[ycord(1, 4, 3)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 4, 1)][1]);
        B[ycord(2, 4, 1)] = RotateLeft(state[ycord(2, 4, 3)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 4, 1)][2]);
        B[ycord(3, 4, 1)] = RotateLeft(state[ycord(3, 4, 3)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 4, 1)][3]);
        B[ycord(4, 4, 1)] = RotateLeft(state[ycord(4, 4, 3)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 4, 1)][4]);

        updateState(state[ycord(0, 4, 3)][0],
                    state[ycord(1, 4, 3)][1],
                    state[ycord(2, 4, 3)][2],
                    state[ycord(3, 4, 3)][3],
                    state[ycord(4, 4, 3)][4],
                    B);

        state[0][0] ^= cRoundConstants[i + 2];

        // Round 4
        updateInterState(C, D, state);

        B[ycord(0, 0, 1)] = state[ycord(0, 0, 4)][0] ^ D[0];
        B[ycord(1, 0, 1)] = RotateLeft(state[ycord(1, 0, 4)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 0, 1)][1]);
        B[ycord(2, 0, 1)] = RotateLeft(state[ycord(2, 0, 4)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 0, 1)][2]);
        B[ycord(3, 0, 1)] = RotateLeft(state[ycord(3, 0, 4)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 0, 1)][3]);
        B[ycord(4, 0, 1)] = RotateLeft(state[ycord(4, 0, 4)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 0, 1)][4]);

        updateState(state[ycord(0, 0, 4)][0],
                    state[ycord(1, 0, 4)][1],
                    state[ycord(2, 0, 4)][2],
                    state[ycord(3, 0, 4)][3],
                    state[ycord(4, 0, 4)][4],
                    B);

        B[ycord(0, 1, 1)] = RotateLeft(state[ycord(0, 1, 4)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 1, 1)][0]);
        B[ycord(1, 1, 1)] = RotateLeft(state[ycord(1, 1, 4)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 1, 1)][1]);
        B[ycord(2, 1, 1)] = RotateLeft(state[ycord(2, 1, 4)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 1, 1)][2]);
        B[ycord(3, 1, 1)] = RotateLeft(state[ycord(3, 1, 4)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 1, 1)][3]);
        B[ycord(4, 1, 1)] = RotateLeft(state[ycord(4, 1, 4)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 1, 1)][4]);

        updateState(state[ycord(0, 1, 4)][0],
                    state[ycord(1, 1, 4)][1],
                    state[ycord(2, 1, 4)][2],
                    state[ycord(3, 1, 4)][3],
                    state[ycord(4, 1, 4)][4],
                    B);

        B[ycord(0, 2, 1)] = RotateLeft(state[ycord(0, 2, 4)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 2, 1)][0]);
        B[ycord(1, 2, 1)] = RotateLeft(state[ycord(1, 2, 4)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 2, 1)][1]);
        B[ycord(2, 2, 1)] = RotateLeft(state[ycord(2, 2, 4)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 2, 1)][2]);
        B[ycord(3, 2, 1)] = RotateLeft(state[ycord(3, 2, 4)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 2, 1)][3]);
        B[ycord(4, 2, 1)] = RotateLeft(state[ycord(4, 2, 4)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 2, 1)][4]);

        updateState(state[ycord(0, 2, 4)][0],
                    state[ycord(1, 2, 4)][1],
                    state[ycord(2, 2, 4)][2],
                    state[ycord(3, 2, 4)][3],
                    state[ycord(4, 2, 4)][4],
                    B);

        B[ycord(0, 3, 1)] = RotateLeft(state[ycord(0, 3, 4)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 3, 1)][0]);
        B[ycord(1, 3, 1)] = RotateLeft(state[ycord(1, 3, 4)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 3, 1)][1]);
        B[ycord(2, 3, 1)] = RotateLeft(state[ycord(2, 3, 4)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 3, 1)][2]);
        B[ycord(3, 3, 1)] = RotateLeft(state[ycord(3, 3, 4)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 3, 1)][3]);
        B[ycord(4, 3, 1)] = RotateLeft(state[ycord(4, 3, 4)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 3, 1)][4]);

        updateState(state[ycord(0, 3, 4)][0],
                    state[ycord(1, 3, 4)][1],
                    state[ycord(2, 3, 4)][2],
                    state[ycord(3, 3, 4)][3],
                    state[ycord(4, 3, 4)][4],
                    B);

        B[ycord(0, 4, 1)] = RotateLeft(state[ycord(0, 4, 4)][0] ^ D[0],
                                       cRotationConstants[ycord(0, 4, 1)][0]);
        B[ycord(1, 4, 1)] = RotateLeft(state[ycord(1, 4, 4)][1] ^ D[1],
                                       cRotationConstants[ycord(1, 4, 1)][1]);
        B[ycord(2, 4, 1)] = RotateLeft(state[ycord(2, 4, 4)][2] ^ D[2],
                                       cRotationConstants[ycord(2, 4, 1)][2]);
        B[ycord(3, 4, 1)] = RotateLeft(state[ycord(3, 4, 4)][3] ^ D[3],
                                       cRotationConstants[ycord(3, 4, 1)][3]);
        B[ycord(4, 4, 1)] = RotateLeft(state[ycord(4, 4, 4)][4] ^ D[4],
                                       cRotationConstants[ycord(4, 4, 1)][4]);

        updateState(state[ycord(0, 4, 4)][0],
                    state[ycord(1, 4, 4)][1],
                    state[ycord(2, 4, 4)][2],
                    state[ycord(3, 4, 4)][3],
                    state[ycord(4, 4, 4)][4],
                    B);

        state[0][0] ^= cRoundConstants[i + 3];
    }
}
inline void
absorbChunk(Uint64* pSrc, Uint64 chunk_size_u64, Uint64* pState)
{
    auto src           = reinterpret_cast<Uint8*>(pSrc);
    auto state         = reinterpret_cast<Uint8*>(pState);
    auto chunk_size_u8 = chunk_size_u64 * 8;
    // check if we do gcc unroll here
    for (Uint64 i = 0; i < chunk_size_u8; ++i) {
        state[i] ^= src[i];
    }
    fFunction((Uint64(*)[cDim])pState);
}

void
Sha3Finalize(Uint8*  state,
             Uint8*  hash,
             Uint64  hash_size,
             Uint64  chunk_size,
             Uint64& index)
{
    // Uint64 hash_copied = 0;
    Uint64 rem = chunk_size - index;

    if (hash_size <= rem) {
        utils::CopyBlock(hash, state + index, hash_size);
        index = (index + hash_size);
        return;
    }
    utils::CopyBlock(hash, state + index, rem);
    hash_size -= rem;
    hash += rem;
    index = 0;

    while (hash_size) {
        fFunction((Uint64(*)[cDim])state);
        if (hash_size <= chunk_size) {
            utils::CopyBlock(hash, state + index, hash_size);
            index = (index + hash_size);
            return;
        }
        utils::CopyBlock(hash, state, chunk_size);
        hash_size -= chunk_size;
        hash += chunk_size;
    }
}

alc_error_t
Sha3Update(Uint64* state, Uint64* pSrc, Uint64 msg_size, Uint64 chunk_size)
{

    Uint32 num_chunks     = msg_size / chunk_size;
    Uint64 chunk_size_u64 = chunk_size / 8;

    for (Uint32 i = 0; i < num_chunks; i++) {
        absorbChunk(pSrc, chunk_size_u64, state);
        pSrc += chunk_size_u64;
    }

    return ALC_ERROR_NONE;
}
