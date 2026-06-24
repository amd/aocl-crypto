/*
 * Copyright (C) 2025, Advanced Micro Devices. All rights reserved.
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

#include <immintrin.h>

#include "alcp/digest/sha256_mb_avx512.hh"
#include "sha2_mb_avx512.hh"

namespace alcp::digest { namespace zen4 {

    static inline __attribute__((always_inline)) void compute_msg_sch(
        __m512i& zmm0, __m512i zmm1, __m512i zmm9, __m512i zmm14)
    {
#ifdef COMPILER_IS_GCC
        // Memory fence to prevent reordering
        asm volatile("" ::: "memory");
#endif
        __m512i s0 = sigma_0(zmm1);
        __m512i s1 = sigma_1(zmm14);

        /* W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
         * where 0 <= t <= 63.
         *
         * W[0..15] are directly taken from the input block.
         * W[16..63] need to be computed; hence this function must be called
         * 48 times per input block.
         *
         * W16 = sigma1(W14) + W[9] + sigma0(W[1]) + W[0].
         * Finally, W0 is set to W16.
         * This function must be called only after W0 is used in round 0.
         */
        zmm0 = _mm512_add_epi32(zmm0, s0);
        zmm0 = _mm512_add_epi32(zmm0, zmm9);
        zmm0 = _mm512_add_epi32(zmm0, s1);
    }

    static inline __attribute__((always_inline)) void round(__m512i  W0,
                                                            Uint64   i,
                                                            __m512i  a,
                                                            __m512i  b,
                                                            __m512i  c,
                                                            __m512i& d,
                                                            __m512i  e,
                                                            __m512i  f,
                                                            __m512i  g,
                                                            __m512i& h)
    {
        __m512i K = _mm512_set1_epi32(cRoundConstants_SHA256[i]);

        /* T1 = h + Sigma1(e) + Ch(e,f,g) + K + W.
         * Finally, d is set to d + T1.
         * Which is the new value of `e` after rotation in the next round.
         */
        __m512i choice = _mm512_ternarylogic_epi32(e, f, g, 0xCA);
        __m512i T1     = _mm512_add_epi32(h, W0);
        __m512i S1     = Sigma_1(e);
        T1             = _mm512_add_epi32(T1, K);
        T1             = _mm512_add_epi32(T1, choice);
        T1             = _mm512_add_epi32(T1, S1);
#ifdef COMPILER_IS_GCC
        // Inline asm forces an in-place vpaddd encoding (and acts as a compiler
        // barrier), avoiding compiler-introduced moves/re-encodings
        asm volatile("vpaddd %[d], %[T1], %[d] \n\t"
                     : [d] "+v"(d)
                     : [T1] "v"(T1));
#else
        d = _mm512_add_epi32(d, T1);
#endif

        /* T2 = Sigma0(a) + Maj(a,b,c).
         * Finally, h is set to T1 + T2.
         * This becomes the new value of `a` after rotation in the next round.
         * `h` is chosen here because its value is discarded when working
         * variables are rotated.
         */
        __m512i major = _mm512_ternarylogic_epi32(a, b, c, 0xE8);
        __m512i S0    = Sigma_0(a);
        __m512i T2    = _mm512_add_epi32(S0, major);
        h             = _mm512_add_epi32(T1, T2);
    }

    static inline void update_state_index(Uint64& a,
                                          Uint64& b,
                                          Uint64& c,
                                          Uint64& d,
                                          Uint64& e,
                                          Uint64& f,
                                          Uint64& g,
                                          Uint64& h)
    {
        /*
         * With index update, we perform the following rotations on working
         * variables:
         *
         * h = g
         * g = f
         * f = e
         *
         * e = d + T1
         * This is achieved by simply doing e = d (i.e. updating index `e`
         * to now have the value of index `d`). This works because after the
         * round function the value of `d` is set to d + T1.
         *
         * d = c
         * c = b
         * b = a
         *
         * a = T1 + T2
         * This is achieved by simply doing a = h (i.e. updating index `a`
         * to now have the value of index `h`). This works because after the
         * round function the value of `h` is set to T1 + T2.
         */
        a = (a + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        b = (b + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        c = (c + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        d = (d + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        e = (e + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        f = (f + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        g = (g + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
        h = (h + NUM_WORKING_VARIABLES - 1) & (NUM_WORKING_VARIABLES - 1);
    }

    static inline void update_block_index(Uint64& i0,
                                          Uint64& i1,
                                          Uint64& i9,
                                          Uint64& i14)
    {
        /*
         * W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
         *
         * This function ensures that the indices of words are updated
         * correctly as t varies from 16 to 63. Example: when t = 16,
         * i0 = 0, i1 = 1, i9 = 9 and i14 = 14.
         *
         * NOTE: Modulo 16 is used, as we rotate message schedule
         * words into the same 16 local variables.
         */
        i0  = (i0 + 1) & (SHA256_BLOCK_SIZE_WORDS - 1);
        i1  = (i1 + 1) & (SHA256_BLOCK_SIZE_WORDS - 1);
        i9  = (i9 + 1) & (SHA256_BLOCK_SIZE_WORDS - 1);
        i14 = (i14 + 1) & (SHA256_BLOCK_SIZE_WORDS - 1);
    }

    static inline void compute_block(__m512i block[SHA256_BLOCK_SIZE_WORDS],
                                     __m512i state[NUM_WORKING_VARIABLES])
    {
        Uint64 i0 = 0, i1 = 1, i9 = 9, i14 = 14;
        Uint64 a = 0, b = 1, c = 2, d = 3, e = 4, f = 5, g = 6, h = 7;

        /* Rounds 0 - 47
         * Since in each round one word from the message schedule is consumed,
         * we can replace it with a new word to be used in subsequent rounds.
         */
        UNROLL_48
        for (Uint64 i = 0; i < ROUNDS_48; i++) {
            round(block[i0],
                  i,
                  state[a],
                  state[b],
                  state[c],
                  state[d],
                  state[e],
                  state[f],
                  state[g],
                  state[h]);
            update_state_index(a, b, c, d, e, f, g, h);
            compute_msg_sch(block[i0], block[i1], block[i9], block[i14]);
            update_block_index(i0, i1, i9, i14);
        }

        /* Rounds 48 - 63
         * Since this function is intended to be used on the last block, the
         * next block is not loaded here.
         */
        UNROLL_16
        for (Uint64 i = 0; i < ROUNDS_16; i++) {
            round(block[i],
                  i + ROUNDS_48,
                  state[a],
                  state[b],
                  state[c],
                  state[d],
                  state[e],
                  state[f],
                  state[g],
                  state[h]);
            update_state_index(a, b, c, d, e, f, g, h);
        }
    }

    static inline __attribute__((always_inline)) void update_state(
        __m512i state[NUM_WORKING_VARIABLES],
        Uint32  hash[NUM_WORKING_VARIABLES][BUFFERS_16])
    {
        /* This function updates the intermediate hash values as:
         * H[0](i) = a + H[0](i-1)
         * H[1](i) = b + H[1](i-1)
         * H[2](i) = c + H[2](i-1)
         * H[3](i) = d + H[3](i-1)
         * H[4](i) = e + H[4](i-1)
         * H[5](i) = f + H[5](i-1)
         * H[6](i) = g + H[6](i-1)
         * H[7](i) = h + H[7](i-1)
         * where (i) indicates the current state and (i-1) indicates the
         * previous state.
         */
        UNROLL_8
        for (Uint64 i = 0; i < NUM_WORKING_VARIABLES; i++) {
            state[i] = _mm512_add_epi32(
                state[i], _mm512_loadu_si512((const void*)&hash[i][0]));
            _mm512_storeu_si512((void*)&hash[i][0], state[i]);
        }
    }

    static inline void finalize(const __m128i** p_p_src,
                                Uint64          residue,
                                Uint64          cLength,
                                Uint64          block_offset,
                                __m512i         block[SHA256_BLOCK_SIZE_WORDS],
                                __m512i         state[NUM_WORKING_VARIABLES],
                                Uint32 hash[NUM_WORKING_VARIABLES][BUFFERS_16])
    {
        /* Add padding. */

        /* Append a `1` bit immediately after the last valid byte. */
        const Uint64 cLastWordIndex =
            residue >> 2; // residue/SHA256_WORD_SIZE_BYTES
        __m512i c_one = _mm512_set1_epi32(
            0x80000000
            >> (residue & (SHA256_WORD_SIZE_BYTES - 1)) * BITS_PER_BYTE);

        block[cLastWordIndex] = _mm512_or_si512(block[cLastWordIndex], c_one);

        /* If there is no room for 9 bytes of padding in the current block,
         * run the round computation for the current block and prepare the
         * next block.
         */
        if (residue >= 56) {
            compute_block(block, state);
            update_state(state, hash);
            UNROLL_14
            for (Uint64 i = 0; i < (SHA256_BLOCK_SIZE_WORDS - 2); i++) {
                block[i] = _mm512_setzero_si512();
            }
        }

        /* Append the message length (in bits) as padding. */
        Uint64 length_bits = cLength * BITS_PER_BYTE;
        Uint32 padding_lsb = static_cast<Uint32>(length_bits);
        Uint32 padding_msb = static_cast<Uint32>(length_bits >> 32);

        block[14] = _mm512_set1_epi32(padding_msb);
        block[15] = _mm512_set1_epi32(padding_lsb);

        /* Do round computation for the last block. */
        compute_block(block, state);
        update_state(state, hash);
    }

    static inline __attribute__((always_inline)) void compute_and_load(
        __m512i         block[SHA256_BLOCK_SIZE_WORDS],
        __m512i         state[NUM_WORKING_VARIABLES],
        const __m128i** p_p_src,
        Uint64          next_block_offset)
    {
        Uint64 i0 = 0, i1 = 1, i9 = 9, i14 = 14;
        Uint64 a = 0, b = 1, c = 2, d = 3, e = 4, f = 5, g = 6, h = 7;

        /* Rounds 0 - 47,
         * Since in each round one word from message schedule is consumed we can
         * replace it with a new word to be used in subsequent round
         */
        UNROLL_48
        for (Uint64 i = 0; i < ROUNDS_48; i++) {
            round(block[i0],
                  i,
                  state[a],
                  state[b],
                  state[c],
                  state[d],
                  state[e],
                  state[f],
                  state[g],
                  state[h]);
            update_state_index(a, b, c, d, e, f, g, h);
            compute_msg_sch(block[i0], block[i1], block[i9], block[i14]);
            update_block_index(i0, i1, i9, i14);
        }

        /* Rounds 48 - 63,
         * And simultaneously load first 16 words of message schedule from next
         * block
         */
        UNROLL_4
        for (Uint64 k = 0; k < 4; k++) {
            UNROLL_4
            for (Uint64 i = 0; i < 4; i++) {
                round(block[k * 4 + i],
                      k * 4 + i + ROUNDS_48,
                      state[a],
                      state[b],
                      state[c],
                      state[d],
                      state[e],
                      state[f],
                      state[g],
                      state[h]);
                update_state_index(a, b, c, d, e, f, g, h);
            }
            load_words_4x16_u32(p_p_src,
                                next_block_offset + k,
                                block[k * 4 + 0],
                                block[k * 4 + 1],
                                block[k * 4 + 2],
                                block[k * 4 + 3]);
            transpose_4x16_u32(block[k * 4 + 0],
                               block[k * 4 + 1],
                               block[k * 4 + 2],
                               block[k * 4 + 3]);
        }
    }

#if defined(COMPILER_IS_GCC) && __GNUC__ >= 15
    // GCC 15 raised the znver5 reassociation width (commit f0ab3de6ec0,
    // "Zen5 tuning part 4: update reassociation width"). This makes the tree
    // reassociation pass split the 512-bit integer add chains in this kernel
    // into more parallel sub-chains than there are vector registers, causing
    // spills and a SHA256 multibuffer throughput regression on Zen5. Disabling
    // reassociation for this function restores the original add ordering.
    __attribute__((optimize("no-tree-reassoc")))
#endif
    alc_error_t Sha256Dequeue(const Uint8** ppSrcBuf,
                              Uint32        hash[SHA256_HASH_SIZE_WORDS],
                              const Uint64  cNumBuffers,
                              const Uint64  blocks,
                              const Uint64  totalMsgLen,
                              Uint8**       ppDstBuf,
                              const Uint64  cDigestLen)
    {
        alc_error_t err = ALC_ERROR_NONE;

        /* residue = totalMsgLen % SHA256_BLOCK_SIZE_BYTES */
        Uint64 residue = totalMsgLen & (SHA256_BLOCK_SIZE_BYTES - 1);

        /* buffers to process = smallest multiple of 16 greater than or equal to
         * cNumBuffers */
        Uint64 remaining_buffers = ((cNumBuffers + BUFFERS_16 - 1) >> 4) << 4;

        const __m128i* local_src[MAX_BUFFERS];
        __m128i*       local_dst[MAX_BUFFERS];

        for (Uint64 i = 0; i < cNumBuffers; i++) {
            local_src[i] = reinterpret_cast<const __m128i*>(ppSrcBuf[i]);
            local_dst[i] = reinterpret_cast<__m128i*>(ppDstBuf[i]);
        }

        /* Duplicate last buffer such that we have multiple of 16 buffers to
         * process */
        for (Uint64 i = cNumBuffers; i < remaining_buffers; i++) {
            local_src[i] =
                reinterpret_cast<const __m128i*>(ppSrcBuf[cNumBuffers - 1]);
            local_dst[i] =
                reinterpret_cast<__m128i*>(ppDstBuf[cNumBuffers - 1]);
        }

        const __m128i** p_p_src = reinterpret_cast<const __m128i**>(local_src);
        __m128i**       p_p_dst = reinterpret_cast<__m128i**>(local_dst);

        __m512i            block[SHA256_BLOCK_SIZE_WORDS]{};
        __m512i            state[NUM_WORKING_VARIABLES]{};
        alignas(64) Uint32 prev[NUM_WORKING_VARIABLES][BUFFERS_16];

        while (remaining_buffers >= BUFFERS_16) {
            broadcast_state(hash,
                            state[0],
                            state[1],
                            state[2],
                            state[3],
                            state[4],
                            state[5],
                            state[6],
                            state[7]);

            /* Save previous state */
            for (Uint64 i = 0; i < NUM_WORKING_VARIABLES; i++) {
                _mm512_storeu_si512((void*)&prev[i][0], state[i]);
            }

            if (blocks) {
                /* Load first block */
                load_words_4x16_u32(
                    p_p_src, 0, block[0], block[1], block[2], block[3]);
                load_words_4x16_u32(
                    p_p_src, 1, block[4], block[5], block[6], block[7]);
                load_words_4x16_u32(
                    p_p_src, 2, block[8], block[9], block[10], block[11]);
                load_words_4x16_u32(
                    p_p_src, 3, block[12], block[13], block[14], block[15]);

                /* Transpose data so that each variable has same word but from
                 * different instance/buffer */
                transpose_4x16_u32(block[0], block[1], block[2], block[3]);
                transpose_4x16_u32(block[4], block[5], block[6], block[7]);
                transpose_4x16_u32(block[8], block[9], block[10], block[11]);
                transpose_4x16_u32(block[12], block[13], block[14], block[15]);

                /* For first (block -1) number of blocks,
                 * compute rounds for current block and load next block
                 */
                Uint64 next_block_offset = NUM_XMM_PER_BLOCK;
                for (Uint64 i = 0; i < (blocks - 1); i++) {
                    compute_and_load(block, state, p_p_src, next_block_offset);
                    next_block_offset += NUM_XMM_PER_BLOCK;
                    update_state(state, prev);
                }

                /* Compute rounds for last block */
                compute_block(block, state);
                update_state(state, prev);
            }

            partial_load_block(
                p_p_src, residue, blocks * NUM_XMM_PER_BLOCK, block);

            finalize(p_p_src,
                     residue,
                     totalMsgLen,
                     blocks * NUM_XMM_PER_BLOCK,
                     block,
                     state,
                     prev);

            store(p_p_dst, state, cDigestLen);

            remaining_buffers -= BUFFERS_16;
            p_p_src += BUFFERS_16;
            p_p_dst += BUFFERS_16;
        }

        return err;
    }
}} // namespace alcp::digest::zen4
