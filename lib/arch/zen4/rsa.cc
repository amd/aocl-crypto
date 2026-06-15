/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#include "alcp/rsa.h"
#include "alcp/rsa/rsa_internal.hh"
#include "alcp/utils/copy.hh"
#include <immintrin.h>

/*
 * AMS1024 is based on Fast modular squaring with AVX512IFMA
 * referenced as mentioned on below link
 * https://eprint.iacr.org/2018/335
 * Authors - Nir Drucker & Shay Gueron
 *
 * AMM1024  and RSA2048MontgomeryExpConstantTimeParallel is based on Fast
 * modular multplication and exponentiation with AVX512IFMA referenced as
 * mentioned on below link
 * https://link.springer.com/chapter/10.1007/978-3-642-31662-3_9
 * Authors - Shay Gueron & Vlad Krasnov
 */

namespace alcp::rsa { namespace zen4 {
#include "../../rsa/rsa.cc.inc"

    constexpr Uint64 num_digit = (2048 / 52 + 1);

    static inline Uint64 GetRadix52Bit(Uint64 val)
    {
        constexpr Uint64 MaskRadix52Bit = 0xfffffffffffff;
        return val & MaskRadix52Bit;
    }

    static inline Uint64 BytesToUint64(const Uint8* val)
    {
        Uint64 val64 = 0;
        memcpy(&val64, val, 8);
        return val64;
    }
    // Converts the radix 64 bit in 1024 bits to radix 52 with 20 digits
    static inline void Rsa1024Radix64BitToRadix52Bit(Uint64*       out,
                                                     const Uint64* in)
    {

        const Uint8* in_byte = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 18; i += 2) {
            out[i]     = GetRadix52Bit(BytesToUint64(in_byte));
            out[i + 1] = GetRadix52Bit(BytesToUint64(in_byte + 6) >> 4);
            in_byte += 13;
        }

        out[18] = GetRadix52Bit(BytesToUint64(in_byte));

        out[19] = (*(in_byte + 6) >> 4) + (*(in_byte + 7) << 4)
                  + (*(in_byte + 8) << 12) + (*(in_byte + 9) << 20)
                  + ((Uint64)(*(in_byte + 10)) << 28);
    }
    // Converts 10-limb (52-bit each) representation of 512-bit number to 8 x Uint64
    static inline void Rsa512Radix64BitToRadix52Bit(Uint64* out, const Uint64* in)
    {
        const Uint8* in_byte = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 8; i += 2) {
            out[i]     = GetRadix52Bit(BytesToUint64(in_byte));
            out[i + 1] = GetRadix52Bit(BytesToUint64(in_byte + 6) >> 4);
            in_byte += 13;
        }
        out[8] = GetRadix52Bit(BytesToUint64(in_byte));
        /* out[9]: 44 bits at bit offset 468 = byte 58 bit 4.
         * Collect 44 bits across bytes 58-63. */
        out[9] = ((Uint64)(*(in_byte + 6)) >> 4)
                 + ((Uint64)(*(in_byte + 7)) << 4)
                 + ((Uint64)(*(in_byte + 8)) << 12)
                 + ((Uint64)(*(in_byte + 9)) << 20)
                 + ((Uint64)(*(in_byte + 10)) << 28)
                 + ((Uint64)(*(in_byte + 11)) << 36);
    }

    // Converts back 10 limbs of 52-bit to 8 x Uint64 (512-bit).
    // NOTE: the final read-modify-write writes through byte 65, so `out` must
    // point to at least 9 Uint64 (the 9th is scratch). Callers allocate [8 + 1].
    static inline void Rsa512Radix52BitToRadix64(Uint64* out, const Uint64* in)
    {
        Uint8*       out_byte = reinterpret_cast<Uint8*>(out);
        const Uint8* in_byte  = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 9; i += 2) {
            utils::CopyBytes(out_byte, in_byte + i * 8, 8);
            out_byte += 6;
            Uint64 processed = (BytesToUint64(out_byte)) ^ (in[i + 1] << 4);
            utils::CopyBytes(out_byte, reinterpret_cast<Uint8*>(&processed), 8);
            out_byte += 7;
        }
    }

    // Converts back the radix 52 bit in 1024 bits to radix 64.
    // NOTE: the final read-modify-write writes through byte 130, so `out` must
    // point to at least 17 Uint64 (the 17th is scratch). Callers allocate [16 + 1].
    static inline void Rsa1024Radix52BitToRadix64(Uint64* out, const Uint64* in)
    {

        Uint8*       out_byte = reinterpret_cast<Uint8*>(out);
        const Uint8* in_byte  = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 19; i += 2) {
            utils::CopyBytes(out_byte, in_byte + i * 8, 8);
            out_byte += 6;
            Uint64 processed = (BytesToUint64(out_byte)) ^ (in[i + 1] << 4);
            utils::CopyBytes(out_byte, reinterpret_cast<Uint8*>(&processed), 8);
            out_byte += 7;
        }
    }

    // Converts the radix 64 bit in 2048 bits to radix 52 bit with 40 digits
    static inline void Rsa2048Radix64BitToRadix52Bit(Uint64*       out,
                                                     const Uint64* in)
    {
        const Uint8* in_byte = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 38; i += 2) {
            out[i]     = GetRadix52Bit(BytesToUint64(in_byte));
            out[i + 1] = GetRadix52Bit((BytesToUint64(in_byte + 6)) >> 4);
            in_byte += 13;
        }

        out[38] = GetRadix52Bit(BytesToUint64(in_byte));

        out[39] = (*(in_byte + 6) >> 4) + (*(in_byte + 7) << 4)
                  + (*(in_byte + 8) << 12);
    }

    // Converts back the radix 52 bit in 2048 bits to radix 64
    static inline void Rsa2048Radix52BitToRadix64(Uint64*       out,
                                                     const Uint64* in)
    {
        Uint8* out_byte = reinterpret_cast<Uint8*>(out);
        for (Uint64 i = 0; i < 39; i += 2) {
            utils::CopyBytes(
                out_byte, reinterpret_cast<const Uint8*>(in) + i * 8, 8);
            out_byte += 6;
            Uint64 processed = (BytesToUint64(out_byte)) ^ (in[i + 1] << 4);
            utils::CopyBytes(out_byte, reinterpret_cast<Uint8*>(&processed), 8);
            out_byte += 7;
        }
    }

    // Constant-time: scans all 32 entries to avoid cache-timing leaks.
    // noinline to prevent code bloat in the exponentiation loop — the
    // inlined version inflated RSA2048MontgomeryExpConstantTimeParallel
    // to 23 KB, thrashing the µop cache.
    static __attribute__((noinline)) void GetFromTableParallel(
        Uint64* t, Uint64 index1, Uint64 index2, Uint64* num1, Uint64* num2)
    {
        Uint64*       t2   = t + 32 * 20;
        const __m512i seq  = _mm512_setr_epi64(0, 1, 2, 3, 4, 5, 6, 7);
        const __m512i tgt1 = _mm512_set1_epi64(static_cast<long long>(index1));
        const __m512i tgt2 = _mm512_set1_epi64(static_cast<long long>(index2));
        const __m512i perm1 =
            _mm512_set1_epi64(static_cast<long long>(index1 & 7));
        const __m512i perm2 =
            _mm512_set1_epi64(static_cast<long long>(index2 & 7));

        __mmask8 m1[4], m2[4];
        for (Uint64 j = 0; j < 32; j += 8) {
            __m512i cur = _mm512_add_epi64(
                seq, _mm512_set1_epi64(static_cast<long long>(j)));
            m1[j / 8] = _mm512_cmpeq_epi64_mask(cur, tgt1);
            m2[j / 8] = _mm512_cmpeq_epi64_mask(cur, tgt2);
        }

        for (Uint64 i = 0; i < 20; i++) {
            __m512i acc1 = _mm512_maskz_mov_epi64(m1[0], _mm512_loadu_si512(t));
            __m512i acc2 = _mm512_maskz_mov_epi64(m2[0], _mm512_loadu_si512(t2));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[1], acc1, _mm512_loadu_si512(t + 8));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[1], acc2, _mm512_loadu_si512(t2 + 8));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[2], acc1, _mm512_loadu_si512(t + 16));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[2], acc2, _mm512_loadu_si512(t2 + 16));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[3], acc1, _mm512_loadu_si512(t + 24));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[3], acc2, _mm512_loadu_si512(t2 + 24));
            num1[i] = _mm_cvtsi128_si64(_mm512_castsi512_si128(
                _mm512_permutexvar_epi64(perm1, acc1)));
            num2[i] = _mm_cvtsi128_si64(_mm512_castsi512_si128(
                _mm512_permutexvar_epi64(perm2, acc2)));
            t += 32;
            t2 += 32;
        }
    }

    static inline void PutInTableParallel(Uint64* t,
                                          Uint64  index,
                                          Uint64* num1,
                                          Uint64* num2)
    {
        // table has 32 entry and each entry is 20 64 bits
        Uint64* t2 = t + 32 * 20;
        for (Uint64 i = 0; i < 20; i++) {
            t[index]  = num1[i];
            t2[index] = num2[i];
            index += 32;
        }
    }

    static inline void FusedMultiplyAddLow512(__m512i       res[5],
                                              const __m512i mod[5],
                                              const __m512i y)
    {
        res[0] = _mm512_madd52lo_epu64(res[0], mod[0], y);
        res[1] = _mm512_madd52lo_epu64(res[1], mod[1], y);
        res[2] = _mm512_madd52lo_epu64(res[2], mod[2], y);
        res[3] = _mm512_madd52lo_epu64(res[3], mod[3], y);
        res[4] = _mm512_madd52lo_epu64(res[4], mod[4], y);
    }

    static inline void FusedMultiplyAddHigh512(__m512i       res[5],
                                               const __m512i mod[5],
                                               const __m512i y)
    {
        res[0] = _mm512_madd52hi_epu64(res[0], mod[0], y);
        res[1] = _mm512_madd52hi_epu64(res[1], mod[1], y);
        res[2] = _mm512_madd52hi_epu64(res[2], mod[2], y);
        res[3] = _mm512_madd52hi_epu64(res[3], mod[3], y);
        res[4] = _mm512_madd52hi_epu64(res[4], mod[4], y);
    }

    static inline void ShiftAndAddCarry512(__m512i res[5])
    {
        const __m512i zero{};
        __m512i       carry = _mm512_maskz_srli_epi64(1, res[0], 52);
        res[0]              = _mm512_alignr_epi64(res[1], res[0], 1);
        res[0]              = _mm512_add_epi64(res[0], carry);
        res[1]              = _mm512_alignr_epi64(res[2], res[1], 1);
        res[2]              = _mm512_alignr_epi64(res[3], res[2], 1);
        res[3]              = _mm512_alignr_epi64(res[4], res[3], 1);
        res[4]              = _mm512_alignr_epi64(zero, res[4], 1);
    }

    static inline void FusedMultiplyAddShiftLow512Stage1(__m512i res[5],
                                                         __m512i first[5],
                                                         __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52lo_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52lo_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52lo_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);

        temp   = _mm512_madd52lo_epu64(zero, first[3], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[3] = _mm512_add_epi64(temp, res[3]);

        temp   = _mm512_madd52lo_epu64(zero, first[4], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[4] = _mm512_add_epi64(temp, res[4]);
    }

    static inline void FusedMultiplyAddShiftLow512Stage2(__m512i res[4],
                                                         __m512i first[4],
                                                         __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52lo_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52lo_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52lo_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);

        temp   = _mm512_madd52lo_epu64(zero, first[3], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[3] = _mm512_add_epi64(temp, res[3]);
    }

    static inline void FusedMultiplyAddShiftLow512Stage3(__m512i res[3],
                                                         __m512i first[3],
                                                         __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52lo_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52lo_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52lo_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);
    }

    static inline void FusedMultiplyAddShiftLow512Stage4(__m512i res[2],
                                                         __m512i first[2],
                                                         __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52lo_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52lo_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);
    }

    static inline void FusedMultiplyAddShiftLow512Stage5(__m512i& res,
                                                         __m512i  first,
                                                         __m512i  second)
    {
        res = _mm512_madd52lo_epu64(res, first, second);
    }

    static inline void FusedMultiplyAddShiftHigh512Stage1(__m512i res[5],
                                                          __m512i first[5],
                                                          __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52hi_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52hi_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52hi_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);

        temp   = _mm512_madd52hi_epu64(zero, first[3], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[3] = _mm512_add_epi64(temp, res[3]);

        temp   = _mm512_madd52hi_epu64(zero, first[4], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[4] = _mm512_add_epi64(temp, res[4]);
    }

    static inline void FusedMultiplyAddShiftHigh512Stage2(__m512i res[4],
                                                          __m512i first[4],
                                                          __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52hi_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52hi_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52hi_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);

        temp   = _mm512_madd52hi_epu64(zero, first[3], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[3] = _mm512_add_epi64(temp, res[3]);
    }

    static inline void FusedMultiplyAddShiftHigh512Stage3(__m512i res[3],
                                                          __m512i first[3],
                                                          __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52hi_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52hi_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);

        temp   = _mm512_madd52hi_epu64(zero, first[2], second);
        temp   = _mm512_slli_epi64(temp, 1);
        res[2] = _mm512_add_epi64(temp, res[2]);
    }

    static inline void FusedMultiplyAddShiftHigh512Stage4(__m512i res[2],
                                                          __m512i first[2],
                                                          __m512i second)
    {
        const __m512i zero{};
        res[0]       = _mm512_madd52hi_epu64(res[0], first[0], second);
        __m512i temp = _mm512_madd52hi_epu64(zero, first[1], second);
        temp         = _mm512_slli_epi64(temp, 1);
        res[1]       = _mm512_add_epi64(temp, res[1]);
    }

    static inline void FusedMultiplyAddShiftHigh512Stage5(__m512i& res,
                                                          __m512i  first,
                                                          __m512i  second)
    {
        res = _mm512_madd52hi_epu64(res, first, second);
    }

    static inline void FusedMultiplyAddLow256(__m256i       res[5],
                                              const __m256i mod[5],
                                              const __m256i y)
    {
        res[0] = _mm256_madd52lo_epu64(res[0], mod[0], y);
        res[1] = _mm256_madd52lo_epu64(res[1], mod[1], y);
        res[2] = _mm256_madd52lo_epu64(res[2], mod[2], y);
        res[3] = _mm256_madd52lo_epu64(res[3], mod[3], y);
        res[4] = _mm256_madd52lo_epu64(res[4], mod[4], y);
    }

    static inline void FusedMultiplyAddHigh256(__m256i       res[5],
                                               const __m256i mod[5],
                                               const __m256i y)
    {
        res[0] = _mm256_madd52hi_epu64(res[0], mod[0], y);
        res[1] = _mm256_madd52hi_epu64(res[1], mod[1], y);
        res[2] = _mm256_madd52hi_epu64(res[2], mod[2], y);
        res[3] = _mm256_madd52hi_epu64(res[3], mod[3], y);
        res[4] = _mm256_madd52hi_epu64(res[4], mod[4], y);
    }

    static inline void ShiftAndAddCarry256(__m256i res[5])
    {
        const __m256i zero{};
        __m256i       carry = _mm256_maskz_srli_epi64(1, res[0], 52);
        res[0]              = _mm256_alignr_epi64(res[1], res[0], 1);
        res[0]              = _mm256_add_epi64(res[0], carry);
        res[1]              = _mm256_alignr_epi64(res[2], res[1], 1);
        res[2]              = _mm256_alignr_epi64(res[3], res[2], 1);
        res[3]              = _mm256_alignr_epi64(res[4], res[3], 1);
        res[4]              = _mm256_alignr_epi64(zero, res[4], 1);
    }

    // Mod reduction low for 3-YMM accumulator (10-limb 512-bit number)
    static inline void FusedMultiplyAddLow256_3(
        __m256i res[3], const __m256i mod[3], __m256i y)
    {
        res[0] = _mm256_madd52lo_epu64(res[0], mod[0], y);
        res[1] = _mm256_madd52lo_epu64(res[1], mod[1], y);
        res[2] = _mm256_madd52lo_epu64(res[2], mod[2], y);
    }

    // Mod reduction high for 3-YMM accumulator
    static inline void FusedMultiplyAddHigh256_3(
        __m256i res[3], const __m256i mod[3], __m256i y)
    {
        res[0] = _mm256_madd52hi_epu64(res[0], mod[0], y);
        res[1] = _mm256_madd52hi_epu64(res[1], mod[1], y);
        res[2] = _mm256_madd52hi_epu64(res[2], mod[2], y);
    }

    // Add doubled cross term (low): res += 2 * madd52lo(0, first, d)
    // Used in AMS (squaring) where off-diagonal products are doubled.
    static inline void AddCrossTermLo256(__m256i& res, __m256i first, __m256i d)
    {
        const __m256i zero{};
        __m256i       t = _mm256_madd52lo_epu64(zero, first, d);
        t               = _mm256_slli_epi64(t, 1);
        res             = _mm256_add_epi64(res, t);
    }

    // Add doubled cross term (high)
    static inline void AddCrossTermHi256(__m256i& res, __m256i first, __m256i d)
    {
        const __m256i zero{};
        __m256i       t = _mm256_madd52hi_epu64(zero, first, d);
        t               = _mm256_slli_epi64(t, 1);
        res             = _mm256_add_epi64(res, t);
    }

    // Shift-carry for 3-YMM accumulator (10 limbs in 4+4+2 layout).
    // Equivalent to ShiftAndAddCarry256 but for 3 regs instead of 5.
    static inline void ShiftAndAddCarry256_3(__m256i res[3])
    {
        const __m256i zero{};
        __m256i       carry = _mm256_maskz_srli_epi64(1, res[0], 52);
        res[0]              = _mm256_alignr_epi64(res[1], res[0], 1);
        res[0]              = _mm256_add_epi64(res[0], carry);
        res[1]              = _mm256_alignr_epi64(res[2], res[1], 1);
        res[2]              = _mm256_alignr_epi64(zero,   res[2], 1);
    }

    static inline void FusedMultiplyAddShiftLow256Stage1(__m256i res[5],
                                                         __m256i first[5],
                                                         __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52lo_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52lo_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);

        temp   = _mm256_madd52lo_epu64(zero, first[2], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[2] = _mm256_add_epi64(temp, res[2]);

        temp   = _mm256_madd52lo_epu64(zero, first[3], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[3] = _mm256_add_epi64(temp, res[3]);

        temp   = _mm256_madd52lo_epu64(zero, first[4], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[4] = _mm256_add_epi64(temp, res[4]);
    }

    static inline void FusedMultiplyAddShiftHigh256Stage1(__m256i res[5],
                                                          __m256i first[5],
                                                          __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52hi_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52hi_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);
        temp         = _mm256_madd52hi_epu64(zero, first[2], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[2]       = _mm256_add_epi64(temp, res[2]);
        temp         = _mm256_madd52hi_epu64(zero, first[3], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[3]       = _mm256_add_epi64(temp, res[3]);
        temp         = _mm256_madd52hi_epu64(zero, first[4], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[4]       = _mm256_add_epi64(temp, res[4]);
    }

    static inline void FusedMultiplyAddShiftLow256Stage2(__m256i res[4],
                                                         __m256i first[4],
                                                         __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52lo_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52lo_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);

        temp   = _mm256_madd52lo_epu64(zero, first[2], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[2] = _mm256_add_epi64(temp, res[2]);

        temp   = _mm256_madd52lo_epu64(zero, first[3], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[3] = _mm256_add_epi64(temp, res[3]);
    }

    static inline void FusedMultiplyAddShiftHigh256Stage2(__m256i res[4],
                                                          __m256i first[4],
                                                          __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52hi_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52hi_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);
        temp         = _mm256_madd52hi_epu64(zero, first[2], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[2]       = _mm256_add_epi64(temp, res[2]);
        temp         = _mm256_madd52hi_epu64(zero, first[3], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[3]       = _mm256_add_epi64(temp, res[3]);
    }

    static inline void FusedMultiplyAddShiftLow256Stage3(__m256i res[3],
                                                         __m256i first[3],
                                                         __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52lo_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52lo_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);

        temp   = _mm256_madd52lo_epu64(zero, first[2], second);
        temp   = _mm256_slli_epi64(temp, 1);
        res[2] = _mm256_add_epi64(temp, res[2]);
    }

    static inline void FusedMultiplyAddShiftHigh256Stage3(__m256i res[3],
                                                       __m256i first[3],
                                                       __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52hi_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52hi_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);
        temp         = _mm256_madd52hi_epu64(zero, first[2], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[2]       = _mm256_add_epi64(temp, res[2]);
    }

    static inline void FusedMultiplyAddShiftLow256Stage4(__m256i res[2],
                                                         __m256i first[2],
                                                         __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52lo_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52lo_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);
    }

    static inline void FusedMultiplyAddShiftHigh256Stage4(__m256i res[2],
                                                          __m256i first[2],
                                                          __m256i second)
    {
        const __m256i zero{};
        res[0]       = _mm256_madd52hi_epu64(res[0], first[0], second);
        __m256i temp = _mm256_madd52hi_epu64(zero, first[1], second);
        temp         = _mm256_slli_epi64(temp, 1);
        res[1]       = _mm256_add_epi64(temp, res[1]);
    }

    static inline void FusedMultiplyAddShiftLow256Stage5(__m256i& res,
                                                         __m256i  first,
                                                         __m256i  second)
    {
        res = _mm256_madd52lo_epu64(res, first, second);
    }

    static inline void FusedMultiplyAddShiftHigh256Stage5(__m256i& res,
                                                          __m256i  first,
                                                          __m256i  second)
    {
        res = _mm256_madd52hi_epu64(res, first, second);
    }

    static inline void LoadReg256(__m256i out[5], const Uint64* inp)
    {
        out[0] = _mm256_loadu_si256((__m256i*)inp);
        out[1] = _mm256_loadu_si256((__m256i*)(inp + 4));
        out[2] = _mm256_loadu_si256((__m256i*)(inp + 8));
        out[3] = _mm256_loadu_si256((__m256i*)(inp + 12));
        out[4] = _mm256_loadu_si256((__m256i*)(inp + 16));
    }

    static inline void StoreReg256(Uint64* out, __m256i inp[5])
    {
        _mm256_storeu_si256((__m256i*)out, inp[0]);
        _mm256_storeu_si256((__m256i*)(out + 4), inp[1]);
        _mm256_storeu_si256((__m256i*)(out + 8), inp[2]);
        _mm256_storeu_si256((__m256i*)(out + 12), inp[3]);
        _mm256_storeu_si256((__m256i*)(out + 16), inp[4]);
    }

    static inline void LoadReg512(__m512i out[5], const Uint64* inp)
    {
        out[0] = _mm512_loadu_si512(inp);
        out[1] = _mm512_loadu_si512(inp + 8);
        out[2] = _mm512_loadu_si512(inp + 16);
        out[3] = _mm512_loadu_si512(inp + 24);
        out[4] = _mm512_loadu_si512(inp + 32);
    }

    static inline void StoreReg512(Uint64* out, __m512i inp[5])
    {
        _mm512_storeu_si512(out, inp[0]);
        _mm512_storeu_si512(out + 8, inp[1]);
        _mm512_storeu_si512(out + 16, inp[2]);
        _mm512_storeu_si512(out + 24, inp[3]);
        _mm512_storeu_si512(out + 32, inp[4]);
    }

    // FMA-low on a ZMM pair (limbs 0-7 in lo, 8-9 in hi)
    static inline void FmaLo512Pair(__m512i& lo, __m512i& hi,
                                    __m512i  fst_lo, __m512i fst_hi, __m512i s)
    {
        lo = _mm512_madd52lo_epu64(lo, fst_lo, s);
        hi = _mm512_madd52lo_epu64(hi, fst_hi, s);
    }

    // FMA-high on a ZMM pair
    static inline void FmaHi512Pair(__m512i& lo, __m512i& hi,
                                    __m512i  fst_lo, __m512i fst_hi, __m512i s)
    {
        lo = _mm512_madd52hi_epu64(lo, fst_lo, s);
        hi = _mm512_madd52hi_epu64(hi, fst_hi, s);
    }

    // Shift+carry for a ZMM pair (limbs 0-7 in lo, 8-9 in hi).
    // Equivalent to ShiftAndAddCarry512 but for a 2-ZMM pair instead of 5.
    static inline void ShiftAndAddCarry512Pair(__m512i& lo, __m512i& hi)
    {
        const __m512i zero{};
        __m512i       carry = _mm512_maskz_srli_epi64(1, lo, 52);
        lo                  = _mm512_alignr_epi64(hi, lo, 1);
        lo                  = _mm512_add_epi64(lo, carry);
        hi                  = _mm512_alignr_epi64(zero, hi, 1);
    }

    static inline void Amm1024LoopInternalStage1(__m256i       res_reg[5],
                                                 __m256i       first_reg[5],
                                                 const __m256i mod_reg[5],
                                                 const Uint64* first,
                                                 const __m256i k_reg)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage1(res_reg, first_reg, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage1(res_reg, first_reg, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage2(__m256i       res_reg[5],
                                                 __m256i       first_reg[5],
                                                 const __m256i mod_reg[5],
                                                 const Uint64* first,
                                                 const __m256i k_reg)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage3(__m256i       res_reg[5],
                                                 __m256i       first_reg[5],
                                                 const __m256i mod_reg[5],
                                                 const Uint64* first,
                                                 const __m256i k_reg)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage3(
                res_reg + 2, first_reg + 2, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage3(
                res_reg + 2, first_reg + 2, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage4(__m256i       res_reg[5],
                                                 __m256i       first_reg[5],
                                                 const __m256i mod_reg[5],
                                                 const Uint64* first,
                                                 const __m256i k_reg)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternalStage5(__m256i       res_reg[5],
                                                 __m256i       first_reg[5],
                                                 const __m256i mod_reg[5],
                                                 const Uint64* first,
                                                 const __m256i k_reg)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage5(
                res_reg[4], first_reg[4], second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage5(
                res_reg[4], first_reg[4], second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternal(__m256i       res_reg[5],
                                           __m256i       first_reg[5],
                                           const __m256i mod_reg[5],
                                           const Uint64* first,
                                           const __m256i k_reg)
    {
        const __m256i zero{};
        for (Uint64 j = 0; j < 20; j++) {
            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            // x0 = x0 + a0 × bi on lower 52 bits
            FusedMultiplyAddLow256(res_reg, first_reg, second_reg);

            // Broadcast y0
            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            // x0 = x0 + m0 × y0 on lower 52 bits
            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            // Xq,…,X1 = Xq,…,X1 >> 64
            ShiftAndAddCarry256(res_reg);

            // x0 = x0 + a0 × bi on higher 52 bits
            FusedMultiplyAddHigh256(res_reg, first_reg, second_reg);

            // x0 = x0 + m0 × y0 on higher 52 bits
            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    /* Interleaved dual-arm AMM1024 inner loop — arm0 and arm1 instructions
     * are interleaved at each step so that arm1 fills the FP scheduler
     * stalls created by arm0's IFMA dependency chain and vice-versa. */
    static inline void Amm1024LoopInternalParallel(
        __m256i       res_reg0[5],
        __m256i       first_reg0[5],
        const __m256i mod_reg0[5],
        const Uint64* second0,
        const __m256i k_reg0,
        __m256i       res_reg1[5],
        __m256i       first_reg1[5],
        const __m256i mod_reg1[5],
        const Uint64* second1,
        const __m256i k_reg1)
    {
        const __m256i zero{};
        for (Uint64 j = 0; j < 20; j++) {
            __m256i s0 = _mm256_set1_epi64x((long long)second0[j]);
            __m256i s1 = _mm256_set1_epi64x((long long)second1[j]);

            FusedMultiplyAddLow256(res_reg0, first_reg0, s0);
            FusedMultiplyAddLow256(res_reg1, first_reg1, s1);

            __m256i y0 = _mm256_madd52lo_epu64(zero, k_reg0, res_reg0[0]);
            __m256i y1 = _mm256_madd52lo_epu64(zero, k_reg1, res_reg1[0]);
            y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y0));
            y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y1));

            FusedMultiplyAddLow256(res_reg0, mod_reg0, y0);
            FusedMultiplyAddLow256(res_reg1, mod_reg1, y1);

            ShiftAndAddCarry256(res_reg0);
            ShiftAndAddCarry256(res_reg1);

            FusedMultiplyAddHigh256(res_reg0, first_reg0, s0);
            FusedMultiplyAddHigh256(res_reg1, first_reg1, s1);

            FusedMultiplyAddHigh256(res_reg0, mod_reg0, y0);
            FusedMultiplyAddHigh256(res_reg1, mod_reg1, y1);
        }
    }

    static inline void Amm2048LoopInternal(__m512i       res_reg[5],
                                           __m512i       first_reg[5],
                                           const __m512i mod_reg[5],
                                           const Uint64* first,
                                           const __m512i k_reg)
    {
        const __m512i zero{};
        for (Uint64 j = 0; j < 40; j++) {
            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddLow512(res_reg, first_reg, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddHigh512(res_reg, first_reg, second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }

    static inline void AMM1024(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const __m256i mod_reg[5],
                               const __m256i k_reg)
    {
        __m256i first_reg[5];

        __m256i res_reg[5]{};

        LoadReg256(first_reg, first);

        Amm1024LoopInternal(res_reg, first_reg, mod_reg, second, k_reg);

        StoreReg256(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024Parallel(Uint64*       res[2],
                                       Uint64*       first[2],
                                       Uint64*       second[2],
                                       const __m256i mod_reg[10],
                                       Uint64        k0[2])
    {
        const __m256i k_reg0 = _mm256_set1_epi64x((long long)k0[0]);
        const __m256i k_reg1 = _mm256_set1_epi64x((long long)k0[1]);

        __m256i first_reg0[5], first_reg1[5];
        __m256i res_reg0[5]{}, res_reg1[5]{};

        LoadReg256(first_reg0, first[0]);
        LoadReg256(first_reg1, first[1]);

        Amm1024LoopInternalParallel(
            res_reg0, first_reg0, mod_reg,     second[0], k_reg0,
            res_reg1, first_reg1, mod_reg + 5, second[1], k_reg1);

        StoreReg256(res[0], res_reg0);
        StoreReg256(res[1], res_reg1);

        Uint64 carry0 = 0, carry1 = 0;
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 s0 = res[0][i] + carry0; carry0 = s0 >> 52; res[0][i] = s0 & 0xfffffffffffff;
            Uint64 s1 = res[1][i] + carry1; carry1 = s1 >> 52; res[1][i] = s1 & 0xfffffffffffff;
        }
    }

    static inline void AMS1024(Uint64*       res,
                               const Uint64* first,
                               const __m256i mod_reg[5],
                               const __m256i k_reg)
    {

        __m256i first_reg[5];

        __m256i res_reg[5]{};
        LoadReg256(first_reg, first);

        // each stage will multiply 4 set of registers from first to all
        // other with the first pointer
        Amm1024LoopInternalStage1(res_reg, first_reg, mod_reg, first, k_reg);

        Amm1024LoopInternalStage2(
            res_reg, first_reg, mod_reg, first + 4, k_reg);

        Amm1024LoopInternalStage3(
            res_reg, first_reg, mod_reg, first + 8, k_reg);

        Amm1024LoopInternalStage4(
            res_reg, first_reg, mod_reg, first + 12, k_reg);

        Amm1024LoopInternalStage5(
            res_reg, first_reg, mod_reg, first + 16, k_reg);

        StoreReg256(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMS1024Parallel(Uint64*       res[2],
                                       Uint64*       first[2],
                                       const __m256i mod_reg[10],
                                       Uint64        k0[2])
    {
        const __m256i zero{};
        const __m256i k_reg0 = _mm256_set1_epi64x((long long)k0[0]);
        const __m256i k_reg1 = _mm256_set1_epi64x((long long)k0[1]);
        const __m256i* mod0 = mod_reg;
        const __m256i* mod1 = mod_reg + 5;

        __m256i f0[5], f1[5];
        __m256i r0[5]{}, r1[5]{};

        LoadReg256(f0, first[0]);
        LoadReg256(f1, first[1]);

        for (Uint64 j = 0; j < 4; j++) {
            __m256i d0 = _mm256_set1_epi64x((long long)first[0][j]);
            __m256i d1 = _mm256_set1_epi64x((long long)first[1][j]);
            FusedMultiplyAddShiftLow256Stage1(r0, f0, d0);
            FusedMultiplyAddShiftLow256Stage1(r1, f1, d1);
            __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg0, r0[0])));
            __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg1, r1[0])));
            FusedMultiplyAddLow256(r0, mod0, y0);
            FusedMultiplyAddLow256(r1, mod1, y1);
            ShiftAndAddCarry256(r0);
            ShiftAndAddCarry256(r1);
            FusedMultiplyAddShiftHigh256Stage1(r0, f0, d0);
            FusedMultiplyAddShiftHigh256Stage1(r1, f1, d1);
            FusedMultiplyAddHigh256(r0, mod0, y0);
            FusedMultiplyAddHigh256(r1, mod1, y1);
        }

        for (Uint64 j = 0; j < 4; j++) {
            __m256i d0 = _mm256_set1_epi64x((long long)first[0][4 + j]);
            __m256i d1 = _mm256_set1_epi64x((long long)first[1][4 + j]);
            FusedMultiplyAddShiftLow256Stage2(r0 + 1, f0 + 1, d0);
            FusedMultiplyAddShiftLow256Stage2(r1 + 1, f1 + 1, d1);
            __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg0, r0[0])));
            __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg1, r1[0])));
            FusedMultiplyAddLow256(r0, mod0, y0);
            FusedMultiplyAddLow256(r1, mod1, y1);
            ShiftAndAddCarry256(r0);
            ShiftAndAddCarry256(r1);
            FusedMultiplyAddShiftHigh256Stage2(r0 + 1, f0 + 1, d0);
            FusedMultiplyAddShiftHigh256Stage2(r1 + 1, f1 + 1, d1);
            FusedMultiplyAddHigh256(r0, mod0, y0);
            FusedMultiplyAddHigh256(r1, mod1, y1);
        }

        for (Uint64 j = 0; j < 4; j++) {
            __m256i d0 = _mm256_set1_epi64x((long long)first[0][8 + j]);
            __m256i d1 = _mm256_set1_epi64x((long long)first[1][8 + j]);
            FusedMultiplyAddShiftLow256Stage3(r0 + 2, f0 + 2, d0);
            FusedMultiplyAddShiftLow256Stage3(r1 + 2, f1 + 2, d1);
            __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg0, r0[0])));
            __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg1, r1[0])));
            FusedMultiplyAddLow256(r0, mod0, y0);
            FusedMultiplyAddLow256(r1, mod1, y1);
            ShiftAndAddCarry256(r0);
            ShiftAndAddCarry256(r1);
            FusedMultiplyAddShiftHigh256Stage3(r0 + 2, f0 + 2, d0);
            FusedMultiplyAddShiftHigh256Stage3(r1 + 2, f1 + 2, d1);
            FusedMultiplyAddHigh256(r0, mod0, y0);
            FusedMultiplyAddHigh256(r1, mod1, y1);
        }

        for (Uint64 j = 0; j < 4; j++) {
            __m256i d0 = _mm256_set1_epi64x((long long)first[0][12 + j]);
            __m256i d1 = _mm256_set1_epi64x((long long)first[1][12 + j]);
            FusedMultiplyAddShiftLow256Stage4(r0 + 3, f0 + 3, d0);
            FusedMultiplyAddShiftLow256Stage4(r1 + 3, f1 + 3, d1);
            __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg0, r0[0])));
            __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg1, r1[0])));
            FusedMultiplyAddLow256(r0, mod0, y0);
            FusedMultiplyAddLow256(r1, mod1, y1);
            ShiftAndAddCarry256(r0);
            ShiftAndAddCarry256(r1);
            FusedMultiplyAddShiftHigh256Stage4(r0 + 3, f0 + 3, d0);
            FusedMultiplyAddShiftHigh256Stage4(r1 + 3, f1 + 3, d1);
            FusedMultiplyAddHigh256(r0, mod0, y0);
            FusedMultiplyAddHigh256(r1, mod1, y1);
        }

        for (Uint64 j = 0; j < 4; j++) {
            __m256i d0 = _mm256_set1_epi64x((long long)first[0][16 + j]);
            __m256i d1 = _mm256_set1_epi64x((long long)first[1][16 + j]);
            FusedMultiplyAddShiftLow256Stage5(r0[4], f0[4], d0);
            FusedMultiplyAddShiftLow256Stage5(r1[4], f1[4], d1);
            __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg0, r0[0])));
            __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(zero, k_reg1, r1[0])));
            FusedMultiplyAddLow256(r0, mod0, y0);
            FusedMultiplyAddLow256(r1, mod1, y1);
            ShiftAndAddCarry256(r0);
            ShiftAndAddCarry256(r1);
            FusedMultiplyAddShiftHigh256Stage5(r0[4], f0[4], d0);
            FusedMultiplyAddShiftHigh256Stage5(r1[4], f1[4], d1);
            FusedMultiplyAddHigh256(r0, mod0, y0);
            FusedMultiplyAddHigh256(r1, mod1, y1);
        }

        StoreReg256(res[0], r0);
        StoreReg256(res[1], r1);

        Uint64 carry0 = 0, carry1 = 0;
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 s0 = res[0][i] + carry0; carry0 = s0 >> 52; res[0][i] = s0 & 0xfffffffffffff;
            Uint64 s1 = res[1][i] + carry1; carry1 = s1 >> 52; res[1][i] = s1 & 0xfffffffffffff;
        }
    }

    static inline void AMM2048(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const __m512i mod_reg[5],
                               const __m512i k_reg)
    {
        __m512i first_reg[5];

        __m512i res_reg[5]{};

        LoadReg512(first_reg, first);

        Amm2048LoopInternal(res_reg, first_reg, mod_reg, second, k_reg);

        StoreReg512(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void Amm2048LoopInternalStage1(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 const __m512i mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {

        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddShiftLow512Stage1(res_reg, first_reg, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddShiftHigh512Stage1(res_reg, first_reg, second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm2048LoopInternalStage2(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 const __m512i mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddShiftLow512Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddShiftHigh512Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }
    static inline void Amm2048LoopInternalStage3(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 const __m512i mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddShiftLow512Stage3(
                res_reg + 2, first_reg + 2, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddShiftHigh512Stage3(
                res_reg + 2, first_reg + 2, second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }
    static inline void Amm2048LoopInternalStage4(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 const __m512i mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddShiftLow512Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddShiftHigh512Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm2048LoopInternalStage5(__m512i       res_reg[5],
                                                 __m512i       first_reg[5],
                                                 const __m512i mod_reg[5],
                                                 const Uint64* first,
                                                 __m512i       k_reg)
    {
        const __m512i zero{};

        for (Uint64 j = 0; j < 8; j++) {

            __m512i second_reg = _mm512_set1_epi64(first[j]);

            FusedMultiplyAddShiftLow512Stage5(
                res_reg[4], first_reg[4], second_reg);

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddShiftHigh512Stage5(
                res_reg[4], first_reg[4], second_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
    }

    static inline void AMS2048(Uint64*       res,
                               const Uint64* first,
                               const __m512i mod_reg[5],
                               const __m512i k_reg)
    {
        __m512i first_reg[5];

        __m512i res_reg[5]{};

        LoadReg512(first_reg, first);

        Amm2048LoopInternalStage1(res_reg, first_reg, mod_reg, first, k_reg);
        Amm2048LoopInternalStage2(
            res_reg, first_reg, mod_reg, first + 8, k_reg);
        Amm2048LoopInternalStage3(
            res_reg, first_reg, mod_reg, first + 16, k_reg);
        Amm2048LoopInternalStage4(
            res_reg, first_reg, mod_reg, first + 24, k_reg);
        Amm2048LoopInternalStage5(
            res_reg, first_reg, mod_reg, first + 32, k_reg);

        StoreReg512(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM2048Reduce(Uint64*       res,
                                     const Uint64* first,
                                     const __m512i mod_reg[5],
                                     const __m512i k_reg)
    {

        __m512i res_reg[5];

        LoadReg512(res_reg, first);

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {

            __m512i y_reg = _mm512_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y_reg));

            FusedMultiplyAddLow512(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry512(res_reg);

            FusedMultiplyAddHigh512(res_reg, mod_reg, y_reg);
        }
        StoreReg512(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024Reduce(Uint64*       res,
                                     const Uint64* first,
                                     const __m256i mod_reg[5],
                                     const __m256i k_reg)
    {
        __m256i res_reg[5];

        LoadReg256(res_reg, first);

        const __m256i zero{};

        for (Uint64 i = 0; i < 20; i++) {

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
        StoreReg256(res, res_reg);

        Uint64 carry = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM1024ReduceParallel(Uint64*       res[2],
                                             Uint64*       first[2],
                                             const __m256i mod_reg[10],
                                             Uint64        k0[2])
    {
        __m256i res_reg[10];

        Uint64* first_0 = first[0];
        Uint64* first_1 = first[1];
        Uint64* res_0   = res[0];
        Uint64* res_1   = res[1];

        LoadReg256(res_reg, first_0);
        LoadReg256(res_reg + 5, first_1);

        __m256i       k_reg_0 = _mm256_set1_epi64x(k0[0]);
        __m256i       k_reg_1 = _mm256_set1_epi64x(k0[1]);
        const __m256i zero{};

        for (Uint64 i = 0; i < 20; i++) {

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second reduction
            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_broadcastq_epi64(_mm256_castsi256_si128(y_reg));

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
        StoreReg256(res_0, res_reg);
        StoreReg256(res_1, res_reg + 5);

        Uint64 carry = 0, carry1 = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res_0[i] + carry;
            carry      = sum >> 52;
            res_0[i]   = sum & 0xfffffffffffff;

            sum      = res_1[i] + carry1;
            carry1   = sum >> 52;
            res_1[i] = sum & 0xfffffffffffff;
        }
    }

    static inline void AMMAndAMS1024(Uint64*       res,
                                     Uint64*       mult,
                                     const __m256i mod_reg[5],
                                     const __m256i k_reg,
                                     Uint64        val)
    {
        AMS1024(res, res, mod_reg, k_reg);
        if (val & mont::one_msb) {
            AMM1024(res, res, mult, mod_reg, k_reg);
        }
    }

    static inline void AMMAndAMS2048(Uint64*       res,
                                     Uint64*       mult,
                                     const __m512i mod_reg[5],
                                     const __m512i k_reg,
                                     Uint64        val)
    {
        AMS2048(res, res, mod_reg, k_reg);
        if (val & mont::one_msb) {
            AMM2048(res, res, mult, mod_reg, k_reg);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::CreateContext(
        MontContextBignum& context, Uint64* mod, Uint64 size)
    {

        context.m_size = size;
        context.m_k0   = computeMontFactor(mod[0]);

        BigNum inp{ mod, size, size - 1 }, res{ context.m_r2, size, size - 1 };

        computeZen4MontConverter(res, inp);

        if (size == 32) {
            Rsa2048Radix64BitToRadix52Bit(context.m_mod_radix_52_bit, mod);
            Rsa2048Radix64BitToRadix52Bit(context.m_r2_radix_52_bit,
                                          context.m_r2);

            __m512i mod_reg[5];

            LoadReg512(mod_reg, context.m_mod_radix_52_bit);

            __m512i k_reg = _mm512_set1_epi64(context.m_k0);
            //(congruent to 2^(4n-k×m) mod (n is number of bit, k is digits for
            // holding radix 52 number ,m is 52)
            // M)
            AMM2048(context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    mod_reg,
                    k_reg);
            // 2^(4km - 4n) in radix 52
            alignas(64) const Uint64 mult[40] = { 0x00, 0x00, 0x1000000 };

            //(congruent to 2^2k×m mod M)
            AMM2048(context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    mult,
                    mod_reg,
                    k_reg);
        } else {
            Rsa1024Radix64BitToRadix52Bit(context.m_mod_radix_52_bit, mod);
            Rsa1024Radix64BitToRadix52Bit(context.m_r2_radix_52_bit,
                                          context.m_r2);

            __m256i mod_reg[5];

            LoadReg256(mod_reg, context.m_mod_radix_52_bit);

            __m256i k_reg = _mm256_set1_epi64x(context.m_k0);
            //(congruent to 2^(4n-k×m) mod
            // M)
            AMM1024(context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    mod_reg,
                    k_reg);
            // 2^(4km - 4n) in radix 52
            alignas(64) const Uint64 mult[20] = { 0x00, 0x1000 };

            //(congruent to 2^2k×m mod M)
            AMM1024(context.m_r2_radix_52_bit,
                    context.m_r2_radix_52_bit,
                    mult,
                    mod_reg,
                    k_reg);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::CreateContext(
        MontContextBignum& context, Uint64* mod, Uint64 size)
    {
        Uint64* r1               = context.m_r1;
        Uint64* r2               = context.m_r2;
        Uint64* r3               = context.m_r3;
        Uint64* r2_radix_52_bit  = context.m_r2_radix_52_bit;
        Uint64* mod_radix_52_bit = context.m_mod_radix_52_bit;

        context.m_size = size;
        context.m_k0   = computeMontFactor(mod[0]);

        BigNum inp{ mod, size, size - 1 }, res{ r2, size, size - 1 };

        computeMontConverter(res, inp);

        MontMultHalf(r3, r2, r2, mod, context.m_k0);

        auto param     = std::make_unique<Uint64[]>(size * 2);
        auto param_ptr = param.get();
        alcp::utils::CopyChunk(param_ptr, r2, size * 8);

        MontReduce(r1, param_ptr, mod, context.m_k0, size * 2);

        if (size <= 8) {
            /* size=8 means 512-bit CRT arm. Compute 512-bit radix-52 representations
             * for use by the parallel RSA-1024 CRT path (AMM512 with n=10, R_AMM=2^520).
             * r2 = R_standard^2 = 2^1024 mod M. We need r2_AMM = R_AMM^2 = 2^1040 mod M.
             * r2_AMM = r2 * 2^16 mod M (computed by 16 doublings with mod reduction). */
            Rsa512Radix64BitToRadix52Bit(mod_radix_52_bit, mod);

            Uint64 r2_ams[8];
            alcp::utils::CopyChunk(r2_ams, r2, 8 * 8);

            for (int shift = 0; shift < 16; shift++) {
                /* Double r2_ams with 64-bit carry */
                Uint64 carry = 0;
                for (int j = 0; j < 8; j++) {
                    __uint128_t v = (__uint128_t)r2_ams[j] * 2 + carry;
                    r2_ams[j]    = (Uint64)v;
                    carry        = (Uint64)(v >> 64);
                }
                /* Constant-time conditional subtraction: t = r2_ams - mod.
                 * The 128-bit borrow avoids the (mod[j] + borrow) overflow that
                 * previously broke the chain when a limb was 0xffffffffffffffff.
                 * Keep t iff the doubling overflowed (carry) or r2_ams >= mod
                 * (no underflow). Both operands are key material, so select
                 * the result without branching on it. */
                Uint64 t[8];
                Uint64 borrow = 0;
                for (int j = 0; j < 8; j++) {
                    __uint128_t d = (__uint128_t)r2_ams[j] - mod[j] - borrow;
                    t[j]          = (Uint64)d;
                    borrow        = (Uint64)(d >> 64) & 1;
                }
                Uint64 mask = (Uint64)0 - (carry | (borrow ^ 1));
                for (int j = 0; j < 8; j++) {
                    r2_ams[j] = (mask & t[j]) | (~mask & r2_ams[j]);
                }
                SecureClear(t, sizeof(t));
            }
            Rsa512Radix64BitToRadix52Bit(r2_radix_52_bit, r2_ams);
            SecureClear(r2_ams, sizeof(r2_ams));
            return;
        }
        Rsa1024Radix64BitToRadix52Bit(mod_radix_52_bit, mod);
        Rsa1024Radix64BitToRadix52Bit(r2_radix_52_bit, r2);
        __m256i mod_reg[5];
        LoadReg256(mod_reg, mod_radix_52_bit);

        __m256i k_reg = _mm256_set1_epi64x(context.m_k0);

        //(congruent to 2^(4n-k×m) mod M)
        AMM1024(
            r2_radix_52_bit, r2_radix_52_bit, r2_radix_52_bit, mod_reg, k_reg);
        // 2^(4n-km) in radix 52
        alignas(64) const Uint64 mult[20] = { 0x00, 0x1000 };

        //(congruent to 2^2k×m mod M)
        AMM1024(r2_radix_52_bit, r2_radix_52_bit, mult, mod_reg, k_reg);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        const Uint64* exp,
        Uint64        expSize,
        Uint64*       mod_radix_52_bit,
        Uint64*       r2_radix_52_bit,
        Uint64        k0)
    {

        alignas(64) Uint64 input_radix_52_bit[40];
        alignas(64) Uint64 res_radix_52_bit[40];
        Rsa2048Radix64BitToRadix52Bit(input_radix_52_bit, input);

        __m512i mod_reg[5];
        LoadReg512(mod_reg, mod_radix_52_bit);

        __m512i k_reg = _mm512_set1_epi64(k0);

        // conversion to mont domain by
        // multiplying with mont converter
        AMM2048(input_radix_52_bit,
                input_radix_52_bit,
                r2_radix_52_bit,
                mod_reg,
                k_reg);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        alcp::utils::CopyChunk(res_radix_52_bit, input_radix_52_bit, 40 * 8);

        while (index++ < 64) {
            AMMAndAMS2048(
                res_radix_52_bit, input_radix_52_bit, mod_reg, k_reg, val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                AMMAndAMS2048(
                    res_radix_52_bit, input_radix_52_bit, mod_reg, k_reg, val);
                val <<= 1;
            }
        }

        AMM2048Reduce(input_radix_52_bit, res_radix_52_bit, mod_reg, k_reg);

        Rsa2048Radix52BitToRadix64(res, input_radix_52_bit);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        const Uint64* exp,
        Uint64        expSize,
        Uint64*       mod_radix_52_bit,
        Uint64*       r2_radix_52_bit,
        Uint64        k0)
    {

        alignas(64) Uint64 input_radix_52_bit[20]{};
        alignas(64) Uint64 res_radix_52_bit[20]{};
        Rsa1024Radix64BitToRadix52Bit(input_radix_52_bit, input);

        __m256i mod_reg[5];
        LoadReg256(mod_reg, mod_radix_52_bit);

        __m256i k_reg = _mm256_set1_epi64x(k0);

        // conversion to mont domain by
        // multiplying with mont converter
        AMM1024(input_radix_52_bit,
                input_radix_52_bit,
                r2_radix_52_bit,
                mod_reg,
                k_reg);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        alcp::utils::CopyChunk(res_radix_52_bit, input_radix_52_bit, 20 * 8);

        while (index++ < 64) {
            AMMAndAMS1024(
                res_radix_52_bit, input_radix_52_bit, mod_reg, k_reg, val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                AMMAndAMS1024(
                    res_radix_52_bit, input_radix_52_bit, mod_reg, k_reg, val);
                val <<= 1;
            }
        }

        AMM1024Reduce(input_radix_52_bit, res_radix_52_bit, mod_reg, k_reg);

        Rsa1024Radix52BitToRadix64(res, input_radix_52_bit);
    }

    template<>
    void archEncryptPublic<KEY_SIZE_1024>(Uint8*              pEncText,
                                          const Uint64*       pTextBignum,
                                          RsaPublicKeyBignum& pubKey,
                                          MontContextBignum&  context)
    {
        auto mod = context.m_mod_radix_52_bit;
        auto r2  = context.m_r2_radix_52_bit;
        auto k0  = context.m_k0;
        auto exp = pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[1024 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = KEY_SIZE_1024 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    template<>
    void archEncryptPublic<KEY_SIZE_2048>(Uint8*              pEncText,
                                          const Uint64*       pTextBignum,
                                          RsaPublicKeyBignum& pubKey,
                                          MontContextBignum&  context)
    {
        auto mod = context.m_mod_radix_52_bit;
        auto r2  = context.m_r2_radix_52_bit;
        auto k0  = context.m_k0;
        auto exp = pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[2048 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = KEY_SIZE_2048 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    /**
     * 512-bit parallel helpers for RSA-1024 CRT acceleration.
     * Each arm is a 512-bit modulus (n=10 limbs of 52-bit).
     * mod_reg512 layout: 6 x __m256i (3 per arm, 4 limbs each, last has 2 valid).
     */
    static inline void LoadReg256_512(__m256i out[3], const Uint64* inp)
    {
        out[0] = _mm256_loadu_si256((__m256i*)inp);
        out[1] = _mm256_loadu_si256((__m256i*)(inp + 4));
        out[2] = _mm256_inserti128_si256(_mm256_setzero_si256(),
                                         _mm_loadu_si128((__m128i*)(inp + 8)),
                                         0);
    }

    // Store 10 limbs from 3 YMM (4+4+2 layout) back to memory.
    static inline void StoreReg256_512(Uint64* dst, const __m256i r[3])
    {
        _mm256_storeu_si256((__m256i*)dst,       r[0]);
        _mm256_storeu_si256((__m256i*)(dst + 4), r[1]);
        _mm_storeu_si128((__m128i*)(dst + 8), _mm256_castsi256_si128(r[2]));
    }

    // Load 10 limbs into a ZMM pair (lo=limbs 0-7, hi=limbs 8-9 in low 2 lanes).
    static inline void LoadZmmPair10(const Uint64* src, __m512i& lo, __m512i& hi)
    {
        lo = _mm512_inserti64x4(
            _mm512_castsi256_si512(_mm256_loadu_si256((__m256i*)src)),
            _mm256_loadu_si256((__m256i*)(src + 4)), 1);
        hi = _mm512_inserti64x2(_mm512_setzero_si512(),
                                _mm_loadu_si128((__m128i*)(src + 8)), 0);
    }

    // Store a ZMM pair back to 10-limb memory.
    static inline void StoreZmmPair10(Uint64* dst, __m512i lo, __m512i hi)
    {
        _mm256_storeu_si256((__m256i*)dst,
                            _mm512_castsi512_si256(lo));
        _mm256_storeu_si256((__m256i*)(dst + 4),
                            _mm512_extracti64x4_epi64(lo, 1));
        _mm_storeu_si128((__m128i*)(dst + 8),
                         _mm512_castsi512_si128(hi));
    }

    // Load 10 limbs stored as 3 YMM (mod_reg layout) into a ZMM pair.
    static inline void LoadZmmPairFromYmm3(__m512i& lo, __m512i& hi,
                                           const __m256i ymm[3])
    {
        lo = _mm512_inserti64x4(_mm512_castsi256_si512(ymm[0]), ymm[1], 1);
        hi = _mm512_inserti64x4(_mm512_setzero_si512(), ymm[2], 0);
    }

    // Constant-time: scans all 32 entries to avoid cache-timing leaks.
    static __attribute__((noinline)) void GetFromTableParallel512(
        Uint64* t, Uint64 index1, Uint64 index2, Uint64* num1, Uint64* num2)
    {
        Uint64*       t2   = t + 32 * 10;
        const __m512i seq  = _mm512_setr_epi64(0, 1, 2, 3, 4, 5, 6, 7);
        const __m512i tgt1 = _mm512_set1_epi64(static_cast<long long>(index1));
        const __m512i tgt2 = _mm512_set1_epi64(static_cast<long long>(index2));
        const __m512i perm1 =
            _mm512_set1_epi64(static_cast<long long>(index1 & 7));
        const __m512i perm2 =
            _mm512_set1_epi64(static_cast<long long>(index2 & 7));

        __mmask8 m1[4], m2[4];
        for (Uint64 j = 0; j < 32; j += 8) {
            __m512i cur = _mm512_add_epi64(
                seq, _mm512_set1_epi64(static_cast<long long>(j)));
            m1[j / 8] = _mm512_cmpeq_epi64_mask(cur, tgt1);
            m2[j / 8] = _mm512_cmpeq_epi64_mask(cur, tgt2);
        }

        for (Uint64 i = 0; i < 10; i++) {
            __m512i acc1 = _mm512_maskz_mov_epi64(m1[0], _mm512_loadu_si512(t));
            __m512i acc2 = _mm512_maskz_mov_epi64(m2[0], _mm512_loadu_si512(t2));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[1], acc1, _mm512_loadu_si512(t + 8));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[1], acc2, _mm512_loadu_si512(t2 + 8));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[2], acc1, _mm512_loadu_si512(t + 16));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[2], acc2, _mm512_loadu_si512(t2 + 16));
            acc1 = _mm512_mask_or_epi64(
                acc1, m1[3], acc1, _mm512_loadu_si512(t + 24));
            acc2 = _mm512_mask_or_epi64(
                acc2, m2[3], acc2, _mm512_loadu_si512(t2 + 24));
            num1[i] = _mm_cvtsi128_si64(_mm512_castsi512_si128(
                _mm512_permutexvar_epi64(perm1, acc1)));
            num2[i] = _mm_cvtsi128_si64(_mm512_castsi512_si128(
                _mm512_permutexvar_epi64(perm2, acc2)));
            t += 32;
            t2 += 32;
        }
    }

    static inline void PutInTableParallel512(Uint64* t,
                                             Uint64  index,
                                             Uint64* num1,
                                             Uint64* num2)
    {
        Uint64* t2 = t + 32 * 10;
        for (Uint64 i = 0; i < 10; i++) {
            t[index]  = num1[i];
            t2[index] = num2[i];
            index += 32;
        }
    }

    /**
     * AMS512Parallel: Almost Montgomery Squaring for 512-bit (n=10 limbs),
     * dual CRT arms in parallel using 3 YMM per arm.
     *
     * Layout: mod_reg[0..2] = arm0 mod, mod_reg[3..5] = arm1 mod.
     * Each arm: ymm[0]=limbs0-3, ymm[1]=limbs4-7, ymm[2]=limbs8-9(lo2).
     *
     * Algorithm: 3-stage squaring (CIOS-like with doubled cross terms).
     *   Stage 1: outer digits 0..3  (diagonal on ymm0, cross on ymm1,ymm2)
     *   Stage 2: outer digits 4..7  (diagonal on ymm1, cross on ymm2)
     *   Stage 3: outer digits 8..9  (diagonal on ymm2, no cross)
     */
    static inline void AMS512Parallel(Uint64*       res[2],
                                      Uint64*       first[2],
                                      const __m256i mod_reg[6],
                                      Uint64        k0[2])
    {
        /* Load both arms (10 limbs in 4+4+2 layout; upper lanes of reg[2]
         * are zeroed by LoadReg256_512). */
        __m256i f0[3], f1[3];
        LoadReg256_512(f0, first[0]);
        LoadReg256_512(f1, first[1]);

        const __m256i k_reg0 = _mm256_set1_epi64x((long long)k0[0]);
        const __m256i k_reg1 = _mm256_set1_epi64x((long long)k0[1]);
        __m256i       r0[3]{}, r1[3]{};

        /* Parallel-y precomputation for Stage 1:
         * In Stage 1, the diagonal IFMA updates r0[0] before y is needed.
         * Break this dependency: y = k0*(r0[0]_old + diag) = y_base + y_adj
         *   y_base = k0 * r0[0]_old   (reads r0[0] from PREV iteration shift)
         *   y_adj  = k0 * first[0][0] * d0  = c_adj * d0  (c_adj precomputed)
         * This lets y_base start concurrently with the diagonal IFMA (T=0 vs. T=4).
         * Stage 2 and Stage 3 do NOT update r0[0] in their diagonal, so they
         * already have no r0[0]→y dependency; no parallel-y needed there. */
        const __m256i c0_adj = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
            _mm256_madd52lo_epu64(__m256i{},
                _mm256_set1_epi64x((long long)first[0][0]), k_reg0)));
        const __m256i c1_adj = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
            _mm256_madd52lo_epu64(__m256i{},
                _mm256_set1_epi64x((long long)first[1][0]), k_reg1)));

        /* Stage 1: outer digits 0..3 — diagonal: f[0], cross: f[1], f[2] */
        for (Uint64 j = 0; j < 4; j++) {
            const __m256i d0 = _mm256_set1_epi64x((long long)first[0][j]);
            const __m256i d1 = _mm256_set1_epi64x((long long)first[1][j]);

            /* y_base reads OLD r0[0] concurrently with diagonal (no WAR hazard) */
            const __m256i y0_base = _mm256_madd52lo_epu64(__m256i{}, k_reg0, r0[0]);
            const __m256i y1_base = _mm256_madd52lo_epu64(__m256i{}, k_reg1, r1[0]);
            r0[0] = _mm256_madd52lo_epu64(r0[0], f0[0], d0);  /* diagonal lo */
            r1[0] = _mm256_madd52lo_epu64(r1[0], f1[0], d1);
            AddCrossTermLo256(r0[1], f0[1], d0);               /* cross k=1 lo */
            const __m256i y0_adj = _mm256_madd52lo_epu64(__m256i{}, c0_adj, d0);
            AddCrossTermLo256(r1[1], f1[1], d1);
            const __m256i y1_adj = _mm256_madd52lo_epu64(__m256i{}, c1_adj, d1);
            AddCrossTermLo256(r0[2], f0[2], d0);               /* cross k=2 lo */
            AddCrossTermLo256(r1[2], f1[2], d1);
            /* Combine and broadcast: y = y_base + y_adj */
            const __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_add_epi64(y0_base, y0_adj)));
            const __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_add_epi64(y1_base, y1_adj)));
            FusedMultiplyAddLow256_3(r0, mod_reg,     y0);
            FusedMultiplyAddLow256_3(r1, mod_reg + 3, y1);
            ShiftAndAddCarry256_3(r0);
            ShiftAndAddCarry256_3(r1);
            r0[0] = _mm256_madd52hi_epu64(r0[0], f0[0], d0);  /* diagonal hi */
            r1[0] = _mm256_madd52hi_epu64(r1[0], f1[0], d1);
            AddCrossTermHi256(r0[1], f0[1], d0);
            AddCrossTermHi256(r1[1], f1[1], d1);
            AddCrossTermHi256(r0[2], f0[2], d0);
            AddCrossTermHi256(r1[2], f1[2], d1);
            FusedMultiplyAddHigh256_3(r0, mod_reg,     y0);
            FusedMultiplyAddHigh256_3(r1, mod_reg + 3, y1);
        }

        /* Stage 2: outer digits 4..7 — diagonal: f[1], cross: f[2] */
        for (Uint64 j = 0; j < 4; j++) {
            const __m256i d0 = _mm256_set1_epi64x((long long)first[0][4 + j]);
            const __m256i d1 = _mm256_set1_epi64x((long long)first[1][4 + j]);

            r0[1] = _mm256_madd52lo_epu64(r0[1], f0[1], d0);
            r1[1] = _mm256_madd52lo_epu64(r1[1], f1[1], d1);
            AddCrossTermLo256(r0[2], f0[2], d0);
            const __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(__m256i{}, k_reg0, r0[0])));
            AddCrossTermLo256(r1[2], f1[2], d1);
            const __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(__m256i{}, k_reg1, r1[0])));
            FusedMultiplyAddLow256_3(r0, mod_reg,     y0);
            FusedMultiplyAddLow256_3(r1, mod_reg + 3, y1);
            ShiftAndAddCarry256_3(r0);
            ShiftAndAddCarry256_3(r1);
            r0[1] = _mm256_madd52hi_epu64(r0[1], f0[1], d0);
            r1[1] = _mm256_madd52hi_epu64(r1[1], f1[1], d1);
            AddCrossTermHi256(r0[2], f0[2], d0);
            AddCrossTermHi256(r1[2], f1[2], d1);
            FusedMultiplyAddHigh256_3(r0, mod_reg,     y0);
            FusedMultiplyAddHigh256_3(r1, mod_reg + 3, y1);
        }

        /* Stage 3: outer digits 8..9 — diagonal: f[2], no cross terms */
        for (Uint64 j = 0; j < 2; j++) {
            const __m256i d0 = _mm256_set1_epi64x((long long)first[0][8 + j]);
            const __m256i d1 = _mm256_set1_epi64x((long long)first[1][8 + j]);

            r0[2] = _mm256_madd52lo_epu64(r0[2], f0[2], d0);
            r1[2] = _mm256_madd52lo_epu64(r1[2], f1[2], d1);
            const __m256i y0 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(__m256i{}, k_reg0, r0[0])));
            const __m256i y1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(
                _mm256_madd52lo_epu64(__m256i{}, k_reg1, r1[0])));
            FusedMultiplyAddLow256_3(r0, mod_reg,     y0);
            FusedMultiplyAddLow256_3(r1, mod_reg + 3, y1);
            ShiftAndAddCarry256_3(r0);
            ShiftAndAddCarry256_3(r1);
            r0[2] = _mm256_madd52hi_epu64(r0[2], f0[2], d0);
            r1[2] = _mm256_madd52hi_epu64(r1[2], f1[2], d1);
            FusedMultiplyAddHigh256_3(r0, mod_reg,     y0);
            FusedMultiplyAddHigh256_3(r1, mod_reg + 3, y1);
        }

        StoreReg256_512(res[0], r0);
        StoreReg256_512(res[1], r1);

        Uint64 carry0 = 0, carry1 = 0;
        for (Uint64 i = 0; i < 10; i++) {
            Uint64 s0 = res[0][i] + carry0; carry0 = s0 >> 52; res[0][i] = s0 & 0xfffffffffffff;
            Uint64 s1 = res[1][i] + carry1; carry1 = s1 >> 52; res[1][i] = s1 & 0xfffffffffffff;
        }
    }

    /**
     * AMM512Parallel: Almost Montgomery Multiplication for 512-bit (n=10),
     * dual CRT arms in parallel.
     *
     * Uses ZMM registers: zmm0=arm0 limbs0-7, zmm1=arm0 limbs8-9(lo2),
     *                     zmm2=arm1 limbs0-7, zmm3=arm1 limbs8-9(lo2).
     * Parallel-y optimization: y = y_base + y_adj where
     *   y_base = old_res[0]*k0,  y_adj = C*second[i],  C = first[0]*k0
     * This eliminates a dependency chain by separating y into two
     * independent halves computed in parallel with the input FMAs.
     */
    static inline void AMM512Parallel(Uint64*       res[2],
                                      Uint64*       first[2],
                                      Uint64*       second[2],
                                      const __m256i mod_reg[6],
                                      Uint64        k0[2])
    {
        /* Load mod and first operands into ZMM pairs */
        __m512i mod0, mod0h, mod1, mod1h;
        LoadZmmPairFromYmm3(mod0, mod0h, mod_reg);
        LoadZmmPairFromYmm3(mod1, mod1h, mod_reg + 3);

        __m512i fst0, fst0h, fst1, fst1h;
        LoadZmmPair10(first[0], fst0, fst0h);
        LoadZmmPair10(first[1], fst1, fst1h);

        const __m512i k_reg0 = _mm512_set1_epi64((long long)k0[0]);
        const __m512i k_reg1 = _mm512_set1_epi64((long long)k0[1]);

        /* Precompute C = first[0]*k0 for parallel-y: y = (res[0]*k0) + (C*second[j])
         * The two terms are independent, filling the 4-cycle IFMA latency. */
        const __m512i c0 = _mm512_broadcastq_epi64(_mm512_castsi512_si128(
            _mm512_madd52lo_epu64(__m512i{}, fst0, k_reg0)));
        const __m512i c1 = _mm512_broadcastq_epi64(_mm512_castsi512_si128(
            _mm512_madd52lo_epu64(__m512i{}, fst1, k_reg1)));

        __m512i r0{}, r0h{}, r1{}, r1h{};

        for (Uint64 j = 0; j < 10; j++) {
            const __m512i s0 = _mm512_set1_epi64((long long)second[0][j]);
            const __m512i s1 = _mm512_set1_epi64((long long)second[1][j]);

            /* Parallel y: y_base and y_adj are independent — fills IFMA latency */
            __m512i y0 = _mm512_add_epi64(
                _mm512_madd52lo_epu64(__m512i{}, r0,  k_reg0),
                _mm512_madd52lo_epu64(__m512i{}, c0,  s0));
            __m512i y1 = _mm512_add_epi64(
                _mm512_madd52lo_epu64(__m512i{}, r1,  k_reg1),
                _mm512_madd52lo_epu64(__m512i{}, c1,  s1));

            FmaLo512Pair(r0, r0h, fst0, fst0h, s0);   /* res += first * second[j] */
            FmaLo512Pair(r1, r1h, fst1, fst1h, s1);

            y0 = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y0));
            y1 = _mm512_broadcastq_epi64(_mm512_castsi512_si128(y1));

            FmaLo512Pair(r0, r0h, mod0, mod0h, y0);   /* res += mod * y */
            FmaLo512Pair(r1, r1h, mod1, mod1h, y1);

            ShiftAndAddCarry512Pair(r0, r0h);
            ShiftAndAddCarry512Pair(r1, r1h);

            FmaHi512Pair(r0, r0h, fst0, fst0h, s0);
            FmaHi512Pair(r1, r1h, fst1, fst1h, s1);
            FmaHi512Pair(r0, r0h, mod0, mod0h, y0);
            FmaHi512Pair(r1, r1h, mod1, mod1h, y1);
        }

        StoreZmmPair10(res[0], r0, r0h);
        StoreZmmPair10(res[1], r1, r1h);

        Uint64 carry0 = 0, carry1 = 0;
        for (Uint64 i = 0; i < 10; i++) {
            Uint64 s0 = res[0][i] + carry0; carry0 = s0 >> 52; res[0][i] = s0 & 0xfffffffffffff;
            Uint64 s1 = res[1][i] + carry1; carry1 = s1 >> 52; res[1][i] = s1 & 0xfffffffffffff;
        }
    }

    static inline void AMM512ReduceParallel(Uint64*       res[2],
                                            Uint64*       first[2],
                                            const __m256i mod_reg[6],
                                            Uint64        k0[2])
    {
        /* Montgomery reduce: multiply by 1 (second = Montgomery 1 = {1,0,...,0}). */
        alignas(64) Uint64 one0[10] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        alignas(64) Uint64 one1[10] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        Uint64* one[2] = { one0, one1 };
        AMM512Parallel(res, first, one, mod_reg, k0);
    }

    static inline void SquareAndMultiplySet512(Uint64*       sq_radix_52[2],
                                                Uint64*       mult_radix_52[2],
                                                const __m256i mod_reg[6],
                                                Uint64        k0[2],
                                                int           index1,
                                                int           index2,
                                                Uint64*       t)
    {
        for (Uint64 i = 0; i < 5; i++) {
            AMS512Parallel(sq_radix_52, sq_radix_52, mod_reg, k0);
        }
        GetFromTableParallel512(
            t, index1, index2, mult_radix_52[0], mult_radix_52[1]);
        AMM512Parallel(sq_radix_52, sq_radix_52, mult_radix_52, mod_reg, k0);
    }

    static inline void RSA1024MontgomeryExpConstantTimeParallel(
        Uint64* res[2],
        Uint64* input[2],
        Uint64* exp[2],
        Uint64* modRadix52Bit[2],
        Uint64* r2Radix52Bit[2],
        Uint64  k0[2])
    {
#ifdef _WIN32
        auto t_storage = std::unique_ptr<Uint64[], decltype(&_aligned_free)>(
            static_cast<Uint64*>(
                _aligned_malloc(32 * 10 * 2 * sizeof(Uint64), 64)),
            _aligned_free);
        std::memset(t_storage.get(), 0, 32 * 10 * 2 * sizeof(Uint64));
        Uint64* t = t_storage.get();
#else
        alignas(64) Uint64 t[32 * 10 * 2]{};
#endif
        alignas(64) Uint64 r1_radix_52_bit_contig[2 * 10]{};
        alignas(64) Uint64 input_radix_52_contig[2 * 10]{};
        alignas(64) Uint64 res_radix_52_contig[2 * 10]{};
        alignas(64) Uint64 mult_radix_52_contig[2 * 10]{};
        alignas(64) Uint64 sq_radix_52_contig[2 * 10]{};

        Uint64* r1_radix_52_bit_p[2] = { r1_radix_52_bit_contig,
                                         r1_radix_52_bit_contig + 10 };
        Uint64* input_radix_52[2]    = { input_radix_52_contig,
                                         input_radix_52_contig + 10 };
        Uint64* res_radix_52[2]      = { res_radix_52_contig,
                                         res_radix_52_contig + 10 };
        Uint64* mult_radix_52[2]     = { mult_radix_52_contig,
                                         mult_radix_52_contig + 10 };
        Uint64* sq_radix_52[2]       = { sq_radix_52_contig,
                                         sq_radix_52_contig + 10 };

        /* mod_reg for 512-bit parallel: 6 x YMM = arm0[3] + arm1[3] */
        __m256i mod_reg[6];
        LoadReg256_512(mod_reg,     modRadix52Bit[0]);
        LoadReg256_512(mod_reg + 3, modRadix52Bit[1]);

        /* Compute r1 = 1 * R mod M (Montgomery form of 1) */
        AMM512ReduceParallel(r1_radix_52_bit_p, r2Radix52Bit, mod_reg, k0);
        PutInTableParallel512(t, 0, r1_radix_52_bit_p[0], r1_radix_52_bit_p[1]);

        /* Convert input to Montgomery domain: inp_mont = input * R2 * R^-1 = input * R mod M */
        Rsa512Radix64BitToRadix52Bit(input_radix_52[0], input[0]);
        Rsa512Radix64BitToRadix52Bit(input_radix_52[1], input[1]);
        AMM512Parallel(res_radix_52, input_radix_52, r2Radix52Bit, mod_reg, k0);

        PutInTableParallel512(t, 1, res_radix_52[0], res_radix_52[1]);

        alcp::utils::CopyChunk(mult_radix_52_contig, res_radix_52_contig, 10 * 8 * 2);

        /* Build table: t[i] = base^i for i=2..31 */
        for (Uint64 i = 2; i < 32; i++) {
            AMM512Parallel(
                mult_radix_52, mult_radix_52, res_radix_52, mod_reg, k0);
            PutInTableParallel512(
                t, i, mult_radix_52[0], mult_radix_52[1]);
        }

        const Uint8* exp_byte_ptr_1 = reinterpret_cast<const Uint8*>(exp[0]);
        const Uint8* exp_byte_ptr_2 = reinterpret_cast<const Uint8*>(exp[1]);

        /* 512-bit exponent = 64 bytes. Process 5 bits at a time.
         * Total bits = 512. First group: leading 4 bits from byte 63.
         * Then 101 groups of 5, processed byte-by-byte descending. */

        /* first 4 bits (top nibble of byte 63) */
        GetFromTableParallel512(t,
                                exp_byte_ptr_1[63] >> 4,
                                exp_byte_ptr_2[63] >> 4,
                                sq_radix_52[0],
                                sq_radix_52[1]);

        /* second 5 bits */
        SquareAndMultiplySet512(
            sq_radix_52, mult_radix_52, mod_reg, k0,
            (exp_byte_ptr_1[62] >> 7) | ((exp_byte_ptr_1[63] & 0xf) << 1),
            (exp_byte_ptr_2[62] >> 7) | ((exp_byte_ptr_2[63] & 0xf) << 1),
            t);

        /* third 5 bits */
        SquareAndMultiplySet512(
            sq_radix_52, mult_radix_52, mod_reg, k0,
            (exp_byte_ptr_1[62] >> 2) & 0x1f,
            (exp_byte_ptr_2[62] >> 2) & 0x1f,
            t);

        /* fourth 5 bits */
        SquareAndMultiplySet512(
            sq_radix_52, mult_radix_52, mod_reg, k0,
            (exp_byte_ptr_1[61] >> 5) | ((exp_byte_ptr_1[62] & 0x3) << 3),
            (exp_byte_ptr_2[61] >> 5) | ((exp_byte_ptr_2[62] & 0x3) << 3),
            t);

        /* fifth 5 bits */
        SquareAndMultiplySet512(
            sq_radix_52, mult_radix_52, mod_reg, k0,
            (exp_byte_ptr_1[61] & 0x1f),
            (exp_byte_ptr_2[61] & 0x1f),
            t);

        /* Main loop: process 8 groups of 5 bits per 5-byte block
         * bytes[i] down to bytes[i-4], i starts at 60 and decrements by 5 */
        for (Int64 i = 60; i > 3; i -= 5) {

            /* first 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                exp_byte_ptr_1[i] >> 3,
                exp_byte_ptr_2[i] >> 3,
                t);

            /* second 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                (exp_byte_ptr_1[i - 1] >> 6) | ((exp_byte_ptr_1[i] & 0x7) << 2),
                (exp_byte_ptr_2[i - 1] >> 6) | ((exp_byte_ptr_2[i] & 0x7) << 2),
                t);

            /* third 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                (exp_byte_ptr_1[i - 1] >> 1) & 0x1f,
                (exp_byte_ptr_2[i - 1] >> 1) & 0x1f,
                t);

            /* fourth 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                (exp_byte_ptr_1[i - 2] >> 4)
                    | ((exp_byte_ptr_1[i - 1] & 0x1) << 4),
                (exp_byte_ptr_2[i - 2] >> 4)
                    | ((exp_byte_ptr_2[i - 1] & 0x1) << 4),
                t);

            /* fifth 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                ((exp_byte_ptr_1[i - 2] & 0xf) << 1)
                    | (exp_byte_ptr_1[i - 3] >> 7),
                ((exp_byte_ptr_2[i - 2] & 0xf) << 1)
                    | (exp_byte_ptr_2[i - 3] >> 7),
                t);

            /* sixth 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                (exp_byte_ptr_1[i - 3] >> 2) & 0x1f,
                (exp_byte_ptr_2[i - 3] >> 2) & 0x1f,
                t);

            /* seventh 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                ((exp_byte_ptr_1[i - 3] & 0x3) << 3)
                    | (exp_byte_ptr_1[i - 4] >> 5),
                ((exp_byte_ptr_2[i - 3] & 0x3) << 3)
                    | (exp_byte_ptr_2[i - 4] >> 5),
                t);

            /* eighth 5 bits */
            SquareAndMultiplySet512(
                sq_radix_52, mult_radix_52, mod_reg, k0,
                exp_byte_ptr_1[i - 4] & 0x1f,
                exp_byte_ptr_2[i - 4] & 0x1f,
                t);
        }

        /* Byte 0: 8 remaining bits [7:0] after the loop covered bytes [60:1].
         * Process as two groups: bits [7:3] (5 bits) then bits [2:0] (3 bits). */

        /* bits [7:3] of byte 0: 5-bit window */
        SquareAndMultiplySet512(sq_radix_52, mult_radix_52, mod_reg, k0,
                                 exp_byte_ptr_1[0] >> 3,
                                 exp_byte_ptr_2[0] >> 3,
                                 t);

        /* bits [2:0] of byte 0: 3-bit window — 3 squarings + one multiply */
        for (Uint64 sq = 0; sq < 3; sq++) {
            AMS512Parallel(sq_radix_52, sq_radix_52, mod_reg, k0);
        }
        GetFromTableParallel512(t,
                                exp_byte_ptr_1[0] & 0x7,
                                exp_byte_ptr_2[0] & 0x7,
                                mult_radix_52[0],
                                mult_radix_52[1]);
        AMM512Parallel(sq_radix_52, sq_radix_52, mult_radix_52, mod_reg, k0);

        /* Convert back from Montgomery domain */
        AMM512ReduceParallel(sq_radix_52, sq_radix_52, mod_reg, k0);

        /* Zero the full 9-limb buffer: Rsa512Radix52BitToRadix64 does a
         * read-modify-write that touches the scratch 9th limb (see its doc). */
        alcp::utils::PadBlock<Uint64>(res[0], 0LL, 9 * 8);
        Rsa512Radix52BitToRadix64(res[0], sq_radix_52[0]);

        alcp::utils::PadBlock<Uint64>(res[1], 0LL, 9 * 8);
        Rsa512Radix52BitToRadix64(res[1], sq_radix_52[1]);
    }

    static __attribute__((noinline)) void SquareAndMultiplySet(
        Uint64*       sq_radix_52[2],
        Uint64*       mult_radix_52[2],
        const __m256i mod_reg[10],
        Uint64        k0[2],
        int           index1,
        int           index2,
        Uint64*       t)
    {
        for (Uint64 i = 0; i < 5; i++) {
            AMS1024Parallel(sq_radix_52, sq_radix_52, mod_reg, k0);
        }

        GetFromTableParallel(
            t, index1, index2, mult_radix_52[0], mult_radix_52[1]);

        AMM1024Parallel(sq_radix_52, sq_radix_52, mult_radix_52, mod_reg, k0);
    }

    static inline void RSA2048MontgomeryExpConstantTimeParallel(
        Uint64* res[2],
        Uint64* input[2],
        Uint64* exp[2],
        Uint64* modRadix52Bit[2],
        Uint64* r2Radix52Bit[2],
        Uint64  k0[2])
    {
#ifdef _WIN32
        auto t_storage = std::unique_ptr<Uint64[], decltype(&_aligned_free)>(
            static_cast<Uint64*>(
                _aligned_malloc(32 * 20 * 2 * sizeof(Uint64), 64)),
            _aligned_free);
        std::memset(t_storage.get(), 0, 32 * 20 * 2 * sizeof(Uint64));
        Uint64* t = t_storage.get();
#else
        alignas(64) Uint64 t[32 * 20 * 2]{};
#endif
        alignas(64) Uint64 r1_radix_52_bit_contig[2 * 20]{};
        alignas(64) Uint64 input_radix_52_contig[2 * 20]{};
        alignas(64) Uint64 res_radix_52_contig[2 * 20]{};
        alignas(64) Uint64 mult_radix_52_contig[2 * 20]{};
        alignas(64) Uint64 sq_radix_52_contig[2 * 20]{};

        Uint64* r1_radix_52_bit_p[2] = { r1_radix_52_bit_contig,
                                         r1_radix_52_bit_contig + 20 };
        Uint64* input_radix_52[2]    = { input_radix_52_contig,
                                         input_radix_52_contig + 20 };
        Uint64* res_radix_52[2]      = { res_radix_52_contig,
                                         res_radix_52_contig + 20 };

        Uint64* mult_radix_52[2] = { mult_radix_52_contig,
                                     mult_radix_52_contig + 20 };
        Uint64* sq_radix_52[2]   = { sq_radix_52_contig,
                                     sq_radix_52_contig + 20 };

        __m256i mod_reg[10];
        LoadReg256(mod_reg, modRadix52Bit[0]);
        LoadReg256(mod_reg + 5, modRadix52Bit[1]);

        AMM1024ReduceParallel(r1_radix_52_bit_p, r2Radix52Bit, mod_reg, k0);
        PutInTableParallel(
            t, 0, r1_radix_52_bit_p[0], r1_radix_52_bit_p[1]);

        Rsa1024Radix64BitToRadix52Bit(input_radix_52[0], input[0]);
        Rsa1024Radix64BitToRadix52Bit(input_radix_52[1], input[1]);

        // almost montgomery multiplication on 1024 bits
        AMM1024Parallel(
            res_radix_52, input_radix_52, r2Radix52Bit, mod_reg, k0);

        PutInTableParallel(t, 1, res_radix_52[0], res_radix_52[1]);

        alcp::utils::CopyChunk(
            mult_radix_52_contig, res_radix_52_contig, 20 * 8 * 2);

        for (Uint64 i = 2; i < 32; i++) {
            AMM1024Parallel(
                mult_radix_52, mult_radix_52, res_radix_52, mod_reg, k0);
            PutInTableParallel(t, i, mult_radix_52[0], mult_radix_52[1]);
        }

        const Uint8* exp_byte_ptr_1 = reinterpret_cast<const Uint8*>(exp[0]);
        const Uint8* exp_byte_ptr_2 = reinterpret_cast<const Uint8*>(exp[1]);

        // applying exponentiation using 5 bits at time and fetching the values
        // from precomputed tables
        // first 4 bit
        GetFromTableParallel(t,
                             exp_byte_ptr_1[127] >> 4,
                             exp_byte_ptr_2[127] >> 4,
                             sq_radix_52[0],
                             sq_radix_52[1]);

        // second 5 bit
        SquareAndMultiplySet(
            sq_radix_52,
            mult_radix_52,
            mod_reg,
            k0,
            (exp_byte_ptr_1[126] >> 7) | ((exp_byte_ptr_1[127] & 0xf) << 1),
            (exp_byte_ptr_2[126] >> 7) | ((exp_byte_ptr_2[127] & 0xf) << 1),
            t);

        // third 5 bit
        SquareAndMultiplySet(sq_radix_52,
                              mult_radix_52,
                              mod_reg,
                              k0,
                              (exp_byte_ptr_1[126] >> 2) & 0x1f,
                              (exp_byte_ptr_2[126] >> 2) & 0x1f,
                              t);

        // fourth 5 bit
        SquareAndMultiplySet(
            sq_radix_52,
            mult_radix_52,
            mod_reg,
            k0,
            (exp_byte_ptr_1[125] >> 5) | ((exp_byte_ptr_1[126] & 0x3) << 3),
            (exp_byte_ptr_2[125] >> 5) | ((exp_byte_ptr_2[126] & 0x3) << 3),
            t);

        // fifth 5 bit
        SquareAndMultiplySet(sq_radix_52,
                              mult_radix_52,
                              mod_reg,
                              k0,
                              ((exp_byte_ptr_1[125] & 0x1f)),
                              ((exp_byte_ptr_2[125] & 0x1f)),
                              t);

        for (Int64 i = 124; i > 3; i -= 5) {

            // first 5 bits
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  exp_byte_ptr_1[i] >> 3,
                                  exp_byte_ptr_2[i] >> 3,
                                  t);

            // second 5 bits
            SquareAndMultiplySet(
                sq_radix_52,
                mult_radix_52,
                mod_reg,
                k0,
                (exp_byte_ptr_1[i - 1] >> 6) | ((exp_byte_ptr_1[i] & 0x7) << 2),
                (exp_byte_ptr_2[i - 1] >> 6) | ((exp_byte_ptr_2[i] & 0x7) << 2),
                t);

            // third 5 bit
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 1] >> 1) & 0x1f,
                                  (exp_byte_ptr_2[i - 1] >> 1) & 0x1f,
                                  t);

            // fourth 5 bit
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 2] >> 4)
                                      | ((exp_byte_ptr_1[i - 1] & 0x1) << 4),
                                  (exp_byte_ptr_2[i - 2] >> 4)
                                      | ((exp_byte_ptr_2[i - 1] & 0x1) << 4),
                                  t);

            // fifth 5 bit
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  ((exp_byte_ptr_1[i - 2] & 0xf) << 1)
                                      | (exp_byte_ptr_1[i - 3] >> 7),
                                  ((exp_byte_ptr_2[i - 2] & 0xf) << 1)
                                      | (exp_byte_ptr_2[i - 3] >> 7),
                                  t);

            // 6th 5 bits
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 3] >> 2) & 0x1f,
                                  (exp_byte_ptr_2[i - 3] >> 2) & 0x1f,
                                  t);
            // 7th 5 bits
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  ((exp_byte_ptr_1[i - 3] & 0x3) << 3)
                                      | (exp_byte_ptr_1[i - 4] >> 5),
                                  ((exp_byte_ptr_2[i - 3] & 0x3) << 3)
                                      | (exp_byte_ptr_2[i - 4] >> 5),
                                  t);

            // 8th 5 bits
            SquareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  exp_byte_ptr_1[i - 4] & 0x1f,
                                  exp_byte_ptr_2[i - 4] & 0x1f,
                                  t);
        }

        AMM1024ReduceParallel(sq_radix_52, sq_radix_52, mod_reg, k0);

        /* Zero the full 17-limb buffer: Rsa1024Radix52BitToRadix64 does a
         * read-modify-write that touches the scratch 17th limb (see its doc). */
        alcp::utils::PadBlock<Uint64>(res[0], 0LL, 17 * 8);
        Rsa1024Radix52BitToRadix64(res[0], sq_radix_52[0]);

        alcp::utils::PadBlock<Uint64>(res[1], 0LL, 17 * 8);
        Rsa1024Radix52BitToRadix64(res[1], sq_radix_52[1]);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::decryptUsingCRT(
        Uint64*              res,
        const Uint64*        inp,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ)
    {
        auto size = contextP.m_size;

        Uint64 buff_p[16];
        // Extra element prevents overflow in Rsa512Radix52BitToRadix64
        Uint64 buff_0_p[8 + 1];
        Uint64 buff_1_p[8 + 1];

        auto p_mod_radix_52_bit = contextP.m_mod_radix_52_bit;
        auto p_mod              = privKey.m_p;
        auto q_mod              = privKey.m_q;
        auto p_exp              = privKey.m_dp;
        auto q_mod_radix_52_bit = contextQ.m_mod_radix_52_bit;
        auto q_exp              = privKey.m_dq;
        auto r2_p               = contextP.m_r2;
        auto r2_q               = contextQ.m_r2;
        auto r2_radix_52_bit_p  = contextP.m_r2_radix_52_bit;
        auto r2_radix_52_bit_q  = contextQ.m_r2_radix_52_bit;
        auto qinv               = privKey.m_qinv;
        auto p_k0               = contextP.m_k0;
        auto q_k0               = contextQ.m_k0;

        /* P reduction - ap */
        alcp::utils::CopyChunk(buff_p, inp, 1024 / 8);
        MontReduceHalf(buff_0_p, buff_p, p_mod, p_k0);
        MontMultHalf(buff_0_p, buff_0_p, r2_p, p_mod, p_k0);

        /* Q reduction - aq */
        alcp::utils::CopyChunk(buff_p, inp, 1024 / 8);
        MontReduceHalf(buff_1_p, buff_p, q_mod, q_k0);
        MontMultHalf(buff_1_p, buff_1_p, r2_q, q_mod, q_k0);

        /* ap = ap^dp mod p, aq = aq^dq mod q — both arms in parallel.
         * RSA1024MontgomeryExpConstantTimeParallel converts inputs to AMM
         * Montgomery domain internally (via AMM(inp, r2_amm)), so we pass
         * the standard-form ap_red and aq_red directly. */
        Uint64* buff[2]  = { buff_0_p, buff_1_p };
        Uint64* expp[2]  = { p_exp, q_exp };
        Uint64* mod[2]   = { p_mod_radix_52_bit, q_mod_radix_52_bit };
        Uint64* r2[2]    = { r2_radix_52_bit_p, r2_radix_52_bit_q };
        Uint64  k0[2]    = { p_k0, q_k0 };

        RSA1024MontgomeryExpConstantTimeParallel(buff, buff, expp, mod, r2, k0);

        /* CRT reconstruction (same as scalar path) */
        MontSub(buff_p, buff_1_p, p_mod, p_mod, size);
        MontSub(buff_0_p, buff_0_p, buff_p, p_mod, size);

        MontMultHalf(res, qinv, r2_p, p_mod, p_k0);
        MontMultHalf(buff_0_p, buff_0_p, res, p_mod, p_k0);

        alcp::utils::PadBlock<Uint64>(buff_p, 0LL, size * 8 * 2);

        mul(buff_p, buff_0_p, size, q_mod, size);

        AddBigNum(res, size * 2, buff_p, buff_1_p, size);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::decryptUsingCRT(
        Uint64*              res,
        const Uint64*        inp,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ)
    {
        auto size = contextP.m_size;

        Uint64 buff_p[32];
        // Extra element prevents overflow in Rsa1024Radix52BitToRadix64
        Uint64 buff_0_p[16 + 1];
        Uint64 buff_1_p[16 + 1];

        auto p_mod_radix_52_bit = contextP.m_mod_radix_52_bit;
        auto p_mod              = privKey.m_p;
        auto q_mod              = privKey.m_q;
        auto p_exp              = privKey.m_dp;
        auto q_mod_radix_52_bit = contextQ.m_mod_radix_52_bit;
        auto q_exp              = privKey.m_dq;
        auto r2_p               = contextP.m_r2;
        auto r2_q               = contextQ.m_r2;
        auto r2_radix_52_bit_p  = contextP.m_r2_radix_52_bit;
        auto r2_radix_52_bit_q  = contextQ.m_r2_radix_52_bit;
        auto qinv               = privKey.m_qinv;
        auto p_k0               = contextP.m_k0;
        auto q_k0               = contextQ.m_k0;

        // P reduction - ap
        alcp::utils::CopyChunk(buff_p, inp, 2048 / 8);

        MontReduceHalf(buff_0_p, buff_p, p_mod, p_k0);

        MontMultHalf(buff_0_p, buff_0_p, r2_p, p_mod, p_k0);

        // Q reduction - aq
        alcp::utils::CopyChunk(buff_p, inp, 2048 / 8);
        MontReduceHalf(buff_1_p, buff_p, q_mod, q_k0);
        MontMultHalf(buff_1_p, buff_1_p, r2_q, q_mod, q_k0);

        Uint64* buff[2] = { buff_0_p, buff_1_p };
        Uint64* exp[2]  = { p_exp, q_exp };
        Uint64* mod[2]  = { p_mod_radix_52_bit, q_mod_radix_52_bit };
        Uint64* r2[2]   = { r2_radix_52_bit_p, r2_radix_52_bit_q };
        Uint64  k0[2]   = { p_k0, q_k0 };

        RSA2048MontgomeryExpConstantTimeParallel(buff, buff, exp, mod, r2, k0);

        // convert aq to aq mod p
        MontSub(buff_p, buff_1_p, p_mod, p_mod, size);

        // ap = (ap - aq) mod p
        MontSub(buff_0_p, buff_0_p, buff_p, p_mod, size);

        // convert qInv to qInv * r mod P
        MontMultHalf(res, qinv, r2_p, p_mod, p_k0);

        // qInv * r * ap * r^-1 mod P ->
        // qInv * ap mod P h = qInv * ap
        // mod P
        MontMultHalf(buff_0_p, buff_0_p, res, p_mod, p_k0);

        alcp::utils::PadBlock<Uint64>(buff_p, 0LL, size * 8 * 2);

        // h * Q
        mul(buff_p, buff_0_p, size, q_mod, size);

        // res = aq + h*Q
        AddBigNum(res, size * 2, buff_p, buff_1_p, size);
        return;
    }

    template void archDecryptPrivate<KEY_SIZE_1024>(
        Uint8*               pText,
        const Uint64*        pEncTextBigNum,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ);

    template void archDecryptPrivate<KEY_SIZE_2048>(
        Uint8*               pText,
        const Uint64*        pEncTextBigNum,
        RsaPrivateKeyBignum& privKey,
        MontContextBignum&   contextP,
        MontContextBignum&   contextQ);

    template void archCreateContext<KEY_SIZE_1024>(MontContextBignum& context,
                                                   Uint64*            mod,
                                                   Uint64             size);

    template void archCreateContext<KEY_SIZE_2048>(MontContextBignum& context,
                                                   Uint64*            mod,
                                                   Uint64             size);
}} // namespace alcp::rsa::zen4
