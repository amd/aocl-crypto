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
#include "alcp/rsa.h"
#include "alcp/rsa/rsa_internal.hh"
#include "alcp/utils/copy.hh"
#include <immintrin.h>

/*
 * AMS1024 is bases on Fast modular squaring with AVX512IFMA
 * reference as mentioned on below link
 * https://eprint.iacr.org/2018/335
 *
 * AMM1024  and RSA2048MontgomeryExpConstantTimeParallel is based on Fast
 * modular multplication and exponentiation with AVX512IFMA referenced as
 * mentioned on below link
 * https://link.springer.com/chapter/10.1007/978-3-642-31662-3_9
 *
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
        // memcpy should be better as it contains more memory optimizations for
        // tasks like this. Shifting is adding more instructions.
#if 0
        return static_cast<Uint64>(val[7]) << 56
               | static_cast<Uint64>(val[6]) << 48
               | static_cast<Uint64>(val[5]) << 40
               | static_cast<Uint64>(val[4]) << 32
               | static_cast<Uint64>(val[3]) << 24
               | static_cast<Uint64>(val[2]) << 16
               | static_cast<Uint64>(val[1]) << 8 | val[0];
#else
        Uint64 val64 = 0;
        memcpy(&val64, val, 8);
        return val64;
#endif
    }
    static inline void Rsa1024Radix64BitToRadix52Bit(Uint64*       out,
                                                     const Uint64* in);

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
    // Converts back the radix 52 bit in 1024 bits to radix 64
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
    static inline void Rsa2048Radix52BitToRadix64Bit(Uint64*       out,
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

    static inline void GetFromTableParallel(
        Uint64* t, Uint64 index1, Uint64 index2, Uint64* num1, Uint64* num2)
    {
        // table has 32 entry and each entry is 20 64 bits
        Uint64* t2 = t + 32 * 20;
        for (Uint64 i = 0; i < 20; i++) {
            num1[i] = t[index1];
            num2[i] = t2[index2];
            index1 += 32;
            index2 += 32;
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

    static inline void FusedMultiplyAddShiftHighStage3(__m256i res[3],
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

    // Multiplying registers holding first to 4th digit to all other digits
    // starting from first to last digit
    static inline void Amm1024LoopInternalStage1Parallel(
        __m256i       res_reg[10],
        __m256i       first_reg[10],
        const __m256i mod_reg[10],
        const Uint64* first,
        const Uint64* second,
        const __m256i k_reg_0,
        const __m256i k_reg_1)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage1(res_reg, first_reg, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage1(res_reg, first_reg, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddShiftLow256Stage1(
                res_reg + 5, first_reg + 5, second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddShiftHigh256Stage1(
                res_reg + 5, first_reg + 5, second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
    }

    // Multiplying registers holding 5th to 8th digit to all other digits
    // starting from 5th to last digit
    static inline void Amm1024LoopInternalStage2Parallel(
        __m256i       res_reg[10],
        __m256i       first_reg[10],
        const __m256i mod_reg[10],
        const Uint64* first,
        const Uint64* second,
        const __m256i k_reg_0,
        const __m256i k_reg_1)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage2(
                res_reg + 1, first_reg + 1, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddShiftLow256Stage2(
                res_reg + 6, first_reg + 6, second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddShiftHigh256Stage2(
                res_reg + 6, first_reg + 6, second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
    }

    // Multiplying registers holding 9th to 12th digit to all other digits
    // starting from 9th to last digit
    static inline void Amm1024LoopInternalStage3Parallel(
        __m256i       res_reg[10],
        __m256i       first_reg[10],
        const __m256i mod_reg[10],
        const Uint64* first,
        const Uint64* second,
        const __m256i k_reg_0,
        const __m256i k_reg_1)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage3(
                res_reg + 2, first_reg + 2, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHighStage3(
                res_reg + 2, first_reg + 2, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddShiftLow256Stage3(
                res_reg + 7, first_reg + 7, second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddShiftHighStage3(
                res_reg + 7, first_reg + 7, second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
    }

    // Multiplying registers holding 13th to 16th digit to all other digits
    // starting from 13th to last digit
    static inline void Amm1024LoopInternalStage4Parallel(
        __m256i       res_reg[10],
        __m256i       first_reg[10],
        const __m256i mod_reg[10],
        const Uint64* first,
        const Uint64* second,
        const __m256i k_reg_0,
        const __m256i k_reg_1)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage4(
                res_reg + 3, first_reg + 3, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddShiftLow256Stage4(
                res_reg + 8, first_reg + 8, second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddShiftHigh256Stage4(
                res_reg + 8, first_reg + 8, second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
    }

    // Multiplying registers holding 17th to 20th digit to all other digits
    // starting from 17th to last digit
    static inline void Amm1024LoopInternalStage5Parallel(
        __m256i       res_reg[10],
        __m256i       first_reg[10],
        const __m256i mod_reg[10],
        const Uint64* first,
        const Uint64* second,
        const __m256i k_reg_0,
        const __m256i k_reg_1)
    {
        const __m256i zero{};

        for (Uint64 j = 0; j < 4; j++) {

            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddShiftLow256Stage5(
                res_reg[4], first_reg[4], second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage5(
                res_reg[4], first_reg[4], second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddShiftLow256Stage5(
                res_reg[9], first_reg[9], second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddShiftHigh256Stage5(
                res_reg[9], first_reg[9], second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
        }
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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHighStage3(
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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddShiftHigh256Stage5(
                res_reg[4], first_reg[4], second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);
        }
    }

    static inline void Amm1024LoopInternalParallel(__m256i       res_reg[10],
                                                   __m256i       first_reg[10],
                                                   const __m256i mod_reg[10],
                                                   const Uint64* first,
                                                   const Uint64* second,
                                                   const __m256i k_reg_0,
                                                   const __m256i k_reg_1)
    {
        const __m256i zero{};
        for (Uint64 j = 0; j < 20; j++) {
            __m256i second_reg = _mm256_set1_epi64x(first[j]);

            FusedMultiplyAddLow256(res_reg, first_reg, second_reg);

            __m256i y_reg = _mm256_madd52lo_epu64(zero, k_reg_0, res_reg[0]);
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddHigh256(res_reg, first_reg, second_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second multiplier
            second_reg = _mm256_set1_epi64x(second[j]);

            FusedMultiplyAddLow256(res_reg + 5, first_reg + 5, second_reg);

            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg + 5, mod_reg + 5, y_reg);

            ShiftAndAddCarry256(res_reg + 5);

            FusedMultiplyAddHigh256(res_reg + 5, first_reg + 5, second_reg);

            FusedMultiplyAddHigh256(res_reg + 5, mod_reg + 5, y_reg);
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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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

    // Parallel AMM1024 for two sets of different inputs
    static inline void AMM1024Parallel(Uint64*       res[2],
                                       Uint64*       first[2],
                                       Uint64*       second[2],
                                       const __m256i mod_reg[10],
                                       Uint64        k0[2])
    {
        __m256i first_reg[10];

        __m256i res_reg[10]{};

        Uint64* first_0  = first[0];
        Uint64* first_1  = first[1];
        Uint64* second_0 = second[0];
        Uint64* second_1 = second[1];
        Uint64* res_0    = res[0];
        Uint64* res_1    = res[1];

        LoadReg256(first_reg, first_0);

        LoadReg256(first_reg + 5, first_1);
        __m256i k_reg_0 = _mm256_set1_epi64x(k0[0]);
        __m256i k_reg_1 = _mm256_set1_epi64x(k0[1]);

        Amm1024LoopInternalParallel(
            res_reg, first_reg, mod_reg, second_0, second_1, k_reg_0, k_reg_1);

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
        __m256i first_reg[10];
        __m256i res_reg[10]{};
        Uint64* first_0 = first[0];
        Uint64* first_1 = first[1];
        Uint64* res_0   = res[0];
        Uint64* res_1   = res[1];

        LoadReg256(first_reg, first_0);
        LoadReg256(first_reg + 5, first_1);

        __m256i k_reg_0 = _mm256_set1_epi64x(k0[0]);
        __m256i k_reg_1 = _mm256_set1_epi64x(k0[1]);

        Amm1024LoopInternalStage1Parallel(
            res_reg, first_reg, mod_reg, first_0, first_1, k_reg_0, k_reg_1);

        Amm1024LoopInternalStage2Parallel(res_reg,
                                          first_reg,
                                          mod_reg,
                                          first_0 + 4,
                                          first_1 + 4,
                                          k_reg_0,
                                          k_reg_1);

        Amm1024LoopInternalStage3Parallel(res_reg,
                                          first_reg,
                                          mod_reg,
                                          first_0 + 8,
                                          first_1 + 8,
                                          k_reg_0,
                                          k_reg_1);

        Amm1024LoopInternalStage4Parallel(res_reg,
                                          first_reg,
                                          mod_reg,
                                          first_0 + 12,
                                          first_1 + 12,
                                          k_reg_0,
                                          k_reg_1);
        Amm1024LoopInternalStage5Parallel(res_reg,
                                          first_reg,
                                          mod_reg,
                                          first_0 + 16,
                                          first_1 + 16,
                                          k_reg_0,
                                          k_reg_1);

        StoreReg256(res_0, res_reg);
        StoreReg256(res_1, res_reg + 5);

        Uint64 carry = 0, carry1 = 0;
        // convert from redundant radix
        // 2^52 to radix 2^52
        for (Uint64 i = 0; i < 20; i++) {
            Uint64 sum = res[0][i] + carry;
            carry      = sum >> 52;
            res[0][i]  = sum & 0xfffffffffffff;

            sum       = res[1][i] + carry1;
            carry1    = sum >> 52;
            res[1][i] = sum & 0xfffffffffffff;
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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm512_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

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
            y_reg         = _mm256_permutexvar_epi64(zero, y_reg);

            FusedMultiplyAddLow256(res_reg, mod_reg, y_reg);

            ShiftAndAddCarry256(res_reg);

            FusedMultiplyAddHigh256(res_reg, mod_reg, y_reg);

            // second reduction
            y_reg = _mm256_madd52lo_epu64(zero, k_reg_1, res_reg[5]);
            y_reg = _mm256_permutexvar_epi64(zero, y_reg);

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
        Uint64* r1               = new Uint64[size]{};
        Uint64* r2               = new Uint64[size]{};
        Uint64* r3               = new Uint64[size]{};
        Uint64* r2_radix_52_bit  = new Uint64[40]{};
        Uint64* mod_radix_52_bit = new Uint64[40]{};

        context.m_r1.reset(r1);
        context.m_r2.reset(r2);
        context.m_r3.reset(r3);
        context.m_r2_radix_52_bit.reset(r2_radix_52_bit);
        context.m_mod_radix_52_bit.reset(mod_radix_52_bit);
        context.m_size = size;
        context.m_k0   = computeMontFactor(mod[0]);

        BigNum inp{ mod, size, size - 1 }, res{ r2, size, size - 1 };

        computeMontConverter(res, inp);

        MontMultHalf(r3, r2, r2, mod, context.m_k0);

        auto param     = std::make_unique<Uint64[]>(size * 2);
        auto param_ptr = param.get();
        alcp::utils::CopyChunk(param_ptr, r2, size * 8);

        MontReduce(r1, param_ptr, mod, context.m_k0, size * 2);

        if (size == 32) {
            Rsa2048Radix64BitToRadix52Bit(mod_radix_52_bit, mod);
            Rsa2048Radix64BitToRadix52Bit(r2_radix_52_bit, r2);

            __m512i mod_reg[5];

            LoadReg512(mod_reg, mod_radix_52_bit);

            __m512i k_reg = _mm512_set1_epi64(context.m_k0);
            //(congruent to 2^(4n-k×m) mod (n is number of bit, k is digits for
            // holding radix 52 number ,m is 52)
            // M)
            AMM2048(r2_radix_52_bit,
                    r2_radix_52_bit,
                    r2_radix_52_bit,
                    mod_reg,
                    k_reg);
            // 2^(4km - 4n) in radix 52
            alignas(64) const Uint64 mult[40] = { 0x00, 0x00, 0x1000000 };

            //(congruent to 2^2k×m mod M)
            AMM2048(r2_radix_52_bit, r2_radix_52_bit, mult, mod_reg, k_reg);
        } else {
            Rsa1024Radix64BitToRadix52Bit(mod_radix_52_bit, mod);
            Rsa1024Radix64BitToRadix52Bit(r2_radix_52_bit, r2);

            __m256i mod_reg[5];

            LoadReg256(mod_reg, mod_radix_52_bit);

            __m256i k_reg = _mm256_set1_epi64x(context.m_k0);
            //(congruent to 2^(4n-k×m) mod
            // M)
            AMM1024(r2_radix_52_bit,
                    r2_radix_52_bit,
                    r2_radix_52_bit,
                    mod_reg,
                    k_reg);
            // 2^(4km - 4n) in radix 52
            alignas(64) const Uint64 mult[20] = { 0x00, 0x1000 };

            //(congruent to 2^2k×m mod M)
            AMM1024(r2_radix_52_bit, r2_radix_52_bit, mult, mod_reg, k_reg);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::CreateContext(
        MontContextBignum& context, Uint64* mod, Uint64 size)
    {
        Uint64* r1               = new Uint64[size]{};
        Uint64* r2               = new Uint64[size]{};
        Uint64* r3               = new Uint64[size]{};
        Uint64* r2_radix_52_bit  = new Uint64[20]{};
        Uint64* mod_radix_52_bit = new Uint64[20]{};

        context.m_r1.reset(r1);
        context.m_r2.reset(r2);
        context.m_r3.reset(r3);
        context.m_r2_radix_52_bit.reset(r2_radix_52_bit);
        context.m_mod_radix_52_bit.reset(mod_radix_52_bit);
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
            // If size is less than 512 bits which is the case for RSA
            // decryption using CRT and can be returned from here.
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
        Uint64*       exp,
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

        Rsa2048Radix52BitToRadix64Bit(res, input_radix_52_bit);
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        Uint64*       exp,
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
        auto mod = context.m_mod_radix_52_bit.get(); //.m_mod.get();
        auto r2  = context.m_r2_radix_52_bit.get();  // context.m_r2.get();
        auto k0  = context.m_k0;
        auto exp = &pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[1024 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_1024>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = 1024 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    template<>
    void archEncryptPublic<KEY_SIZE_2048>(Uint8*              pEncText,
                                          const Uint64*       pTextBignum,
                                          RsaPublicKeyBignum& pubKey,
                                          MontContextBignum&  context)
    {
        auto mod = context.m_mod_radix_52_bit.get(); //.m_mod.get();
        auto r2  = context.m_r2_radix_52_bit.get();  // context.m_r2.get();
        auto k0  = context.m_k0;
        auto exp = &pubKey.m_public_exponent;

        alignas(64) Uint64 res_buffer_bignum[2048 / 64 * 3]{};
        mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
            res_buffer_bignum, pTextBignum, exp, 1, mod, r2, k0);

        Uint8* enc_text = reinterpret_cast<Uint8*>(res_buffer_bignum);
        for (Int64 i = 2048 / 8 - 1, j = 0; i >= 0; --i, ++j) {
            pEncText[j] = enc_text[i];
        }
    }

    static inline void SqauareAndMultiplySet(Uint64*       sq_radix_52[2],
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
        alignas(64) Uint64 t[32 * 20 * 2] = {};
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

        // to do check which window size
        // is correct
        // Uint64 winSize    = 5;
        // putting one in mont form
        AMM1024ReduceParallel(r1_radix_52_bit_p, r2Radix52Bit, mod_reg, k0);
        PutInTableParallel(t, 0, r1_radix_52_bit_p[0], r1_radix_52_bit_p[1]);

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
        SqauareAndMultiplySet(
            sq_radix_52,
            mult_radix_52,
            mod_reg,
            k0,
            (exp_byte_ptr_1[126] >> 7) | ((exp_byte_ptr_1[127] & 0xf) << 1),
            (exp_byte_ptr_2[126] >> 7) | ((exp_byte_ptr_2[127] & 0xf) << 1),
            t);

        // third 5 bit
        SqauareAndMultiplySet(sq_radix_52,
                              mult_radix_52,
                              mod_reg,
                              k0,
                              (exp_byte_ptr_1[126] >> 2) & 0x1f,
                              (exp_byte_ptr_2[126] >> 2) & 0x1f,
                              t);

        // fourth 5 bit
        SqauareAndMultiplySet(
            sq_radix_52,
            mult_radix_52,
            mod_reg,
            k0,
            (exp_byte_ptr_1[125] >> 5) | ((exp_byte_ptr_1[126] & 0x3) << 3),
            (exp_byte_ptr_2[125] >> 5) | ((exp_byte_ptr_2[126] & 0x3) << 3),
            t);

        // fifth 5 bit
        SqauareAndMultiplySet(sq_radix_52,
                              mult_radix_52,
                              mod_reg,
                              k0,
                              ((exp_byte_ptr_1[125] & 0x1f)),
                              ((exp_byte_ptr_2[125] & 0x1f)),
                              t);

        for (Int64 i = 124; i > 3; i -= 5) {

            // first 5 bits
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  exp_byte_ptr_1[i] >> 3,
                                  exp_byte_ptr_2[i] >> 3,
                                  t);

            // second 5 bits
            SqauareAndMultiplySet(
                sq_radix_52,
                mult_radix_52,
                mod_reg,
                k0,
                (exp_byte_ptr_1[i - 1] >> 6) | ((exp_byte_ptr_1[i] & 0x7) << 2),
                (exp_byte_ptr_2[i - 1] >> 6) | ((exp_byte_ptr_2[i] & 0x7) << 2),
                t);

            // third 5 bit
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 1] >> 1) & 0x1f,
                                  (exp_byte_ptr_2[i - 1] >> 1) & 0x1f,
                                  t);

            // fourth 5 bit
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 2] >> 4)
                                      | ((exp_byte_ptr_1[i - 1] & 0x1) << 4),
                                  (exp_byte_ptr_2[i - 2] >> 4)
                                      | ((exp_byte_ptr_2[i - 1] & 0x1) << 4),
                                  t);

            // fifth 5 bit
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  ((exp_byte_ptr_1[i - 2] & 0xf) << 1)
                                      | (exp_byte_ptr_1[i - 3] >> 7),
                                  ((exp_byte_ptr_2[i - 2] & 0xf) << 1)
                                      | (exp_byte_ptr_2[i - 3] >> 7),
                                  t);

            // 6th 5 bits
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  (exp_byte_ptr_1[i - 3] >> 2) & 0x1f,
                                  (exp_byte_ptr_2[i - 3] >> 2) & 0x1f,
                                  t);
            // 7th 5 bits
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  ((exp_byte_ptr_1[i - 3] & 0x3) << 3)
                                      | (exp_byte_ptr_1[i - 4] >> 5),
                                  ((exp_byte_ptr_2[i - 3] & 0x3) << 3)
                                      | (exp_byte_ptr_2[i - 4] >> 5),
                                  t);

            // 8th 5 bits
            SqauareAndMultiplySet(sq_radix_52,
                                  mult_radix_52,
                                  mod_reg,
                                  k0,
                                  exp_byte_ptr_1[i - 4] & 0x1f,
                                  exp_byte_ptr_2[i - 4] & 0x1f,
                                  t);
        }

        AMM1024ReduceParallel(sq_radix_52, sq_radix_52, mod_reg, k0);

        alcp::utils::PadBlock<Uint64>(res[0], 0LL, 16 * 8);
        Rsa1024Radix52BitToRadix64(res[0], sq_radix_52[0]);

        alcp::utils::PadBlock<Uint64>(res[1], 0LL, 16 * 8);
        Rsa1024Radix52BitToRadix64(res[1], sq_radix_52[1]);
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
        // Buffer Overflowed when allocated as 16*64 bits. Allocating another 64
        // bits to prevent offerflow in  Rsa1024Radix52BitToRadix64. Might be
        // related to bignum overflowing more than 128 bytes
        Uint64 buff_0_p[16 + 1];
        Uint64 buff_1_p[16 + 1];

        auto p_mod_radix_52_bit = contextP.m_mod_radix_52_bit.get();
        auto p_mod              = privKey.m_p.get();
        auto q_mod              = privKey.m_q.get();
        auto p_exp              = privKey.m_dp.get();
        auto q_mod_radix_52_bit = contextQ.m_mod_radix_52_bit.get();
        auto q_exp              = privKey.m_dq.get();
        auto r2_p               = contextP.m_r2.get();
        auto r2_q               = contextQ.m_r2.get();
        auto r2_radix_52_bit_p  = contextP.m_r2_radix_52_bit.get();
        auto r2_radix_52_bit_q  = contextQ.m_r2_radix_52_bit.get();
        auto qinv               = privKey.m_qinv.get();
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

        // Rsa1024Radix64BitToRadix52Bit(r1_p_rdix_52_bit,
        // r1_p); ap = ap ^ dp mod p // aq
        // = aq ^dq mod q
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
