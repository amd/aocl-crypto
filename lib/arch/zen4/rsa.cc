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

namespace alcp::rsa { namespace zen4 {
#include "../../rsa/rsa.cc.inc"

    constexpr Uint64     num_digit = (2048 / 52 + 1);
    constexpr Uint64     num_reg   = num_digit / 8;
    static inline Uint64 GetRadix52Bit(Uint64 val)
    {
        constexpr Uint64 MaskRadix52Bit = 0xfffffffffffff;
        return val & MaskRadix52Bit;
    }

    static inline void BytesToRadix52Bit(Uint64* out, const Uint64* in)
    {
        const Uint8* in_byte = reinterpret_cast<const Uint8*>(in);
        for (Uint64 i = 0; i < 38; i += 2) {
            out[i] = GetRadix52Bit(*(reinterpret_cast<const Uint64*>(in_byte)));
            out[i + 1] = GetRadix52Bit(
                (*(reinterpret_cast<const Uint64*>(in_byte + 6))) >> 4);
            in_byte += 13;
        }

        out[38] = GetRadix52Bit(*(reinterpret_cast<const Uint64*>(in_byte)));

        out[39] = (*(in_byte + 6) >> 4) + (*(in_byte + 7) << 4)
                  + (*(in_byte + 8) << 12);
    }

    static inline void Radix52BitToBytes(Uint64* out, const Uint64* in)
    {
        Uint8* out_byte = reinterpret_cast<Uint8*>(out);
        for (Uint64 i = 0; i < 39; i += 2) {
            *(reinterpret_cast<Uint64*>(out_byte)) = in[i];
            out_byte += 6;
            *(reinterpret_cast<Uint64*>(out_byte)) ^= (in[i + 1] << 4);
            out_byte += 7;
        }
    }

    static inline void AMM2048(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg[num_reg];
        __m512i mod_reg[num_reg];
        __m512i res_reg[num_reg]{};

        for (Uint64 i = 0; i < num_reg; i++) {
            first_reg[i] = _mm512_loadu_si512(first + i * 8);
            mod_reg[i]   = _mm512_loadu_si512(mod + i * 8);
        }

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {
            __m512i second_reg = _mm512_set1_epi64(second[i]);

            for (Uint64 j = 0; j < num_reg; j++) {
                res_reg[j] =
                    _mm512_madd52lo_epu64(res_reg[j], first_reg[j], second_reg);
            }

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg[0]));

            Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);
            for (Uint64 j = 0; j < num_reg; j++) {
                res_reg[j] =
                    _mm512_madd52lo_epu64(res_reg[j], mod_reg[j], y_reg);
            }

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg[0], 52);
            res_reg[0]    = _mm512_alignr_epi64(res_reg[1], res_reg[0], 1);
            res_reg[0]    = _mm512_add_epi64(res_reg[0], carry);
            res_reg[1]    = _mm512_alignr_epi64(res_reg[2], res_reg[1], 1);
            res_reg[2]    = _mm512_alignr_epi64(res_reg[3], res_reg[2], 1);
            res_reg[3]    = _mm512_alignr_epi64(res_reg[4], res_reg[3], 1);
            res_reg[4]    = _mm512_alignr_epi64(zero, res_reg[4], 1);

            for (Uint64 j = 0; j < num_reg; j++) {
                res_reg[j] =
                    _mm512_madd52hi_epu64(res_reg[j], first_reg[j], second_reg);
            }

            for (Uint64 j = 0; j < num_reg; j++) {
                res_reg[j] =
                    _mm512_madd52hi_epu64(res_reg[j], mod_reg[j], y_reg);
            }
        }

        for (Uint64 i = 0; i < num_reg; i++) {
            _mm512_storeu_si512(res + i * 8, res_reg[i]);
        }

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    // Todo: Adding the AMS2048 version
    static inline void AMMAndAMS2048(
        Uint64* res, Uint64* mult, Uint64* mod, Uint64 k0, Uint64 val)
    {
        AMM2048(res, res, res, mod, k0);
        if (val & mont::one_msb) {
            AMM2048(res, res, mult, mod, k0);
        }
    }

    template<>
    inline void mont::MontCompute<KEY_SIZE_2048>::MontgomeryExp(
        Uint64*       res,
        const Uint64* input,
        Uint64*       exp,
        Uint64        expSize,
        Uint64*       mod,
        Uint64*       r2,
        Uint64        k0)
    {

        alignas(64) Uint64 mod_radix_52_bit[40];
        alignas(64) Uint64 r2_radix_52_bit[40];
        alignas(64) Uint64 input_radix_52_bit[40];
        alignas(64) Uint64 res_radix_52_bit[40];
        // 2^(4n-km) in radix 52
        alignas(64) const Uint64 mult[40] = { 0x00, 0x00, 0x1000000 };

        BytesToRadix52Bit(mod_radix_52_bit, mod);
        BytesToRadix52Bit(r2_radix_52_bit, r2);
        BytesToRadix52Bit(input_radix_52_bit, input);

        //(congruent to 2^(4n-k×m) mod M)
        AMM2048(r2_radix_52_bit,
                r2_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                k0);

        //(congruent to 2^2k×m mod M)
        AMM2048(r2_radix_52_bit, r2_radix_52_bit, mult, mod_radix_52_bit, k0);

        // conversion to mont domain by multiplying with mont converter
        AMM2048(input_radix_52_bit,
                input_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                k0);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        // Uint64* mult = res + KEY_SIZE_2048 / 64;

        alcp::utils::CopyChunk(res_radix_52_bit, input_radix_52_bit, 40 * 8);

        while (index++ < 64) {
            AMMAndAMS2048(res_radix_52_bit,
                          input_radix_52_bit,
                          mod_radix_52_bit,
                          k0,
                          val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                AMMAndAMS2048(res_radix_52_bit,
                              input_radix_52_bit,
                              mod_radix_52_bit,
                              k0,
                              val);
                val <<= 1;
            }
        }

        alcp::utils::PadBlock(r2_radix_52_bit, 0, 40 * 8);
        r2_radix_52_bit[0] = 1;
        // convert from mont domain to residue domain
        // Todo : check if it can be converted to reduce
        AMM2048(input_radix_52_bit,
                res_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                k0);
        Radix52BitToBytes(res, input_radix_52_bit);
    }

    template void archEncryptPublic<KEY_SIZE_1024>(Uint8*        pEncText,
                                                   const Uint64* pTextBignum,
                                                   RsaPublicKeyBignum& pubKey,
                                                   MontContextBignum&  context);
    template void archEncryptPublic<KEY_SIZE_2048>(Uint8*        pEncText,
                                                   const Uint64* pTextBignum,
                                                   RsaPublicKeyBignum& pubKey,
                                                   MontContextBignum&  context);

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
