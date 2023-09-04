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

    constexpr Uint64 num_digit = (2048 / 52 + 1);

    static inline void AMM2048(Uint64*       res,
                               const Uint64* first,
                               const Uint64* second,
                               const Uint64* mod,
                               Uint64        k0)
    {
        __m512i first_reg_0;
        __m512i first_reg_1;
        __m512i first_reg_2;
        __m512i first_reg_3;
        __m512i first_reg_4;

        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;

        __m512i res_reg_0{};
        __m512i res_reg_1{};
        __m512i res_reg_2{};
        __m512i res_reg_3{};
        __m512i res_reg_4{};

        first_reg_0 = _mm512_loadu_si512(first);
        first_reg_1 = _mm512_loadu_si512(first + 8);
        first_reg_2 = _mm512_loadu_si512(first + 16);
        first_reg_3 = _mm512_loadu_si512(first + 24);
        first_reg_4 = _mm512_loadu_si512(first + 32);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);
        mod_reg_3 = _mm512_loadu_si512(mod + 24);
        mod_reg_4 = _mm512_loadu_si512(mod + 32);

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {
            __m512i second_reg = _mm512_set1_epi64(second[i]);

            res_reg_0 =
                _mm512_madd52lo_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52lo_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52lo_epu64(res_reg_2, first_reg_2, second_reg);
            res_reg_3 =
                _mm512_madd52lo_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52lo_epu64(res_reg_4, first_reg_4, second_reg);

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(res_reg_3, res_reg_2, 1);
            res_reg_3     = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_4     = _mm512_alignr_epi64(zero, res_reg_4, 1);

            res_reg_0 =
                _mm512_madd52hi_epu64(res_reg_0, first_reg_0, second_reg);
            res_reg_1 =
                _mm512_madd52hi_epu64(res_reg_1, first_reg_1, second_reg);
            res_reg_2 =
                _mm512_madd52hi_epu64(res_reg_2, first_reg_2, second_reg);
            res_reg_3 =
                _mm512_madd52hi_epu64(res_reg_3, first_reg_3, second_reg);
            res_reg_4 =
                _mm512_madd52hi_epu64(res_reg_4, first_reg_4, second_reg);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);
        _mm512_storeu_si512(res + 24, res_reg_3);
        _mm512_storeu_si512(res + 32, res_reg_4);

        Uint64 carry = 0;
        // convert from redundant radix 2^52 to radix 2^52
        for (Uint64 i = 0; i < 40; i++) {
            Uint64 sum = res[i] + carry;
            carry      = sum >> 52;
            res[i]     = sum & 0xfffffffffffff;
        }
    }

    static inline void AMM2048Reduce(Uint64*       res,
                                     const Uint64* first,
                                     const Uint64* mod,
                                     Uint64        k0)
    {
        __m512i mod_reg_0;
        __m512i mod_reg_1;
        __m512i mod_reg_2;
        __m512i mod_reg_3;
        __m512i mod_reg_4;

        __m512i res_reg_0 = _mm512_loadu_si512(first);
        __m512i res_reg_1 = _mm512_loadu_si512(first + 8);
        __m512i res_reg_2 = _mm512_loadu_si512(first + 16);
        __m512i res_reg_3 = _mm512_loadu_si512(first + 24);
        __m512i res_reg_4 = _mm512_loadu_si512(first + 32);

        mod_reg_0 = _mm512_loadu_si512(mod);
        mod_reg_1 = _mm512_loadu_si512(mod + 8);
        mod_reg_2 = _mm512_loadu_si512(mod + 16);
        mod_reg_3 = _mm512_loadu_si512(mod + 24);
        mod_reg_4 = _mm512_loadu_si512(mod + 32);

        const __m512i zero{};

        for (Uint64 i = 0; i < num_digit; i++) {

            Uint64 x0 = _mm_cvtsi128_si64(_mm512_castsi512_si128(res_reg_0));

            Uint64 y0 = (k0 * (x0 & 0xfffffffffffff)) & 0xfffffffffffff;

            __m512i y_reg = _mm512_set1_epi64(y0);

            res_reg_0 = _mm512_madd52lo_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52lo_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52lo_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52lo_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52lo_epu64(res_reg_4, mod_reg_4, y_reg);

            __m512i carry = _mm512_maskz_srli_epi64(1, res_reg_0, 52);
            res_reg_0     = _mm512_alignr_epi64(res_reg_1, res_reg_0, 1);
            res_reg_0     = _mm512_add_epi64(res_reg_0, carry);
            res_reg_1     = _mm512_alignr_epi64(res_reg_2, res_reg_1, 1);
            res_reg_2     = _mm512_alignr_epi64(res_reg_3, res_reg_2, 1);
            res_reg_3     = _mm512_alignr_epi64(res_reg_4, res_reg_3, 1);
            res_reg_4     = _mm512_alignr_epi64(zero, res_reg_4, 1);

            res_reg_0 = _mm512_madd52hi_epu64(res_reg_0, mod_reg_0, y_reg);
            res_reg_1 = _mm512_madd52hi_epu64(res_reg_1, mod_reg_1, y_reg);
            res_reg_2 = _mm512_madd52hi_epu64(res_reg_2, mod_reg_2, y_reg);
            res_reg_3 = _mm512_madd52hi_epu64(res_reg_3, mod_reg_3, y_reg);
            res_reg_4 = _mm512_madd52hi_epu64(res_reg_4, mod_reg_4, y_reg);
        }

        _mm512_storeu_si512(res, res_reg_0);
        _mm512_storeu_si512(res + 8, res_reg_1);
        _mm512_storeu_si512(res + 16, res_reg_2);
        _mm512_storeu_si512(res + 24, res_reg_3);
        _mm512_storeu_si512(res + 32, res_reg_4);

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

        BytesToRadix52Bit(mod_radix_52_bit, mod);
        BytesToRadix52Bit(r2_radix_52_bit, r2);

        //(congruent to 2^(4n-k×m) mod M)
        AMM2048(r2_radix_52_bit,
                r2_radix_52_bit,
                r2_radix_52_bit,
                mod_radix_52_bit,
                context.m_k0);
        // 2^(4n-km) in radix 52
        alignas(64) const Uint64 mult[40] = { 0x00, 0x00, 0x1000000 };

        //(congruent to 2^2k×m mod M)
        AMM2048(r2_radix_52_bit,
                r2_radix_52_bit,
                mult,
                mod_radix_52_bit,
                context.m_k0);
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
        BytesToRadix52Bit(input_radix_52_bit, input);

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

        AMM2048Reduce(
            input_radix_52_bit, res_radix_52_bit, mod_radix_52_bit, k0);

        Radix52BitToBytes(res, input_radix_52_bit);
    }

    template void archEncryptPublic<KEY_SIZE_1024>(Uint8*        pEncText,
                                                   const Uint64* pTextBignum,
                                                   RsaPublicKeyBignum& pubKey,
                                                   MontContextBignum&  context);

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
