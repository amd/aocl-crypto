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

    static inline void LoadRadix52Buffer(const Uint64* buff, __m512i reg[5])
    {
        for (Uint64 i = 0; i < 5; i++) {
            reg[i] = _mm512_load_si512(buff);
            buff += 64;
        }
    }

    static inline void MontMultAVX512(Uint64*       res,
                                      const Uint64* first,
                                      const Uint64* second,
                                      const Uint64* mod,
                                      Uint64        k0)
    {
        __m512i reg_first[5];
        __m512i reg_second[5];
        __m512i reg_mod[5];

        LoadRadix52Buffer(first, reg_first);
        LoadRadix52Buffer(mod, reg_mod);

        // MontMult2048(res, first, second, mod, k0);
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
        BytesToRadix52Bit(mod_radix_52_bit, mod);
        BytesToRadix52Bit(r2_radix_52_bit, r2);

        // conversion to mont domain by multiplying with mont converter
        MontMultAVX512(res, input, r2, mod, k0);

        Uint64 val = exp[expSize - 1];

        Uint64 num_leading_zero = _lzcnt_u64(val);

        Uint64 index = num_leading_zero + 1;

        val = val << index;

        Uint64* mult = res + KEY_SIZE_2048 / 64;

        alcp::utils::CopyChunk(mult, res, KEY_SIZE_2048 / 8);

        while (index++ < 64) {
            MultAndSquare(res, mult, mod, k0, val);
            val <<= 1;
        }

        for (Int64 i = expSize - 2; i >= 0; i--) {
            val = exp[i];
            UNROLL_64
            for (Uint64 j = 0; j < 64; j++) {
                MultAndSquare(res, mult, mod, k0, val);
                val <<= 1;
            }
        }

        // convert from mont domain to residue domain

        alcp::utils::CopyChunk(mult, res, KEY_SIZE_2048 / 8);

        MontReduce(res, mult, mod, k0);
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
