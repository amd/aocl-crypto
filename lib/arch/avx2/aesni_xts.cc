/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aesni.hh"
#include "alcp/utils/copy.hh"
#include "cipher/avx2/aes_xts_avx2.hh"

#include <immintrin.h>

namespace alcp::cipher { namespace aesni {
    template<void AesEnc_1x128(__m128i* a, const __m128i* pKey, int nRounds),
             void AesEnc_2x128(
                 __m128i* a, __m128i* b, const __m128i* pKey, int nRounds),
             void AesEnc_4x128(__m128i*       a,
                               __m128i*       b,
                               __m128i*       c,
                               __m128i*       d,
                               const __m128i* pKey,
                               int            nRounds)>
    inline alc_error_t EncryptXtsKernel(const Uint8* pSrc,
                                        Uint8*       pDest,
                                        Uint64       len,
                                        const Uint8* pKey,
                                        int          nRounds,
                                        Uint8*       pIv)
    {
        auto p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128 = reinterpret_cast<__m128i*>(pDest);
        auto p_iv128   = reinterpret_cast<__m128i*>(pIv);

        Uint64 blocks          = len / Rijndael::cBlockSize;
        int    last_Round_Byte = len % Rijndael::cBlockSize;

#if 0
        // iv encryption using tweak key to get alpha
        __m128i current_alpha =
            _mm_loadu_si128(p_iv128); // loadu to handle unaligned memory
        AesEnc_1x128(&current_alpha, p_tweak_key128, nRounds);
#endif

        __m128i current_alpha = _mm_load_si128(p_iv128);

        // Encrypting 4 source text blocks at a time
        while (blocks >= 4) {

            __m128i src128[4];

            // Calulating Aplha for the next 4 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_3 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_4 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            src128[0] = _mm_loadu_si128(p_src128 + 0);
            src128[1] = _mm_loadu_si128(p_src128 + 1);
            src128[2] = _mm_loadu_si128(p_src128 + 2);
            src128[3] = _mm_loadu_si128(p_src128 + 3);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = (current_alpha_1 ^ src128[0]);
            __m128i tweaked_src_text_2 = (current_alpha_2 ^ src128[1]);
            __m128i tweaked_src_text_3 = (current_alpha_3 ^ src128[2]);
            __m128i tweaked_src_text_4 = (current_alpha_4 ^ src128[3]);

            AesEnc_4x128(&tweaked_src_text_1,
                         &tweaked_src_text_2,
                         &tweaked_src_text_3,
                         &tweaked_src_text_4,
                         p_key128,
                         nRounds);
            // getting Cipher Text after xor of message and Alpha ^ j
            tweaked_src_text_1 = (current_alpha_1 ^ tweaked_src_text_1);
            tweaked_src_text_2 = (current_alpha_2 ^ tweaked_src_text_2);
            tweaked_src_text_3 = (current_alpha_3 ^ tweaked_src_text_3);
            tweaked_src_text_4 = (current_alpha_4 ^ tweaked_src_text_4);

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text_1);
            _mm_storeu_si128(p_dest128 + 1, tweaked_src_text_2);
            _mm_storeu_si128(p_dest128 + 2, tweaked_src_text_3);
            _mm_storeu_si128(p_dest128 + 3, tweaked_src_text_4);

            p_dest128 += 4;
            p_src128 += 4;

            blocks -= 4;
        }

        // Encrypting 2 source text blocks at a time
        if (blocks >= 2) {

            __m128i src128[2];

            // Calulating Aplha for the next 4 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            src128[0] = _mm_loadu_si128(p_src128 + 0);
            src128[1] = _mm_loadu_si128(p_src128 + 1);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ src128[1];

            AesEnc_2x128(
                &tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);

            // getting Chiper Text after xor of message and Alpha ^ j
            tweaked_src_text_1 = current_alpha_1 ^ tweaked_src_text_1;
            tweaked_src_text_2 = current_alpha_2 ^ tweaked_src_text_2;

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text_1);
            _mm_storeu_si128(p_dest128 + 1, tweaked_src_text_2);

            p_dest128 += 2;
            p_src128 += 2;

            blocks -= 2;
        }

        // Encrypting all blocks except last 2 if extra bytes present in
        // source text
        if (blocks >= 1) {

            // Encrypting Text using EncKey
            // PP = ( Tweak xor P )
            __m128i src128           = _mm_loadu_si128(p_src128);
            __m128i tweaked_src_text = current_alpha ^ src128;
            // CC = ( aesEnc(PP) )
            AesEnc_1x128(&tweaked_src_text, p_key128, nRounds);
            // C  = ( Tweak xor CC )
            tweaked_src_text = tweaked_src_text ^ current_alpha;

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text);

            p_dest128++;
            p_src128++;

            // Increasing Aplha  for the next round
            aes::MultiplyAlphaByTwo(current_alpha);

            blocks--;
        }

        auto p_dest8 = reinterpret_cast<Uint8*>(p_dest128);
        auto p_src8  = reinterpret_cast<const Uint8*>(p_src128);

        if (last_Round_Byte) {
            // stealing bytes for (m-1)th chiper message and storing it at mth
            // destinatIon on last line of code and getting last_Message_Block
            // to be encrypted
            __m128i last_messgae_block;
            auto    p_last_messgae_block =
                reinterpret_cast<Uint8*>(&last_messgae_block);

            utils::CopyBytes(p_last_messgae_block + last_Round_Byte,
                             p_dest8 - 16 + last_Round_Byte,
                             16 - last_Round_Byte);
            utils::CopyBytes(p_last_messgae_block, p_src8, last_Round_Byte);
            // mth cipher text
            utils::CopyBytes(p_dest8, p_dest8 - 16, last_Round_Byte);

            // encrypting last message block
            last_messgae_block = current_alpha ^ last_messgae_block;
            AesEnc_1x128(&last_messgae_block, p_key128, nRounds);
            last_messgae_block = current_alpha ^ last_messgae_block;

            utils::CopyBytes((p_dest8 - 16), p_last_messgae_block, 16);
        }

#ifdef AES_MULTI_UPDATE
        _mm_store_si128(p_iv128, current_alpha);
#endif
        return ALC_ERROR_NONE;
    }

    template<void AesEnc_1x128(__m128i* a, const __m128i* pKey, int nRounds),
             void AesDec_1x128(__m128i* a, const __m128i* pKey, int nRounds),
             void AesDec_2x128(
                 __m128i* a, __m128i* b, const __m128i* pKey, int nRounds),
             void AesDec_4x128(__m128i*       a,
                               __m128i*       b,
                               __m128i*       c,
                               __m128i*       d,
                               const __m128i* pKey,
                               int            nRounds)>
    inline alc_error_t DecryptXtsKernel(const Uint8* pSrc,
                                        Uint8*       pDest,
                                        Uint64       len,
                                        const Uint8* pKey,
                                        int          nRounds,
                                        Uint8*       pIv)
    {
        auto p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128 = reinterpret_cast<__m128i*>(pDest);
        auto p_iv128   = reinterpret_cast<__m128i*>(pIv);

        Uint64 blocks          = len / Rijndael::cBlockSize;
        int    last_Round_Byte = len % Rijndael::cBlockSize;

#if 0
        // iv encryption using tweak key to get alpha
        __m128i current_alpha = _mm_loadu_si128(p_iv128),
                last_tweak    = _mm_setzero_si128();

        AesEnc_1x128(&current_alpha, p_tweak_key128, nRounds);
#endif

        __m128i current_alpha = _mm_load_si128(p_iv128),
                last_tweak    = _mm_setzero_si128();

        // Decrypting 4 cipher text blocks at a time
        while (blocks >= 4) {

            __m128i src128[4];

            // Calulating Aplha for the next 4 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_3 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_4 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            if (blocks == 4 && last_Round_Byte) {
                last_tweak      = current_alpha_4;
                current_alpha_4 = current_alpha;
            }

            src128[0] = _mm_loadu_si128(p_src128 + 0);
            src128[1] = _mm_loadu_si128(p_src128 + 1);
            src128[2] = _mm_loadu_si128(p_src128 + 2);
            src128[3] = _mm_loadu_si128(p_src128 + 3);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ src128[1];
            __m128i tweaked_src_text_3 = current_alpha_3 ^ src128[2];
            __m128i tweaked_src_text_4 = current_alpha_4 ^ src128[3];

            AesDec_4x128(&tweaked_src_text_1,
                         &tweaked_src_text_2,
                         &tweaked_src_text_3,
                         &tweaked_src_text_4,
                         p_key128,
                         nRounds);
            // getting Tweaked Text after xor of message and Alpha ^ j
            tweaked_src_text_1 = current_alpha_1 ^ tweaked_src_text_1;
            tweaked_src_text_2 = current_alpha_2 ^ tweaked_src_text_2;
            tweaked_src_text_3 = current_alpha_3 ^ tweaked_src_text_3;
            tweaked_src_text_4 = current_alpha_4 ^ tweaked_src_text_4;

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text_1);
            _mm_storeu_si128(p_dest128 + 1, tweaked_src_text_2);
            _mm_storeu_si128(p_dest128 + 2, tweaked_src_text_3);
            _mm_storeu_si128(p_dest128 + 3, tweaked_src_text_4);

            p_dest128 += 4;
            p_src128 += 4;

            blocks -= 4;
        }

        // Decrypting 2 cipher text blocks at a time
        if (blocks >= 2) {

            __m128i src128[2];

            // Calulating Aplha for the next 2 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            if (blocks == 2 && last_Round_Byte) {
                last_tweak      = current_alpha_2;
                current_alpha_2 = current_alpha;
            }

            src128[0] = _mm_loadu_si128(p_src128 + 0);
            src128[1] = _mm_loadu_si128(p_src128 + 1);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ src128[1];

            AesDec_2x128(
                &tweaked_src_text_1, &tweaked_src_text_2, p_key128, nRounds);
            // getting Tweaked Text after xor of message and Alpha ^ j
            tweaked_src_text_1 = current_alpha_1 ^ tweaked_src_text_1;
            tweaked_src_text_2 = current_alpha_2 ^ tweaked_src_text_2;

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text_1);
            _mm_storeu_si128(p_dest128 + 1, tweaked_src_text_2);

            p_dest128 += 2;
            p_src128 += 2;

            blocks -= 2;
        }

        // Decrypting all blocks except last 2 if extra bytes present in
        // source text

        if (blocks >= 1) {

            // Current block needs next to next tweak block
            if (last_Round_Byte) {
                last_tweak = current_alpha;
                aes::MultiplyAlphaByTwo(current_alpha);
            }

            // Decrypting Text using DecKey
            __m128i src128           = _mm_loadu_si128(p_src128);
            __m128i tweaked_src_text = current_alpha ^ src128;
            AesDec_1x128(&tweaked_src_text, p_key128, nRounds);
            tweaked_src_text = tweaked_src_text ^ current_alpha;

            // storing the results in destination
            _mm_storeu_si128(p_dest128, tweaked_src_text);

            p_dest128++;
            p_src128++;

            blocks--;

            // Only one complete block without partial block
            if (!(last_Round_Byte)) {
                aes::MultiplyAlphaByTwo(current_alpha);
            }
        }

        auto p_dest8 = reinterpret_cast<Uint8*>(p_dest128);
        auto p_src8  = reinterpret_cast<const Uint8*>(p_src128);
        if (last_Round_Byte) {
            // stealing bytes from (m-1)th message block and storing it at mth
            // destinatIon on last line of code and getting last message block
            // to encrypt
            __m128i last_src_text;
            auto    p_last_src_text = reinterpret_cast<Uint8*>(&last_src_text);

            utils::CopyBytes(p_dest8, p_dest8 - 16, last_Round_Byte);
            utils::CopyBytes(p_last_src_text + last_Round_Byte,
                             p_dest8 - 16 + last_Round_Byte,
                             16 - last_Round_Byte);
            utils::CopyBytes(p_last_src_text, p_src8, last_Round_Byte);

            // encrypting the last block
            last_src_text = (last_tweak ^ last_src_text);
            AesDec_1x128(&last_src_text, p_key128, nRounds);
            last_src_text = (last_tweak ^ last_src_text);

            utils::CopyBytes((p_dest8 - 16), p_last_src_text, 16);
        }

#ifdef AES_MULTI_UPDATE
        _mm_store_si128(p_iv128, current_alpha);
#endif

        return ALC_ERROR_NONE;
    }

    // GF(2^128) multiplication: a * b mod p(x),
    // where p(x) = x^128 + x^7 + x^2 + x + 1 (IEEE Std 1619-2025, Section 5.2)
    // Uses PCLMULQDQ (Karatsuba) + 3-step reduction with poly = 0x87.
    static inline __m128i GfMul128(__m128i a, __m128i b)
    {
        // Carryless multiply to get 256-bit result
        __m128i lo = _mm_clmulepi64_si128(a, b, 0x00);  // a_lo * b_lo
        __m128i hi = _mm_clmulepi64_si128(a, b, 0x11);  // a_hi * b_hi
        __m128i mid1 = _mm_clmulepi64_si128(a, b, 0x01); // a_lo * b_hi
        __m128i mid2 = _mm_clmulepi64_si128(a, b, 0x10); // a_hi * b_lo
        __m128i mid = _mm_xor_si128(mid1, mid2);

        // Combine: result = hi:lo with mid added in the middle
        __m128i mid_lo = _mm_slli_si128(mid, 8);  // shift mid left by 64 bits
        __m128i mid_hi = _mm_srli_si128(mid, 8);  // shift mid right by 64 bits
        lo = _mm_xor_si128(lo, mid_lo);
        hi = _mm_xor_si128(hi, mid_hi);

        // Now reduce 256-bit result (hi:lo) mod x^128 + x^7 + x^2 + x + 1
        // For reduction: x^128 = x^7 + x^2 + x + 1, so multiply hi by 0x87 and XOR
        __m128i poly = _mm_set_epi64x(0, 0x87);

        // Reduce hi part
        __m128i hi_reduced_lo = _mm_clmulepi64_si128(hi, poly, 0x00);
        __m128i hi_reduced_hi = _mm_clmulepi64_si128(hi, poly, 0x01);

        lo = _mm_xor_si128(lo, hi_reduced_lo);
        __m128i carry = _mm_srli_si128(hi_reduced_hi, 8);
        lo = _mm_xor_si128(lo, _mm_slli_si128(hi_reduced_hi, 8));

        // Final reduction if needed (carry from hi_reduced_hi)
        __m128i final_reduce = _mm_clmulepi64_si128(carry, poly, 0x00);
        lo = _mm_xor_si128(lo, final_reduce);

        return lo;
    }

    // Precomputed α^(2^k) for k = 0..15 in GF(2^128)
    // Polynomial: x^128 + x^7 + x^2 + x + 1 (IEEE Std 1619-2025, Section 5.2)
    // Eliminates squaring iterations in TweakBlockCalculate for inc < 2^16.
    static const __m128i alpha_powers[16] = {
        _mm_set_epi64x(0x0000000000000000, 0x0000000000000002),  // α^(2^0)  = α^1
        _mm_set_epi64x(0x0000000000000000, 0x0000000000000004),  // α^(2^1)  = α^2
        _mm_set_epi64x(0x0000000000000000, 0x0000000000000010),  // α^(2^2)  = α^4
        _mm_set_epi64x(0x0000000000000000, 0x0000000000000100),  // α^(2^3)  = α^8
        _mm_set_epi64x(0x0000000000000000, 0x0000000000010000),  // α^(2^4)  = α^16
        _mm_set_epi64x(0x0000000000000000, 0x0000000100000000),  // α^(2^5)  = α^32
        _mm_set_epi64x(0x0000000000000001, 0x0000000000000000),  // α^(2^6)  = α^64
        _mm_set_epi64x(0x0000000000000000, 0x0000000000000087),  // α^(2^7)  = α^128
        _mm_set_epi64x(0x0000000000000000, 0x0000000000004015),  // α^(2^8)  = α^256
        _mm_set_epi64x(0x0000000000000000, 0x0000000010000111),  // α^(2^9)  = α^512
        _mm_set_epi64x(0x0000000000000000, 0x0100000000010101),  // α^(2^10) = α^1024
        _mm_set_epi64x(0x0001000000000000, 0x0000000100010001),  // α^(2^11) = α^2048
        _mm_set_epi64x(0x0000008700000001, 0x0000000100000001),  // α^(2^12) = α^4096
        _mm_set_epi64x(0x000000000021caea, 0x0000000000000086),  // α^(2^13) = α^8192
        _mm_set_epi64x(0x0000000000000000, 0x00021cae93f7cfc8),  // α^(2^14) = α^16384
        _mm_set_epi64x(0x0000000401504454, 0x4105551550555040),  // α^(2^15) = α^32768
    };

    void TweakBlockCalculate(Uint8* pTweakBlock, Uint64 inc)
    {
        if (inc == 0) return;

        __m128i* pTweakBlock128 = reinterpret_cast<__m128i*>(pTweakBlock);
        __m128i  tweak = _mm_load_si128(pTweakBlock128);

        // Compute α^inc using precomputed α^(2^k) lookup table.
        // Low 16 bits use the table; any remaining high bits fall back
        // to squaring.  Most callers stay within 16 bits.
        __m128i result = _mm_set_epi64x(0, 1);       // multiplicative identity

        // Fast path: use precomputed table for the low 16 bits
        Uint64 low = inc & 0xFFFF;
        for (int i = 0; low != 0; i++, low >>= 1) {
            if (low & 1) {
                result = GfMul128(result, alpha_powers[i]);
            }
        }

        // Slow path: handle bits 16+ with binary exponentiation
        Uint64 high = inc >> 16;
        if (high) {
            // Start from α^(2^16) = (α^(2^15))^2
            __m128i alpha_power = GfMul128(alpha_powers[15], alpha_powers[15]);
            while (high > 0) {
                if (high & 1) {
                    result = GfMul128(result, alpha_power);
                }
                alpha_power = GfMul128(alpha_power, alpha_power);
                high >>= 1;
            }
        }

        // tweak = tweak * α^inc
        tweak = GfMul128(tweak, result);

        _mm_store_si128(pTweakBlock128, tweak);
    }

    void InitializeTweakBlock(const Uint8  pIv[],
                                              Uint8        pTweak[],
                                              const Uint8* pTweakKey,
                                              int          nRounds)
    {
        // IV
        __m128i init_vect = _mm_loadu_si128(reinterpret_cast<const __m128i*>(
            pIv)); // pIv from User can be unaligned

        AesEncrypt(
            &init_vect, reinterpret_cast<const __m128i*>(pTweakKey), nRounds);

        _mm_store_si128(reinterpret_cast<__m128i*>(pTweak), init_vect);
    }

    alc_error_t EncryptXts(const Uint8* pSrc,
                           Uint8*       pDest,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           Uint8*       pIv)
    {
        // AesEncrypt 1Block, 2Block, 3Block, 4Block
        return EncryptXtsKernel<AesEncrypt, AesEncrypt, AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    alc_error_t DecryptXts(const Uint8* pSrc,
                           Uint8*       pDest,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           Uint8*       pIv)
    {
        return DecryptXtsKernel<AesEncrypt, AesDecrypt, AesDecrypt, AesDecrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

}} // namespace alcp::cipher::aesni
