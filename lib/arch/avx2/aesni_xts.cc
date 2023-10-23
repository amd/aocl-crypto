/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
    inline alc_error_t EncryptXts(const Uint8* pSrc,
                                  Uint8*       pDest,
                                  Uint64       len,
                                  const Uint8* pKey,
                                  const Uint8* pTweakKey,
                                  int          nRounds,
                                  Uint8*       pIv)
    {
        auto p_key128 = reinterpret_cast<const __m128i*>(pKey);
        // auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
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

            // Calulating Aplha for the next 4 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_3 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_4 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = (current_alpha_1 ^ p_src128[0]);
            __m128i tweaked_src_text_2 = (current_alpha_2 ^ p_src128[1]);
            __m128i tweaked_src_text_3 = (current_alpha_3 ^ p_src128[2]);
            __m128i tweaked_src_text_4 = (current_alpha_4 ^ p_src128[3]);

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

            // Calulating Aplha for the next 4 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ p_src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ p_src128[1];

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
            __m128i tweaked_src_text = current_alpha ^ p_src128[0];
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

        _mm_store_si128(p_iv128, current_alpha);
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
    inline alc_error_t DecryptXts(const Uint8* pSrc,
                                  Uint8*       pDest,
                                  Uint64       len,
                                  const Uint8* pKey,
                                  const Uint8* pTweakKey,
                                  int          nRounds,
                                  Uint8*       pIv)
    {
        auto p_key128 = reinterpret_cast<const __m128i*>(pKey);
        // auto p_tweak_key128 = reinterpret_cast<const __m128i*>(pTweakKey);
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
            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ p_src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ p_src128[1];
            __m128i tweaked_src_text_3 = current_alpha_3 ^ p_src128[2];
            __m128i tweaked_src_text_4 = current_alpha_4 ^ p_src128[3];

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

            // Calulating Aplha for the next 2 blocks
            __m128i current_alpha_1 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);
            __m128i current_alpha_2 = current_alpha;
            aes::MultiplyAlphaByTwo(current_alpha);

            if (blocks == 2 && last_Round_Byte) {
                last_tweak      = current_alpha_2;
                current_alpha_2 = current_alpha;
            }

            // getting Tweaked Text after xor of message and Alpha ^ j
            __m128i tweaked_src_text_1 = current_alpha_1 ^ p_src128[0];
            __m128i tweaked_src_text_2 = current_alpha_2 ^ p_src128[1];

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
            __m128i tweaked_src_text = current_alpha ^ p_src128[0];
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

        _mm_store_si128(p_iv128, current_alpha);

        return ALC_ERROR_NONE;
    }

    ALCP_API_EXPORT Status InitializeTweakBlock(Uint8        pTweak[],
                                                const Uint8* pTweakKey,
                                                int          nRounds)
    {
        Status s = StatusOk();
        // IV
        __m128i init_vect =
            _mm_load_si128(reinterpret_cast<const __m128i*>(pTweak));

        AesEncrypt(
            &init_vect, reinterpret_cast<const __m128i*>(pTweakKey), nRounds);

        _mm_store_si128(reinterpret_cast<__m128i*>(pTweak), init_vect);

        return s;
    }

    ALCP_API_EXPORT
    alc_error_t EncryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              const Uint8* pTweakKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        // AesEncrypt 1Block, 2Block, 3Block, 4Block
        return EncryptXts<AesEncrypt, AesEncrypt, AesEncrypt>(
            pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
    }

    alc_error_t EncryptXts192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              const Uint8* pTweakKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        // AesEncrypt 1Block, 2Block, 3Block, 4Block
        return EncryptXts<AesEncrypt, AesEncrypt, AesEncrypt>(
            pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
    }

    alc_error_t EncryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              const Uint8* pTweakKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        // AesEncrypt 1Block, 2Block, 3Block, 4Block
        return EncryptXts<AesEncrypt, AesEncrypt, AesEncrypt>(
            pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
    }

    ALCP_API_EXPORT
    alc_error_t DecryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              const Uint8* pTweakKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptXts<AesEncrypt, AesDecrypt, AesDecrypt, AesDecrypt>(
            pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
    }

    alc_error_t DecryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              const Uint8* pTweakKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptXts<AesEncrypt, AesDecrypt, AesDecrypt, AesDecrypt>(
            pSrc, pDest, len, pKey, pTweakKey, nRounds, pIv);
    }

}} // namespace alcp::cipher::aesni
