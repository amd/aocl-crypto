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

#include "alcp/base.hh"

#include <cstdint>
#include <immintrin.h>

#include "alcp/cipher/aesni.hh"
#include "avx512.hh"

#include "../zen3/vaes.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

namespace alcp::cipher::vaes512 {

template<void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
         void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
         void AesEncNoLoad_4x512(
             __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
         void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
         void alcp_clear_keys_zmm(sKeys& keys)>
alc_error_t inline DecryptCbc(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
{
    if (len == 0) {
        return ALC_ERROR_NONE;
    }

    // Fast path for 1-3 blocks: use 128-bit AES-NI to avoid ZMM key
    // load/clear overhead (~22-30 ZMM register ops saved per call)
    if (len < 64) {
        auto       p_in  = reinterpret_cast<const __m128i*>(pCipherText);
        auto       p_out = reinterpret_cast<__m128i*>(pPlainText);
        const auto pkey  = reinterpret_cast<const __m128i*>(pKey);
        __m128i    iv    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv));

        while (len >= 16) {
            __m128i ct = _mm_loadu_si128(p_in);
            __m128i block = ct;
            aesni::AesDecrypt(&block, pkey, nRounds);
            block = _mm_xor_si128(block, iv);
            _mm_storeu_si128(p_out, block);
            iv = ct;
            p_in++;
            p_out++;
            len -= 16;
        }

#ifdef AES_MULTI_UPDATE
        _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv), iv);
#endif
        return ALC_ERROR_NONE;
    }

    // Tier 2: VAES-256 on-the-fly for 4-8 blocks (64-128 bytes).
    // Broadcasts round keys per-round via _mm256_broadcastsi128_si256,
    // avoiding the ~22 ZMM register ops of key load/clear overhead.
    if (len <= 128) {
        auto       p_in  = reinterpret_cast<const __m128i*>(pCipherText);
        auto       p_out = reinterpret_cast<__m128i*>(pPlainText);
        const auto pkey  = reinterpret_cast<const __m128i*>(pKey);

#ifdef AES_MULTI_UPDATE
        __m128i last_ct = _mm_loadu_si128(p_in + (len / 16 - 1));
#endif

        // IV pair: [original_iv (lower 128), ct0 (upper 128)]
        __m256i iv256 = _mm256_inserti128_si256(
            _mm256_castsi128_si256(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(pIv))),
            _mm_loadu_si128(p_in),
            1);

        __m256i c1, c2;

        // 8-block batch (4 x __m256i = 128 bytes); exact match only
        if (len == 128) {
            __m256i c3, c4;
            c1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in));
            c2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in + 2));
            c3 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in + 4));
            c4 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in + 6));

            __m256i iv2 = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(p_in + 1));
            __m256i iv3 = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(p_in + 3));
            __m256i iv4 = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(p_in + 5));

            vaes::AesDecrypt(&c1, &c2, &c3, &c4, pkey, nRounds);

            c1 = _mm256_xor_si256(c1, iv256);
            c2 = _mm256_xor_si256(c2, iv2);
            c3 = _mm256_xor_si256(c3, iv3);
            c4 = _mm256_xor_si256(c4, iv4);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out), c1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out + 2), c2);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out + 4), c3);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out + 6), c4);

#ifdef AES_MULTI_UPDATE
            _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv), last_ct);
#endif
            return ALC_ERROR_NONE;
        }

        // 4-block batch (2 x __m256i = 64 bytes)
        if (len >= 64) {
            c1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in));
            c2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in + 2));
            __m256i iv2 = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(p_in + 1));

            vaes::AesDecrypt(&c1, &c2, pkey, nRounds);

            c1 = _mm256_xor_si256(c1, iv256);
            c2 = _mm256_xor_si256(c2, iv2);

            len -= 64;
            if (len >= 32) {
                iv256 = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(p_in + 3));
            } else if (len >= 16) {
                iv256 = _mm256_inserti128_si256(
                    _mm256_castsi128_si256(_mm_loadu_si128(p_in + 3)),
                    _mm_loadu_si128(p_in + 4),
                    1);
            }

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out), c1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out + 2), c2);

            p_in += 4;
            p_out += 4;
        }

        // 2-block batch (1 x __m256i = 32 bytes)
        if (len >= 32) {
            c1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p_in));

            vaes::AesDecrypt(&c1, pkey, nRounds);
            c1 = _mm256_xor_si256(c1, iv256);

            len -= 32;
            if (len >= 16) {
                iv256 = _mm256_inserti128_si256(
                    _mm256_castsi128_si256(_mm_loadu_si128(p_in + 1)),
                    _mm_loadu_si128(p_in + 2),
                    1);
            }

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p_out), c1);

            p_in += 2;
            p_out += 2;
        }

        // Remaining single block
        if (len >= 16) {
            __m128i ct    = _mm_loadu_si128(p_in);
            __m128i block = ct;
            aesni::AesDecrypt(&block, pkey, nRounds);
            block = _mm_xor_si128(block, _mm256_castsi256_si128(iv256));
            _mm_storeu_si128(p_out, block);
        }

#ifdef AES_MULTI_UPDATE
        _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv), last_ct);
#endif
        return ALC_ERROR_NONE;
    }

    // Tier 3: VAES-512 with pre-loaded ZMM keys for 9+ blocks (144+ bytes)
    auto pIn  = reinterpret_cast<const __m128i*>(pCipherText);
    auto pOut = reinterpret_cast<__m512i*>(pPlainText);

    __m512i cblock1, cblock2, cblock3, cblock4;
    __m512i iv1, iv2, iv3, iv4;

    sKeys keys{};
    alcp_load_key_zmm(reinterpret_cast<const __m128i*>(pKey), keys);

    // Initialize iv1 with IV
    iv1 = alcp_loadu_128((const __m512i*)pIv);

    // Permute index for IV packing: shift 512-bit right by 128 bits
    const __m512i cShiftIdx = _mm512_set_epi64(5, 4, 3, 2, 1, 0, 0, 0);

    // Process first 4+ blocks with special IV packing: iv1 = [IV, c0, c1, c2]
    {
        // Pack IV with first 3 ciphertext blocks
        __m512i shifted_ct = _mm512_loadu_si512(pIn);
        shifted_ct = _mm512_permutexvar_epi64(cShiftIdx, shifted_ct);
        iv1  = _mm512_mask_blend_epi64(0xFC, iv1, shifted_ct);

        // Process 16-block batches (256 bytes each)
        for (; len >= 256; len -= 256) {
            cblock1 = _mm512_loadu_si512(pIn);
            cblock2 = _mm512_loadu_si512(pIn + 4);
            cblock3 = _mm512_loadu_si512(pIn + 8);
            cblock4 = _mm512_loadu_si512(pIn + 12);

            iv2 = _mm512_loadu_si512(pIn + 3);
            iv3 = _mm512_loadu_si512(pIn + 7);
            iv4 = _mm512_loadu_si512(pIn + 11);

            AesEncNoLoad_4x512(cblock1, cblock2, cblock3, cblock4, keys);
            cblock1 = alcp_xor(cblock1, iv1);
            cblock2 = alcp_xor(cblock2, iv2);
            cblock3 = alcp_xor(cblock3, iv3);
            cblock4 = alcp_xor(cblock4, iv4);

            // Pre-load iv1 before stores (inplace-safe: input not yet
            // overwritten). Use overlapping 512-bit load when 4+ blocks
            // follow, giving [CT15, CT16, CT17, CT18] directly.
            // Otherwise 128-bit load of last block for tail path.
            if (len - 256 >= 64) {
                iv1 = _mm512_loadu_si512((__m512i*)(pIn + 15));
            } else {
                iv1 = alcp_loadu_128((__m512i*)(pIn + 15));
            }

            alcp_storeu(pOut, cblock1);
            alcp_storeu(pOut + 1, cblock2);
            alcp_storeu(pOut + 2, cblock3);
            alcp_storeu(pOut + 3, cblock4);

            pIn += 16;
            pOut += 4;
        }

        // Process 8 blocks (128 bytes)
        if (len >= 128) {
            cblock1 = _mm512_loadu_si512(pIn);
            cblock2 = _mm512_loadu_si512(pIn + 4);
            iv2 = _mm512_loadu_si512(pIn + 3);

            AesEncNoLoad_2x512(cblock1, cblock2, keys);
            cblock1 = alcp_xor(cblock1, iv1);
            cblock2 = alcp_xor(cblock2, iv2);

            len -= 128;
            if (len >= 64) {
                iv1 = _mm512_loadu_si512((__m512i*)(pIn + 7));
            } else {
                iv1 = alcp_loadu_128((__m512i*)(pIn + 7));
            }

            alcp_storeu(pOut, cblock1);
            alcp_storeu(pOut + 1, cblock2);

            pIn += 8;
            pOut += 2;
        }

        // Process 4 blocks (64 bytes)
        if (len >= 64) {
            cblock1 = _mm512_loadu_si512(pIn);

            AesEncNoLoad_1x512(cblock1, keys);
            cblock1 = alcp_xor(cblock1, iv1);

            len -= 64;

            if (__builtin_expect(len == 0, 0)) {
#ifdef AES_MULTI_UPDATE
                _mm_storeu_si128(
                    reinterpret_cast<__m128i*>(pIv),
                    _mm_loadu_si128(
                        reinterpret_cast<const __m128i*>(pIn + 3)));
#endif
                alcp_storeu(pOut, cblock1);
                alcp_clear_keys_zmm(keys);
                return ALC_ERROR_NONE;
            }

            iv1 = alcp_loadu_128((__m512i*)(pIn + 3));
            alcp_storeu(pOut, cblock1);
            pIn += 4;
            pOut += 1;
        }
    }

    // Clear ZMM keys before switching to 128-bit AES-NI for the tail
    alcp_clear_keys_zmm(keys);

    // Process remaining 1-3 blocks with 128-bit AES-NI
    auto       p_tail_in  = pIn;
    auto       p_tail_out = reinterpret_cast<__m128i*>(pOut);
    const auto pkey       = reinterpret_cast<const __m128i*>(pKey);
    __m128i    iv         = _mm512_castsi512_si128(iv1);

    while (len >= 16) {
        __m128i ct    = _mm_loadu_si128(p_tail_in);
        __m128i block = ct;
        aesni::AesDecrypt(&block, pkey, nRounds);
        block = _mm_xor_si128(block, iv);
        _mm_storeu_si128(p_tail_out, block);
        iv = ct;
        p_tail_in++;
        p_tail_out++;
        len -= 16;
    }

#ifdef AES_MULTI_UPDATE
    _mm_storeu_si128(reinterpret_cast<__m128i*>(pIv), iv);
#endif
    return ALC_ERROR_NONE;
}

} // namespace alcp::cipher::vaes512

namespace alcp::cipher {

template<alcp::cipher::CipherKeyLen T, alcp::utils::CpuArchLevel arch>
alc_error_t
tDecryptCbc(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    constexpr int nRounds = static_cast<int>(T) / 32 + 6;
    if constexpr (nRounds == 10) {
        return DecryptCbc<AesDecryptNoLoad_1x512Rounds10,
                          AesDecryptNoLoad_2x512Rounds10,
                          AesDecryptNoLoad_4x512Rounds10,
                          alcp_load_key_zmm_10rounds,
                          alcp_clear_keys_zmm_10rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    } else if constexpr (nRounds == 12) {
        return DecryptCbc<AesDecryptNoLoad_1x512Rounds12,
                          AesDecryptNoLoad_2x512Rounds12,
                          AesDecryptNoLoad_4x512Rounds12,
                          alcp_load_key_zmm_12rounds,
                          alcp_clear_keys_zmm_12rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    } else if constexpr (nRounds == 14) {
        return DecryptCbc<AesDecryptNoLoad_1x512Rounds14,
                          AesDecryptNoLoad_2x512Rounds14,
                          AesDecryptNoLoad_4x512Rounds14,
                          alcp_load_key_zmm_14rounds,
                          alcp_clear_keys_zmm_14rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    } else {
        static_assert(nRounds >= 10 && nRounds <= 14,
                      "Unsupported AES key length");
        return ALC_ERROR_NOT_PERMITTED;
    }
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey128Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds10,
                      AesDecryptNoLoad_2x512Rounds10,
                      AesDecryptNoLoad_4x512Rounds10,
                      alcp_load_key_zmm_10rounds,
                      alcp_clear_keys_zmm_10rounds>(
        pSrc, pDest, len, pKey, 10, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey192Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds12,
                      AesDecryptNoLoad_2x512Rounds12,
                      AesDecryptNoLoad_4x512Rounds12,
                      alcp_load_key_zmm_12rounds,
                      alcp_clear_keys_zmm_12rounds>(
        pSrc, pDest, len, pKey, 12, pIv);
}

template<>
alc_error_t
tDecryptCbc<alcp::cipher::CipherKeyLen::eKey256Bit,
            alcp::utils::CpuArchLevel::eZen4>(
    const Uint8* pSrc, Uint8* pDest, Uint64 len, const Uint8* pKey, Uint8* pIv)
{
    using namespace vaes512;
    return DecryptCbc<AesDecryptNoLoad_1x512Rounds14,
                      AesDecryptNoLoad_2x512Rounds14,
                      AesDecryptNoLoad_4x512Rounds14,
                      alcp_load_key_zmm_14rounds,
                      alcp_clear_keys_zmm_14rounds>(
        pSrc, pDest, len, pKey, 14, pIv);
}

} // namespace alcp::cipher
