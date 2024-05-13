/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "avx2.hh"
#include <cstdint>
#include <immintrin.h>

namespace alcp::cipher { namespace aesni {

    template<
        void AesEnc_1x128(__m128i* pBlk0, const __m128i* pKey, int nRounds),
        void AesEnc_2x128(
            __m128i* pBlk0, __m128i* pBlk1, const __m128i* pKey, int nRounds),
        void AesEnc_4x128(__m128i*       pBlk0,
                          __m128i*       pBlk1,
                          __m128i*       pBlk2,
                          __m128i*       pBlk3,
                          const __m128i* pKey,
                          int            nRounds)>
    alc_error_t inline DecryptCfb(const Uint8* pSrc,
                                  Uint8*       pDest,
                                  Uint64       len,
                                  const Uint8* pKey,
                                  int          nRounds,
                                  Uint8*       pIv)
    {
        alc_error_t err       = ALC_ERROR_NONE;
        auto        p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto        p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto        p_dest128 = reinterpret_cast<__m128i*>(pDest);

        __m128i iv128 = _mm_loadu_si128((const __m128i*)pIv);

        Uint64 blocks = len / Rijndael::cBlockSize;

        for (; blocks >= 4; blocks -= 4) {
            __m128i blk0 = iv128; // CipherText Feedback
            __m128i blk1 = _mm_loadu_si128(p_src128 + 0);
            __m128i blk2 = _mm_loadu_si128(p_src128 + 1);
            __m128i blk3 = _mm_loadu_si128(p_src128 + 2);
            iv128        = _mm_loadu_si128(p_src128 + 3);

            AesEnc_4x128(&blk0, &blk1, &blk2, &blk3, p_key128, nRounds);

            blk0 = _mm_xor_si128(blk0, _mm_loadu_si128(p_src128 + 0));
            blk1 = _mm_xor_si128(blk1, _mm_loadu_si128(p_src128 + 1));
            blk2 = _mm_xor_si128(blk2, _mm_loadu_si128(p_src128 + 2));
            blk3 = _mm_xor_si128(blk3, iv128);

            _mm_storeu_si128(p_dest128 + 0, blk0);
            _mm_storeu_si128(p_dest128 + 1, blk1);
            _mm_storeu_si128(p_dest128 + 2, blk2);
            _mm_storeu_si128(p_dest128 + 3, blk3);

            p_src128 += 4;
            p_dest128 += 4;
        }

        if (blocks >= 2) {
            __m128i blk0 = iv128; // CipherText Feedback
            __m128i blk1 = _mm_loadu_si128(p_src128 + 0);
            iv128        = _mm_loadu_si128(p_src128 + 1);

            AesEnc_2x128(&blk0, &blk1, p_key128, nRounds);

            blk0 = _mm_xor_si128(blk0, _mm_loadu_si128(p_src128));
            blk1 = _mm_xor_si128(blk1, iv128);

            _mm_storeu_si128(p_dest128 + 0, blk0);
            _mm_storeu_si128(p_dest128 + 1, blk1);

            p_src128 += 2;
            p_dest128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            /* Still one block left */
            __m128i blk = iv128;

            AesEnc_1x128(&blk, p_key128, nRounds);

            blk = _mm_xor_si128(blk, _mm_loadu_si128(p_src128));

            _mm_storeu_si128(p_dest128, blk);

            p_src128 += 1;
            p_dest128 += 1;
            blocks--;
        }

        // IV is no longer needed hence we can write the old ciphertext back to
        // IV
        alcp_storeu_128(reinterpret_cast<__m128i*>(pIv),
                        alcp_loadu_128(p_src128 - 1));

        assert(blocks == 0);

        return err;
    }

    template<
        void AesEnc_1x128(__m128i* pBlk0, const __m128i* pKey, int nRounds)>
    alc_error_t inline EncryptCfb(const Uint8* pSrc,
                                  Uint8*       pDest,
                                  Uint64       len,
                                  const Uint8* pKey,
                                  int          nRounds,
                                  Uint8*       pIv)
    {
        auto p_key128  = reinterpret_cast<const __m128i*>(pKey);
        auto p_src128  = reinterpret_cast<const __m128i*>(pSrc);
        auto p_dest128 = reinterpret_cast<__m128i*>(pDest);

        __m128i iv128  = _mm_loadu_si128((const __m128i*)pIv);
        Uint64  blocks = len / Rijndael::cBlockSize;

        while (blocks >= 4) {
            __m128i tmpblk = iv128;

            for (int i = 0; i < 4; i++) {
                __m128i srcblk = _mm_loadu_si128(&p_src128[i]);

                AesEnc_1x128(&tmpblk, p_key128, nRounds);
                tmpblk = _mm_xor_si128(tmpblk, srcblk);

                /* TODO: Store blocks using ERMS/FSRM or similar */
                _mm_storeu_si128(&p_dest128[i], tmpblk);
            }

            iv128 = tmpblk;

            p_src128 += 4;
            p_dest128 += 4;
            blocks -= 4;
        }

        if (blocks >= 2) {
            __m128i tmpblk = iv128;

            for (int i = 0; i < 2; i++) {
                __m128i srcblk = _mm_loadu_si128(&p_src128[i]);

                AesEnc_1x128(&tmpblk, p_key128, nRounds);
                tmpblk = _mm_xor_si128(tmpblk, srcblk);

                /* TODO: Store blocks using ERMS/FSRM or similar */
                _mm_storeu_si128(&p_dest128[i], tmpblk);
            }

            iv128 = tmpblk;

            p_src128 += 2;
            p_dest128 += 2;
            blocks -= 2;
        }

        if (blocks) {
            __m128i tmpblk = iv128;
            __m128i srcblk = _mm_loadu_si128(p_src128);

            AesEnc_1x128(&tmpblk, p_key128, nRounds);
            tmpblk = _mm_xor_si128(tmpblk, srcblk);

            /* TODO: Store blocks using ERMS/FSRM or similar */
            _mm_storeu_si128(p_dest128, tmpblk);

            iv128 = tmpblk;

            blocks--;
        }

        assert(blocks == 0);

        // IV is no longer needed hence we can write the old ciphertext back to
        // IV
        alcp_storeu_128(reinterpret_cast<__m128i*>(pIv), iv128);

        return ALC_ERROR_NONE;
    }

    ALCP_API_EXPORT
    alc_error_t EncryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return EncryptCfb<aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    ALCP_API_EXPORT
    alc_error_t EncryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return EncryptCfb<aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    ALCP_API_EXPORT
    alc_error_t EncryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return EncryptCfb<aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    // Decrypt
    ALCP_API_EXPORT
    alc_error_t DecryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<aesni::AesEncrypt,
                          aesni::AesEncrypt,
                          aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    ALCP_API_EXPORT
    alc_error_t DecryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<aesni::AesEncrypt,
                          aesni::AesEncrypt,
                          aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    ALCP_API_EXPORT
    alc_error_t DecryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<aesni::AesEncrypt,
                          aesni::AesEncrypt,
                          aesni::AesEncrypt>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }
}} // namespace alcp::cipher::aesni
