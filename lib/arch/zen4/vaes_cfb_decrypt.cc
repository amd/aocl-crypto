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

#include <cstdint>

#include <immintrin.h>

#include "alcp/cipher/aesni.hh"
#include "avx512.hh"
#include "vaes_avx512.hh"
#include "vaes_avx512_core.hh"

namespace alcp::cipher { namespace vaes512 {

    template<
        void AesEncNoLoad_1x512(__m512i& a, const sKeys& keys),
        void AesEncNoLoad_2x512(__m512i& a, __m512i& b, const sKeys& keys),
        void AesEncNoLoad_4x512(
            __m512i& a, __m512i& b, __m512i& c, __m512i& d, const sKeys& keys),
        void alcp_load_key_zmm(const __m128i pkey128[], sKeys& keys),
        void alcp_clear_keys_zmm(sKeys& keys)>
    inline alc_error_t DecryptCfb(const Uint8* pSrc,
                                  Uint8*       pDest,
                                  Uint64       len,
                                  const Uint8* pKey,
                                  int          nRounds,
                                  Uint8*       pIv)
    {
        alc_error_t err    = ALC_ERROR_NONE;
        Uint64      blocks = len / Rijndael::cBlockSize;
        Uint64      res    = len % Rijndael::cBlockSize;

        auto pkey128  = reinterpret_cast<const __m128i*>(pKey);
        auto pa_128   = reinterpret_cast<const __m128i*>(pSrc);
        auto pb_128   = pa_128;
        auto pOut_512 = reinterpret_cast<__m512i*>(pDest);

        __m512i a1, a2, a3, a4;
        __m512i b1, b2, b3, b4;
        //__m512i _a1;

        sKeys keys;
        alcp_load_key_zmm(pkey128, keys);

        Int32 isIvUsed = 0;

        if (blocks >= 4) {
            // Load IV into b1 to process 1st block.
            b1          = alcp_loadu_128((const __m512i*)pIv);
            b2          = _mm512_loadu_si512(pb_128);
            __m512i idx = _mm512_set_epi64(5, 4, 3, 2, 1, 0, 0, 0);
            b2          = _mm512_permutexvar_epi64(idx, b2);
            b1 = _mm512_mask_blend_epi64(252, b1, b2); // pack iv and b2

            for (; blocks >= 16; blocks -= 16) {
                if (isIvUsed) {
                    b1 = _mm512_loadu_si512(pb_128);
                    pb_128 += 4;
                } else {
                    pb_128 += 3;
                }
                isIvUsed = 1;

                a1 = _mm512_loadu_si512(pa_128);
                a2 = _mm512_loadu_si512(pa_128 + 4);
                a3 = _mm512_loadu_si512(pa_128 + 8);
                a4 = _mm512_loadu_si512(pa_128 + 12);

                b2 = _mm512_loadu_si512(pb_128);
                b3 = _mm512_loadu_si512(pb_128 + 4);
                b4 = _mm512_loadu_si512(pb_128 + 8);
                pb_128 += 12;

                AesEncNoLoad_4x512(b1, b2, b3, b4, keys);
                a1 = alcp_xor(a1, b1);
                a2 = alcp_xor(a2, b2);
                a3 = alcp_xor(a3, b3);
                a4 = alcp_xor(a4, b4);

                // Store decrypted blocks.
                alcp_storeu(pOut_512, a1);
                alcp_storeu(pOut_512 + 1, a2);
                alcp_storeu(pOut_512 + 2, a3);
                alcp_storeu(pOut_512 + 3, a4);

                pa_128 += 16;
                pOut_512 += 4;
            }

            if (blocks) {

                if (blocks >= 8) {
                    if (isIvUsed) {
                        b1 = _mm512_loadu_si512(pb_128);
                        pb_128 += 4;
                    } else {
                        pb_128 += 3;
                    }
                    isIvUsed = 1;

                    a1 = _mm512_loadu_si512(pa_128);
                    a2 = _mm512_loadu_si512(pa_128 + 4);
                    b2 = _mm512_loadu_si512(pb_128);
                    pb_128 += 4;
                    AesEncNoLoad_2x512(b1, b2, keys);
                    a1 = alcp_xor(a1, b1);
                    a2 = alcp_xor(a2, b2);
                    alcp_storeu(pOut_512, a1);
                    alcp_storeu(pOut_512 + 1, a2);

                    pa_128 += 8;
                    pOut_512 += 2;
                    blocks -= 8;
                }

                if (blocks >= 4) {
                    if (isIvUsed) {
                        b1 = _mm512_loadu_si512(pb_128);
                        pb_128 += 4;
                    } else {
                        pb_128 += 3;
                    }
                    isIvUsed = 1;
                    a1       = _mm512_loadu_si512(pa_128);
                    AesEncNoLoad_1x512(b1, keys);
                    a1 = alcp_xor(a1, b1);
                    alcp_storeu(pOut_512, a1);

                    pa_128 += 4;
                    pOut_512 += 1;
                    blocks -= 4;
                }

                auto p_out_128 = reinterpret_cast<__m128i*>(pOut_512);
                for (; blocks != 0; blocks--) {
                    a1 = alcp_loadu_128((const __m512i*)pa_128);
                    if (isIvUsed) {
                        b1 = alcp_loadu_128((__m512i*)(pb_128));
                    }
                    pb_128 += 1;
                    isIvUsed = 1;

                    AesEncNoLoad_1x512(b1, keys);

                    a1 = alcp_xor(a1, b1);
                    alcp_storeu_128((__m512i*)p_out_128, a1);

                    pa_128++;
                    p_out_128++;
                }
                // Update back the initial pointer
                pOut_512 = reinterpret_cast<__m512i*>(p_out_128);
            }
        } else {
            b1             = alcp_loadu_128((const __m512i*)pIv);
            auto p_out_128 = reinterpret_cast<__m128i*>(pOut_512);
            for (; blocks != 0; blocks--) {
                if (isIvUsed) {
                    b1 = alcp_loadu_128((__m512i*)pb_128);
                    pb_128++;
                }
                isIvUsed = 1;

                a1 = alcp_loadu_128((const __m512i*)pa_128);
                AesEncNoLoad_1x512(b1, keys);
                a1 = alcp_xor(a1, b1);
                alcp_storeu_128((__m512i*)p_out_128, a1);
                pa_128++;
                p_out_128++;
            }
            // Update back the initial pointer
            pOut_512 = reinterpret_cast<__m512i*>(p_out_128);
        }

        if (res) {
            // FIXME: To be merged into
            b1             = alcp_loadu_128((const __m512i*)pIv);
            auto p_out_128 = reinterpret_cast<__m128i*>(pOut_512);

            if (isIvUsed) {
                b1 = alcp_loadu_128((__m512i*)pb_128);
                pb_128++;
            }
            isIvUsed = 1;

            a1 = _mm512_setzero_si512();
            // Create mask to load bytes
            Uint64 mask = 0xFFFF >> (16 - res);
            // Mask load bytes
            a1 = _mm512_mask_loadu_epi8(a1, mask, (const __m512i*)pa_128);

            AesEncNoLoad_1x512(b1, keys);

            a1 = alcp_xor(a1, b1);

            _mm512_mask_storeu_epi8((__m512i*)p_out_128, mask, a1);
            // p_in_128++;
            // p_out_128++;
        }

#ifdef AES_MULTI_UPDATE
        // Store nth ciphertext to iv
        alcp_storeu_128(reinterpret_cast<__m512i*>(pIv),
                        alcp_loadu_128(((const __m512i*)(pa_128 - 1))));
#endif

        // clear all keys in registers.
        alcp_clear_keys_zmm(keys);

        assert(blocks == 0);

        return err;
    }

    alc_error_t DecryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<AesEncryptNoLoad_1x512Rounds10,
                          AesEncryptNoLoad_2x512Rounds10,
                          AesEncryptNoLoad_4x512Rounds10,
                          alcp_load_key_zmm_10rounds,
                          alcp_clear_keys_zmm_10rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    alc_error_t DecryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<AesEncryptNoLoad_1x512Rounds12,
                          AesEncryptNoLoad_2x512Rounds12,
                          AesEncryptNoLoad_4x512Rounds12,
                          alcp_load_key_zmm_12rounds,
                          alcp_clear_keys_zmm_12rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }

    alc_error_t DecryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv)
    {
        return DecryptCfb<AesEncryptNoLoad_1x512Rounds14,
                          AesEncryptNoLoad_2x512Rounds14,
                          AesEncryptNoLoad_4x512Rounds14,
                          alcp_load_key_zmm_14rounds,
                          alcp_clear_keys_zmm_14rounds>(
            pSrc, pDest, len, pKey, nRounds, pIv);
    }
}} // namespace alcp::cipher::vaes512
