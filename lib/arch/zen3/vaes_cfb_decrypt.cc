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

#include "vaes.hh"

#include "alcp/cipher/aes.hh"
#include "alcp/types.hh"
#include "avx256.hh"

#include <immintrin.h>

namespace alcp::cipher::vaes {
template<void AesEnc_1x256(__m256i* pBlk0, const __m128i* pKey, int nRounds),
         void AesEnc_2x256(
             __m256i* pBlk0, __m256i* pBlk1, const __m128i* pKey, int nRounds),
         void AesEnc_4x256(__m256i*       pBlk0,
                           __m256i*       pBlk1,
                           __m256i*       pBlk2,
                           __m256i*       pBlk3,
                           const __m128i* pKey,
                           int            nRounds)>
alc_error_t inline DecryptCfbKernel(
    const Uint8* pCipherText, // ptr to ciphertext
    Uint8*       pPlainText,  // ptr to plaintext
    Uint64       len,         // message length in bytes
    const Uint8* pKey,        // ptr to Key
    int          nRounds,     // No. of rounds
    Uint8*       pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;

    Uint64*  p_iv64   = reinterpret_cast<Uint64*>(pIv);
    __m128i* p_key128 = (__m128i*)pKey;
    __m256i* p_ct256  = (__m256i*)pCipherText;
    __m256i* p_pt256  = (__m256i*)pPlainText;

    __m256i iv256 = _mm256_set_epi64x(0, 0, p_iv64[1], p_iv64[0]);

    Uint64 blocks = len / Rijndael::cBlockSize;
    Uint64 res    = len % Rijndael::cBlockSize;
    Uint64 chunk  = 4 * 2;

    for (; blocks >= chunk; blocks -= chunk) {
        __m256i blk0 = _mm256_loadu_si256(p_ct256);
        __m256i blk1 = _mm256_loadu_si256(p_ct256 + 1);
        __m256i blk2 = _mm256_loadu_si256(p_ct256 + 2);
        __m256i blk3 = _mm256_loadu_si256(p_ct256 + 3);

        __m256i y0 = _mm256_set_epi64x(blk0[1], blk0[0], iv256[1], iv256[0]);
        __m256i y1 = _mm256_set_epi64x(blk1[1], blk1[0], blk0[3], blk0[2]);
        __m256i y2 = _mm256_set_epi64x(blk2[1], blk2[0], blk1[3], blk1[2]);
        __m256i y3 = _mm256_set_epi64x(blk3[1], blk3[0], blk2[3], blk2[2]);

        /* y0 |= iv256; */
        /* y1 |= blk0; */
        /* y2 |= blk1; */
        /* y3 |= blk2; */

        AesEnc_4x256(&y0, &y1, &y2, &y3, p_key128, nRounds);

        // update iv256
        iv256 = _mm256_set_epi64x(0, 0, blk3[3], blk3[2]);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);
        blk2 = _mm256_xor_si256(blk2, y2);
        blk3 = _mm256_xor_si256(blk3, y3);

        _mm256_storeu_si256(p_pt256, blk0);
        _mm256_storeu_si256(p_pt256 + 1, blk1);
        _mm256_storeu_si256(p_pt256 + 2, blk2);
        _mm256_storeu_si256(p_pt256 + 3, blk3);

        p_ct256 += 4;
        p_pt256 += 4;
    }

    chunk = 2 * 2;
    if (blocks >= chunk) {
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(p_ct256);
        __m256i blk1 = _mm256_loadu_si256(p_ct256 + 1);

        __m256i y0 = _mm256_set_epi64x(blk0[1], blk0[0], iv256[1], iv256[0]);
        __m256i y1 = _mm256_set_epi64x(blk1[1], blk1[0], blk0[3], blk0[2]);

        /* y0 |= iv256; */
        /* y1 |= blk0; */

        AesEnc_2x256(&y0, &y1, p_key128, nRounds);

        // update iv256
        iv256 = _mm256_set_epi64x(0, 0, blk1[3], blk1[2]);

        blk0 = _mm256_xor_si256(blk0, y0);
        blk1 = _mm256_xor_si256(blk1, y1);

        _mm256_storeu_si256(p_pt256, blk0);
        _mm256_storeu_si256(p_pt256 + 1, blk1);

        p_ct256 += 2;
        p_pt256 += 2;

        blocks -= chunk;
    }

    /* 3/2/1 blocks left */
    if (blocks >= 2) {
        Uint64* p_iv64 = (Uint64*)p_ct256;
        // load ciphertext
        __m256i blk0 = _mm256_loadu_si256(p_ct256);

        __m256i y0 = _mm256_set_epi64x(p_iv64[1], p_iv64[0], 0, 0);

        y0 = (y0 | iv256);

        AesEnc_1x256(&y0, p_key128, nRounds);

        // update iv256
        iv256 = _mm256_set_epi64x(0, 0, blk0[3], blk0[2]);

        blk0 = _mm256_xor_si256(blk0, y0);

        _mm256_storeu_si256(p_pt256, blk0);

        p_ct256 += 1;
        p_pt256 += 1;
        blocks -= 2;
    }

    /* process single block of 128-bit */
    __m128i* p_ct128 = reinterpret_cast<__m128i*>(p_ct256);
    if (blocks) {
        Uint64* p_iv64  = (Uint64*)p_ct128;
        __m256i mask_lo = _mm256_set_epi64x(0,
                                            0,
                                            static_cast<long long>(1UL) << 63,
                                            static_cast<long long>(1UL) << 63);

        __m256i blk0 = _mm256_set_epi64x(p_iv64[1], p_iv64[0], 0, 0);
        __m256i y0   = (blk0 | iv256);

        __m256i tmpblk = _mm256_permute2x128_si256(blk0, blk0, 1);
        AesEnc_1x256(&y0, p_key128, nRounds);

        iv256 = blk0;
        blk0  = _mm256_xor_si256(tmpblk, y0);
        _mm256_maskstore_epi64((long long*)p_pt256, mask_lo, blk0);

        p_ct128 += 1;
        blocks--;
    }

    if (res) {
        __m256i blk0 = _mm256_setzero_si256();

        Uint64* p_iv64 = (Uint64*)(p_ct128 - 1);
        std::copy((Uint8*)p_iv64, ((Uint8*)p_iv64) + 16, (Uint8*)&iv256);
        std::copy((Uint8*)p_ct128, ((Uint8*)p_ct128) + res, (Uint8*)&blk0);

        // __m256i tmpblk = _mm256_permute2x128_si256(blk0, blk0, 1);
        AesEnc_1x256(&iv256, p_key128, nRounds);

        blk0 = _mm256_xor_si256(blk0, iv256);

        std::copy((Uint8*)&blk0, ((Uint8*)&blk0) + res, (Uint8*)p_pt256);
    }

#ifdef AES_MULTI_UPDATE
    // Load last CT from cache
    alcp_storeu_128(reinterpret_cast<__m256i*>(pIv),
                    alcp_loadu_128(reinterpret_cast<__m256i*>(p_ct128 - 1)));
#endif

    return err;
}
} // namespace alcp::cipher::vaes

namespace alcp::cipher {

template<CipherKeyLen T, alcp::utils::CpuCipherFeatures arch>
alc_error_t
DecryptCfb(const Uint8* pSrc,
           Uint8*       pDest,
           Uint64       len,
           const Uint8* pKey,
           int          nRounds,
           Uint8*       pIv)
{
    return alcp::cipher::vaes::DecryptCfbKernel<alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt>(
        pSrc, pDest, len, pKey, nRounds, pIv);
}

template<>
alc_error_t
DecryptCfb<alcp::cipher::CipherKeyLen::eKey128Bit,
           alcp::utils::CpuCipherFeatures::eVaes256>(const Uint8* pSrc,
                                                     Uint8*       pDest,
                                                     Uint64       len,
                                                     const Uint8* pKey,
                                                     int          nRounds,
                                                     Uint8*       pIv)
{
    return alcp::cipher::vaes::DecryptCfbKernel<alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt>(
        pSrc, pDest, len, pKey, 10, pIv);
}

template<>
alc_error_t
DecryptCfb<alcp::cipher::CipherKeyLen::eKey192Bit,
           alcp::utils::CpuCipherFeatures::eVaes256>(const Uint8* pSrc,
                                                     Uint8*       pDest,
                                                     Uint64       len,
                                                     const Uint8* pKey,
                                                     int          nRounds,
                                                     Uint8*       pIv)
{
    return alcp::cipher::vaes::DecryptCfbKernel<alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt>(
        pSrc, pDest, len, pKey, 12, pIv);
}

template<>
alc_error_t
DecryptCfb<alcp::cipher::CipherKeyLen::eKey256Bit,
           alcp::utils::CpuCipherFeatures::eVaes256>(const Uint8* pSrc,
                                                     Uint8*       pDest,
                                                     Uint64       len,
                                                     const Uint8* pKey,
                                                     int          nRounds,
                                                     Uint8*       pIv)
{
    return alcp::cipher::vaes::DecryptCfbKernel<alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt,
                                                alcp::cipher::vaes::AesEncrypt>(
        pSrc, pDest, len, pKey, 14, pIv);
}

} // namespace alcp::cipher
