/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#ifndef _CIPHER_WRAPPER_HH
#define _CIPHER_WRAPPER_HH 2

#include <immintrin.h>

#include "alcp/error.h"

#include "aes.hh"

#include "utils/copy.hh"

#include <alcp/types.h>

namespace alcp::cipher {

namespace aesni {

    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey,
                           int            nRounds);

    alc_error_t ExpandTweakKeys(const uint8_t* pUserKey,
                                uint8_t*       pEncKey,
                                int            nRounds);

    alc_error_t EncryptCbc(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCbc(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptOfb(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptOfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptCtr(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCtr(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptCfb(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptGcm(const uint8_t* pInput,
                           uint8_t*       pOutput,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t InitGcm(const uint8_t* pKey,
                        int            nRounds,
                        const uint8_t* pIv,
                        uint64_t       ivBytes,
                        __m128i*       pHsubKey_128,
                        __m128i*       ptag_128,
                        __m128i*       piv_128,
                        __m128i        reverse_mask_128);
    /**
     * @brief Initializes CCM
     *
     * @param ctx - Context
     * @param t - Tag Length
     * @param q - Length required to store length of Plain text
     * @param key - Key used for encryption
     * @param block
     */

    void CcmInit(ccm_data_p ctx, unsigned int t, unsigned int q);

    int CcmSetIv(ccm_data_p ctx, const Uint8* nonce, size_t nlen, size_t mlen);

    void CcmSetAad(ccm_data_p ctx, const Uint8* aad, size_t alen);

    int CcmEncrypt(ccm_data_p ctx, const Uint8* inp, Uint8* out, size_t len);

    int CcmDecrypt(ccm_data_p ctx, const Uint8* inp, Uint8* out, size_t len);

    void ctr64_add(Uint8* counter, size_t inc);

    size_t CcmGetTag(ccm_data_p ctx, Uint8* tag, size_t len);

    alc_error_t processAdditionalDataGcm(const uint8_t* pAdditionalData,
                                         uint64_t       additionalDataLen,
                                         __m128i*       pgHash_128,
                                         __m128i        hash_subKey_128,
                                         __m128i        reverse_mask_128);

    void gcmCryptInit(__m128i* c1,
                      __m128i  iv_128,
                      __m128i* one_lo,
                      __m128i* one_x,
                      __m128i* two_x,
                      __m128i* three_x,
                      __m128i* four_x,
                      __m128i* eight_x,
                      __m128i* swap_ctr);

    alc_error_t CryptGcm(const uint8_t* pPlainText,
                         uint8_t*       pCipherText,
                         uint64_t       len,
                         const uint8_t* pKey,
                         int            nRounds,
                         const uint8_t* pIv,
                         __m128i*       pgHash,
                         __m128i        Hsubkey_128,
                         __m128i        iv_128,
                         __m128i        reverse_mask_128,
                         bool           isEncrypt);

    alc_error_t GetTagGcm(uint64_t tagLen,
                          uint64_t plaintextLen,
                          uint64_t adLength,
                          __m128i* pgHash_128,
                          __m128i* ptag128,
                          __m128i  Hsubkey_128,
                          __m128i  reverse_mask_128,
                          uint8_t* tag);

    // ctr APIs for aesni
    void ctrInit(__m128i*       c1,
                 const uint8_t* pIv,
                 __m128i*       one_lo,
                 __m128i*       one_x,
                 __m128i*       two_x,
                 __m128i*       three_x,
                 __m128i*       four_x,
                 __m128i*       eight_x,
                 __m128i*       swap_ctr);

    uint64_t ctrProcessAvx128(const Uint8*   p_in_x,
                              Uint8*         p_out_x,
                              uint64_t       blocks,
                              const __m128i* pkey128,
                              const uint8_t* pIv,
                              int            nRounds);
} // namespace aesni

namespace vaes512 {
    uint64_t ctrProcessAvx512(const Uint8*   p_in_x,
                              Uint8*         p_out_x,
                              uint64_t       blocks,
                              const __m128i* pkey128,
                              const uint8_t* pIv,
                              int            nRounds);

    alc_error_t DecryptCbcAvx512(const uint8_t* pCipherText,
                                 uint8_t*       pPlainText,
                                 uint64_t       len,
                                 const uint8_t* pKey,
                                 int            nRounds,
                                 const uint8_t* pIv);

    alc_error_t DecryptCfbAvx512(const uint8_t* pSrc,
                                 uint8_t*       pDest,
                                 uint64_t       len,
                                 const uint8_t* pKey,
                                 int            nRounds,
                                 const uint8_t* pIv);

    alc_error_t EncryptXtsAvx512(const uint8_t* pSrc,
                                 uint8_t*       pDest,
                                 uint64_t       len,
                                 const uint8_t* pKey,
                                 const uint8_t* pTweakKey,
                                 int            nRounds,
                                 const uint8_t* pIv);

    alc_error_t DecryptXtsAvx512(const uint8_t* pSrc,
                                 uint8_t*       pDest,
                                 uint64_t       len,
                                 const uint8_t* pKey,
                                 const uint8_t* pTweakKey,
                                 int            nRounds,
                                 const uint8_t* pIv);

    alc_error_t CryptGcm(const uint8_t* pPlainText,
                         uint8_t*       pCipherText,
                         uint64_t       len,
                         const uint8_t* pKey,
                         int            nRounds,
                         const uint8_t* pIv,
                         __m128i*       pgHash,
                         __m128i        Hsubkey_128,
                         __m128i        iv_128,
                         __m128i        reverse_mask_128,
                         bool           isEncrypt);

} // namespace vaes512

namespace vaes {

    alc_error_t ExpandKeys(const uint8_t* pUserKey,
                           uint8_t*       pEncKey,
                           uint8_t*       pDecKey,
                           int            nRounds);

    alc_error_t DecryptCfb(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptCbc(const uint8_t* pCipherText,
                           uint8_t*       pPlainText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptCfb(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t EncryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    alc_error_t DecryptXts(const uint8_t* pPlainText,
                           uint8_t*       pCipherText,
                           uint64_t       len,
                           const uint8_t* pKey,
                           const uint8_t* pTweakKey,
                           int            nRounds,
                           const uint8_t* pIv);

    // ctr APIs for vaes
    void ctrInit(__m256i*       c1,
                 const uint8_t* pIv,
                 __m256i*       onelo,
                 __m256i*       one_x,
                 __m256i*       two_x,
                 __m256i*       three_x,
                 __m256i*       four_x,
                 __m256i*       eight_x,
                 __m256i*       swap_ctr);

    uint64_t ctrProcessAvx256(const Uint8*   p_in_x,
                              Uint8*         p_out_x,
                              uint64_t       blocks,
                              const __m128i* pkey128,
                              const uint8_t* pIv,
                              int            nRounds);
} // namespace vaes
} // namespace alcp::cipher

#endif /* _CIPHER_WRAPPER_HH */