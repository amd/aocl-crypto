/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include "aes_gcm.hh"

#include "alcp/utils/copy.hh"

#include <alcp/types.h>

namespace alcp::cipher {

namespace aesni {

    alc_error_t ExpandKeys(const Uint8* pUserKey,
                           Uint8*       pEncKey,
                           Uint8*       pDecKey,
                           int          nRounds);

    alc_error_t ExpandTweakKeys(const Uint8* pUserKey,
                                Uint8*       pEncKey,
                                int          nRounds);

    alc_error_t EncryptCbc128(const Uint8* pPlainText,
                              Uint8*       pCipherText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptCbc192(const Uint8* pPlainText,
                              Uint8*       pCipherText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptCbc256(const Uint8* pPlainText,
                              Uint8*       pCipherText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc128(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc192(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc256(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptOfb(const Uint8* pPlainText,
                           Uint8*       pCipherText,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           Uint8*       pIv);

    alc_error_t DecryptOfb(const Uint8* pCipherText,
                           Uint8*       pPlainText,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           Uint8*       pIv);

    alc_error_t EncryptCtr(const Uint8* pPlainText,
                           Uint8*       pCipherText,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           const Uint8* pIv);

    alc_error_t DecryptCtr(const Uint8* pCipherText,
                           Uint8*       pPlainText,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           const Uint8* pIv);

    alc_error_t DecryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptGcm(const Uint8* pInput,
                           Uint8*       pOutput,
                           Uint64       len,
                           const Uint8* pKey,
                           int          nRounds,
                           const Uint8* pIv);

    alc_error_t InitGcm(const Uint8* pKey,
                        int          nRounds,
                        const Uint8* pIv,
                        Uint64       ivBytes,
                        __m128i&     HsubKey_128,
                        __m128i&     tag_128,
                        __m128i&     iv_128,
                        __m128i      reverse_mask_128);

    alc_error_t processAdditionalDataGcm(const Uint8* pAdditionalData,
                                         Uint64       additionalDataLen,
                                         __m128i&     gHash_128,
                                         __m128i      hash_subKey_128,
                                         __m128i      reverse_mask_128);

    alc_error_t CryptGcm(const Uint8*          pInputText,  // ptr to inputText
                         Uint8*                pOutputText, // ptr to outputtext
                         Uint64                len,  // message length in bytes
                         const Uint8*          pKey, // ptr to Key
                         int                   nRounds, // No. of rounds
                         alc_gcm_local_data_t* gcmLocalData,
                         bool                  isEncrypt,
                         Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t GetTagGcm(Uint64   tagLen,
                          Uint64   plaintextLen,
                          Uint64   adLength,
                          __m128i& gHash_128,
                          __m128i& tag128,
                          __m128i  Hsubkey_128,
                          __m128i  reverse_mask_128,
                          Uint8*   tag);

    // ctr APIs for aesni
    void ctrInit(__m128i*     c1,
                 const Uint8* pIv,
                 __m128i*     one_lo,
                 __m128i*     one_x,
                 __m128i*     two_x,
                 __m128i*     three_x,
                 __m128i*     four_x,
                 __m128i*     swap_ctr);

    Uint64 ctrProcessAvx2(const Uint8*   p_in_x,
                          Uint8*         p_out_x,
                          Uint64         blocks,
                          Uint64         res,
                          const __m128i* pkey128,
                          Uint8*         pIv,
                          int            nRounds);

    void InitializeTweakBlock(const Uint8  pIv[],
                              Uint8        pTweak[],
                              const Uint8* pTweakKey,
                              int          nRounds);

    void TweakBlockCalculate(Uint8* pIv, Uint64 inc);
} // namespace aesni

namespace vaes512 {

    alc_error_t CryptCtr128(const Uint8* p_in_x,
                            Uint8*       p_out_x,
                            Uint64       len,
                            const Uint8* pKey,
                            int          nRounds,
                            Uint8*       pIv);

    alc_error_t CryptCtr192(const Uint8* p_in_x,
                            Uint8*       p_out_x,
                            Uint64       len,
                            const Uint8* pKey,
                            int          nRounds,
                            Uint8*       pIv);

    alc_error_t CryptCtr256(const Uint8* p_in_x,
                            Uint8*       p_out_x,
                            Uint64       len,
                            const Uint8* pKey,
                            int          nRounds,
                            Uint8*       pIv);

    alc_error_t DecryptCbc128(const Uint8* pSrc,    // ptr to ciphertext
                              Uint8*       pDest,   // ptr to plaintext
                              Uint64       len,     // message length in bytes
                              const Uint8* pKey,    // ptr to Key
                              int          nRounds, // No. of rounds
                              Uint8*       pIv // ptr to Initialization Vector
    );

    alc_error_t DecryptCbc192(const Uint8* pSrc,    // ptr to ciphertext
                              Uint8*       pDest,   // ptr to plaintext
                              Uint64       len,     // message length in bytes
                              const Uint8* pKey,    // ptr to Key
                              int          nRounds, // No. of rounds
                              Uint8*       pIv // ptr to Initialization Vector
    );

    alc_error_t DecryptCbc256(const Uint8* pSrc,    // ptr to ciphertext
                              Uint8*       pDest,   // ptr to plaintext
                              Uint64       len,     // message length in bytes
                              const Uint8* pKey,    // ptr to Key
                              int          nRounds, // No. of rounds
                              Uint8*       pIv // ptr to Initialization Vector
    );

    alc_error_t DecryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t encryptGcm128(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t encryptGcm192(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t encryptGcm256(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm128(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm192(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm256(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

} // namespace vaes512

namespace vaes {

    alc_error_t ExpandKeys(const Uint8* pUserKey,
                           Uint8*       pEncKey,
                           Uint8*       pDecKey,
                           int          nRounds);

    alc_error_t DecryptCfb128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb192(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCfb256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc128(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc192(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptCbc256(const Uint8* pCipherText,
                              Uint8*       pPlainText,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t EncryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts128(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t DecryptXts256(const Uint8* pSrc,
                              Uint8*       pDest,
                              Uint64       len,
                              const Uint8* pKey,
                              int          nRounds,
                              Uint8*       pIv);

    alc_error_t encryptGcm128(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t encryptGcm192(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t encryptGcm256(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,

                              Uint64* pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm128(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm192(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    alc_error_t decryptGcm256(const Uint8*          pPlainText,
                              Uint8*                pCipherText,
                              Uint64                len,
                              bool                  isFirstUpdate,
                              const Uint8*          pKey,
                              int                   nRounds,
                              alc_gcm_local_data_t* gcmLocalData,
                              Uint64*               pGcmCtxHashSubkeyTable);

    // ctr APIs for vaes
    void ctrInit(__m256i*     c1,
                 const Uint8* pIv,
                 __m256i*     onelo,
                 __m256i*     one_x,
                 __m256i*     two_x,
                 __m256i*     three_x,
                 __m256i*     four_x,
                 __m256i*     swap_ctr);

    Uint64 ctrProcessAvx256(const Uint8*   p_in_x,
                            Uint8*         p_out_x,
                            Uint64         blocks,
                            Uint64         res,
                            const __m128i* pkey128,
                            Uint8*         pIv,
                            int            nRounds);
} // namespace vaes
} // namespace alcp::cipher

#endif /* _CIPHER_WRAPPER_HH */