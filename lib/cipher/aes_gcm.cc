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

#include "alcp/cipher/aes.hh"

#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

namespace alcp::cipher {

namespace vaes512 {

    alc_error_t GcmAEAD128::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = decryptGcm128(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = decryptGcm192(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = decryptGcm256(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD128::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = encryptGcm128(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = encryptGcm192(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        err = encryptGcm256(pInput,
                            pOutput,
                            len,
                            m_len,
                            m_enc_key,
                            m_nrounds,
                            pIv,
                            this,
                            m_reverse_mask_128,
                            m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmGhash::setIv(Uint64 len, const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_iv            = pIv;
        // GCM init call
        // len is used as ivlen
        // In init call, we generate HashSubKey, partial tag data.

        if (pIv == nullptr) {
            // Len 0 is invalid so return error.
            err = ALC_ERROR_INVALID_ARG;
            return err;
        }
        m_gHash_128         = _mm_setzero_si128();
        m_hash_subKey_128   = _mm_setzero_si128();
        m_len               = 0;
        m_additionalDataLen = 0;
        m_tagLen            = 0;
        m_ivLen             = 12; // default 12 bytes or 96bits

        m_ivLen = len;
        err     = vaes512::InitGcm(m_enc_key,
                               m_nrounds,
                               pIv,
                               m_ivLen,
                               m_hash_subKey_128,
                               m_tag_128,
                               m_iv_128,
                               m_reverse_mask_128);

        return err;
    }

    alc_error_t GcmGhash::setAad(const Uint8* pInput, Uint64 len)
    {
        alc_error_t err = ALC_ERROR_NONE;

        /* iv is not initialized means wrong order, we will return its a bad
         * state to call setAad*/
        if (m_iv == nullptr) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
        // additional data processing, when input is additional data &
        // output is NULL
        const Uint8* pAdditionalData = pInput;
        m_additionalDataLen          = len;

        err = processAdditionalDataGcm(pAdditionalData,
                                       m_additionalDataLen,
                                       m_gHash_128,
                                       m_hash_subKey_128,
                                       m_reverse_mask_128);

        return err;
    }

    alc_error_t GcmGhash::getTag(Uint8* pOutput, Uint64 len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (m_iv == nullptr) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        } else if (len > 16 || len == 0) {
            err = ALC_ERROR_INVALID_SIZE;
            return err;
        }
        // else if (len > 16 || len < 12) {
        //     err = ALC_ERROR_INVALID_SIZE;
        //     return err;
        // }

        Uint8* ptag = pOutput;

        err = vaes512::GetTagGcm(len,
                                 m_len,
                                 m_additionalDataLen,
                                 m_gHash_128,
                                 m_tag_128,
                                 m_hash_subKey_128,
                                 m_reverse_mask_128,
                                 ptag);
        if (alcp_is_error(err)) {
            printf("Error Occured\n");
        }

        return err;
    }
} // namespace vaes512

namespace aesni {
    alc_error_t GcmAEAD128::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to decryptGcm128 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       false,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to decryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       false,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to decryptGcm256 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       false,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD128::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to encryptGcm128 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       true,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to encryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       true,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len,
                                          const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_len += len;
        // to be modified to encryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_enc_key,
                       m_nrounds,
                       this,
                       m_reverse_mask_128,
                       true,
                       m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmGhash::setIv(Uint64 len, const Uint8* pIv)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_iv            = pIv;
        // GCM init call
        // len is used as ivlen
        // In init call, we generate HashSubKey, partial tag data.

        if (pIv == nullptr) {
            // Len 0 is invalid so return error.
            err = ALC_ERROR_INVALID_ARG;
            return err;
        }
        m_gHash_128         = _mm_setzero_si128();
        m_hash_subKey_128   = _mm_setzero_si128();
        m_len               = 0;
        m_additionalDataLen = 0;
        m_tagLen            = 0;
        m_ivLen             = 12; // default 12 bytes or 96bits

        m_ivLen = len;

        err = InitGcm(getEncryptKeys(),
                      getRounds(),
                      pIv,
                      m_ivLen,
                      &m_hash_subKey_128,
                      &m_tag_128,
                      &m_iv_128,
                      m_reverse_mask_128);

        return err;
    }

    alc_error_t GcmGhash::setAad(const Uint8* pInput, Uint64 len)
    {
        alc_error_t err = ALC_ERROR_NONE;

        /* iv is not initialized means wrong order, we will return its a bad
         * state to call setAad*/
        if (m_iv == nullptr) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
        // additional data processing, when input is additional data &
        // output is NULL
        const Uint8* pAdditionalData = pInput;
        m_additionalDataLen          = len;

        err = processAdditionalDataGcm(pAdditionalData,
                                       m_additionalDataLen,
                                       &m_gHash_128,
                                       m_hash_subKey_128,
                                       m_reverse_mask_128);

        return err;
    }

    alc_error_t GcmGhash::getTag(Uint8* pOutput, Uint64 len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (m_iv == nullptr) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        } else if (len > 16 || len == 0) {
            err = ALC_ERROR_INVALID_SIZE;
            return err;
        }
        // else if (len > 16 || len < 12) {
        //     err = ALC_ERROR_INVALID_SIZE;
        //     return err;
        // }

        Uint8* ptag = pOutput;

        err = GetTagGcm(len,
                        m_len,
                        m_additionalDataLen,
                        &m_gHash_128,
                        &m_tag_128,
                        m_hash_subKey_128,
                        m_reverse_mask_128,
                        ptag);
        if (alcp_is_error(err)) {
            printf("Error Occured\n");
        }

        return err;
    }
} // namespace aesni
} // namespace alcp::cipher
