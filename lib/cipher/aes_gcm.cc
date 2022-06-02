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

#include "cipher/aes.hh"
#include "cipher/aesni.hh"
#include "cipher/vaes.hh"
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher {

alc_error_t
Gcm::decrypt(const uint8_t* pInput,
             uint8_t*       pOutput,
             uint64_t       len,
             const uint8_t* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Gcm::encrypt(const uint8_t* pInput,
             uint8_t*       pOutput,
             uint64_t       len,
             const uint8_t* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Gcm::cryptUpdate(const uint8_t* pInput,
                 uint8_t*       pOutput,
                 uint64_t       len,
                 const uint8_t* pIv,
                 bool           isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;

    /*  Follow in Gcm:
     *  InitGcm -> processAdditionalDataGcm ->CryptGcm-> GetTagGcm */
    if (Cipher::isAesniAvailable()) {
        // gcm init, both input and output pointers are NULL
        if ((pInput == NULL) && (pOutput == NULL)) {
            // GCM init call
            // len is used as ivlen
            // In init call, we generate HashSubKey, partial tag data.
            m_gHash_128         = _mm_setzero_si128();
            m_hash_subKey_128   = _mm_setzero_si128();
            m_len               = 0;
            m_additionalDataLen = 0;
            m_tagLen            = 0;
            m_ivLen             = 12; // default 12 bytes or 96bits

            m_ivLen = len;
            err     = aesni::InitGcm(getEncryptKeys(),
                                 getRounds(),
                                 pIv,
                                 m_ivLen,
                                 &m_hash_subKey_128,
                                 &m_tag_128,
                                 &m_iv_128,
                                 m_reverse_mask_128);
        } else if ((pInput != NULL) && (pOutput == NULL)) {
            // additional data processing, when input is additional data &
            // output is NULL
            const uint8_t* pAdditionalData = pInput;
            m_additionalDataLen            = len;

            // Additional data call
            err = aesni::processAdditionalDataGcm(pAdditionalData,
                                                  m_additionalDataLen,
                                                  &m_gHash_128,
                                                  m_hash_subKey_128,
                                                  m_reverse_mask_128);
        } else if ((pInput != NULL) && (pOutput != NULL)) {
            // CTR encrypt and Hash
            const uint8_t* pPlainText  = pInput;
            uint8_t*       pCipherText = pOutput;
            m_len                      = len;

            // Encrypt call
            err = aesni::CryptGcm(pPlainText,
                                  pCipherText,
                                  m_len,
                                  getEncryptKeys(),
                                  getRounds(),
                                  pIv,
                                  &m_gHash_128,
                                  m_hash_subKey_128,
                                  m_iv_128,
                                  m_reverse_mask_128,
                                  isEncrypt);

        } else if ((pInput == NULL) && (pOutput != NULL)) {
            // Get tag info, when Output is not Null and Input is Null.
            uint8_t* ptag = pOutput;
            err           = aesni::GetTagGcm(m_len,
                                   m_additionalDataLen,
                                   &m_gHash_128,
                                   &m_tag_128,
                                   m_hash_subKey_128,
                                   m_reverse_mask_128,
                                   ptag);
        }
        return err;
    }

    return err;
}

alc_error_t
Gcm::decryptUpdate(const uint8_t* pInput,
                   uint8_t*       pOutput,
                   uint64_t       len,
                   const uint8_t* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, false);
    return err;
}

alc_error_t
Gcm::encryptUpdate(const uint8_t* pInput,
                   uint8_t*       pOutput,
                   uint64_t       len,
                   const uint8_t* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, true);
    return err;
}

} // namespace alcp::cipher
