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

#include "alcp/cipher/aes.hh"

#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

namespace alcp::cipher {

// GcmGhash common code using aesni
alc_error_t
GcmGhash::setAad(const Uint8* pInput, Uint64 aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* iv is not initialized means wrong order, we
     * will return its a bad state to call setAad*/
    if (m_cipherData.m_iv == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    // additional data processing, when input is
    // additional data & output is NULL
    const Uint8* pAdditionalData     = pInput;
    m_cipherData.m_additionalDataLen = aadLen;

    err = aesni::processAdditionalDataGcm(pAdditionalData,
                                          m_cipherData.m_additionalDataLen,
                                          m_gcm_local_data.m_gHash_128,
                                          m_gcm_local_data.m_hash_subKey_128,
                                          m_gcm_local_data.m_reverse_mask_128);

    return err;
}

// over AES init, since additional InitGcm() is required
alc_error_t
GcmGhash::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pKey != NULL && keyLen != 0) {
        err                     = setKey(pKey, keyLen);
        m_cipherData.m_isKeyset = true;
    }

    if (pIv != NULL && ivLen != 0) {
        err                    = setIv(pIv, ivLen);
        m_cipherData.m_isIvset = true;
    }

    // In init call, we generate HashSubKey, partial
    // tag data.
    if (m_cipherData.m_isIvset && m_cipherData.m_isKeyset) {
        m_gcm_local_data.m_gHash_128       = _mm_setzero_si128();
        m_gcm_local_data.m_hash_subKey_128 = _mm_setzero_si128();
        m_cipherData.m_dataLen             = 0;
        m_cipherData.m_additionalDataLen   = 0;
        m_cipherData.m_tagLen              = 0;

        err = aesni::InitGcm(m_cipherData.m_enc_key,
                             m_nrounds,
                             m_cipherData.m_iv,
                             m_cipherData.m_ivLen,
                             m_gcm_local_data.m_hash_subKey_128,
                             m_cipherData.m_tag_128,
                             m_gcm_local_data.m_counter_128,
                             m_gcm_local_data.m_reverse_mask_128);
    } else {
        return ALC_ERROR_BAD_STATE; // FIXME: better error code?
    }

    return err;
}

alc_error_t
GcmGhash::getTag(Uint8* pOutput, Uint64 tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_cipherData.m_iv == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    } else if (tagLen > 16 || tagLen == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }

    Uint8* ptag = pOutput;

    err = aesni::GetTagGcm(tagLen,
                           m_cipherData.m_dataLen,
                           m_cipherData.m_additionalDataLen,
                           m_gcm_local_data.m_gHash_128,
                           m_cipherData.m_tag_128,
                           m_gcm_local_data.m_hash_subKey_128,
                           m_gcm_local_data.m_reverse_mask_128,
                           ptag);
    if (alcp_is_error(err)) {
        printf("Error Occured\n");
    }

    return err;
}

// this wrapper to be refined further.
#define CRYPT_AEAD_WRAPPER_FUNC(                                               \
    CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, PKEY, NUM_ROUNDS)                     \
    alc_error_t CLASS_NAME::WRAPPER_FUNC(                                      \
        const Uint8* pinput, Uint8* pOutput, Uint64 len)                       \
    {                                                                          \
        alc_error_t err = ALC_ERROR_NONE;                                      \
        m_cipherData.m_dataLen += len;                                         \
        bool isFirstUpdate = false;                                            \
        if (len == m_cipherData.m_dataLen) {                                   \
            isFirstUpdate = true;                                              \
        }                                                                      \
        err = FUNC_NAME(pinput,                                                \
                        pOutput,                                               \
                        len,                                                   \
                        isFirstUpdate,                                         \
                        PKEY,                                                  \
                        NUM_ROUNDS,                                            \
                        &m_gcm_local_data,                                     \
                        &m_cipherData,                                         \
                        m_cipherData.m_gcm.m_hashSubkeyTable);                 \
        return err;                                                            \
    }

namespace vaes512 {

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD128, decryptUpdate, decryptGcm128, m_cipherData.m_enc_key, 10)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD192, decryptUpdate, decryptGcm192, m_cipherData.m_enc_key, 12)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD256, decryptUpdate, decryptGcm256, m_cipherData.m_enc_key, 14)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD128, encryptUpdate, encryptGcm128, m_cipherData.m_enc_key, 10)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD192, encryptUpdate, encryptGcm192, m_cipherData.m_enc_key, 12)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD256, encryptUpdate, encryptGcm256, m_cipherData.m_enc_key, 14)

} // namespace vaes512

namespace vaes {
    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD128, decryptUpdate, decryptGcm128, m_cipherData.m_enc_key, 10)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD192, decryptUpdate, decryptGcm192, m_cipherData.m_enc_key, 12)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD256, decryptUpdate, decryptGcm256, m_cipherData.m_enc_key, 14)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD128, encryptUpdate, encryptGcm128, m_cipherData.m_enc_key, 10)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD192, encryptUpdate, encryptGcm192, m_cipherData.m_enc_key, 12)

    CRYPT_AEAD_WRAPPER_FUNC(
        GcmAEAD256, encryptUpdate, encryptGcm256, m_cipherData.m_enc_key, 14)

} // namespace vaes

namespace aesni {

    // below code to be re-written to use CRYPT_AEAD_WRAPPER_FUNC wrapper
    // itself.

    alc_error_t GcmAEAD128::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to decryptGcm128 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       false,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to decryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       false,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::decryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to decryptGcm256 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       false,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD128::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to encryptGcm128 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       true,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD192::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to encryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       true,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

    alc_error_t GcmAEAD256::encryptUpdate(const Uint8* pInput,
                                          Uint8*       pOutput,
                                          Uint64       len)
    {
        alc_error_t err = ALC_ERROR_NONE;
        m_cipherData.m_dataLen += len;
        // to be modified to encryptGcm192 function
        err = CryptGcm(pInput,
                       pOutput,
                       len,
                       m_cipherData.m_enc_key,
                       m_nrounds,
                       &m_gcm_local_data,
                       &m_cipherData,
                       true,
                       m_cipherData.m_gcm.m_hashSubkeyTable);
        return err;
    }

} // namespace aesni
} // namespace alcp::cipher
