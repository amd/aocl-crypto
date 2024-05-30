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
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/compare.hh"
//
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

namespace alcp::cipher {
// init & finish implementation

alc_error_t
Gcm::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pKey != NULL && keyLen != 0) {
        err = setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    if (pIv != NULL && ivLen != 0) {
        err = setIv(pIv, ivLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    // In init call, we generate HashSubKey, partial
    // tag data.
    if (m_ivState_aes && m_isKeySet_aes) {
        m_gcm_local_data.m_gHash_128       = _mm_setzero_si128();
        m_gcm_local_data.m_hash_subKey_128 = _mm_setzero_si128();
        m_dataLen                          = 0;
        // printf("\n gcm init");
        err = aesni::InitGcm(m_cipher_key_data.m_enc_key,
                             m_nrounds,
                             m_pIv_aes,
                             m_ivLen_aes,
                             m_gcm_local_data.m_hash_subKey_128,
                             m_gcm_local_data.m_tag_128,
                             m_gcm_local_data.m_counter_128,
                             m_gcm_local_data.m_reverse_mask_128);
    }

    return err;
}

// authentication api implementation
alc_error_t
GcmAuth::setAad(alc_cipher_data_t* ctx, const Uint8* pInput, Uint64 aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* iv is not initialized means wrong order, we
     * will return its a bad state to call setAad*/
    if (m_pIv_aes == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    // additional data processing, when input is
    // additional data & output is NULL
    const Uint8* pAdditionalData         = pInput;
    m_gcm_local_data.m_additionalDataLen = aadLen;
#if DEBUG_PROV_GCM_INIT
    printf("\n processAad adlen %ld ", m_gcm_local_data.m_additionalDataLen);
#endif
    // printf("\n gcm aad");
    err = aesni::processAdditionalDataGcm(pAdditionalData,
                                          m_gcm_local_data.m_additionalDataLen,
                                          m_gcm_local_data.m_gHash_128,
                                          m_gcm_local_data.m_hash_subKey_128,
                                          m_gcm_local_data.m_reverse_mask_128);

    return err;
}
alc_error_t
GcmAuth::getTag(alc_cipher_data_t* ctx, Uint8* ptag, Uint64 tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_pIv_aes == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    } else if (tagLen > 16 || tagLen == 0) {
        return ALC_ERROR_INVALID_SIZE;
    }
#if DEBUG_PROV_GCM_INIT
    printf("\n getTag taglen %ld isEnc %d", tagLen, ctx->enc);
#endif

    // During decrypt, tag generated should be compared with
    // input Tag.
    Uint8 tagInput[ALCP_GCM_TAG_MAX_SIZE];
    if (!m_isEnc_aes) {
        // create a copy of input
        memcpy(tagInput, ptag, tagLen);
    }

    err = aesni::GetTagGcm(tagLen,
                           m_dataLen,
                           m_gcm_local_data.m_additionalDataLen,
                           m_gcm_local_data.m_gHash_128,
                           m_gcm_local_data.m_tag_128,
                           m_gcm_local_data.m_hash_subKey_128,
                           m_gcm_local_data.m_reverse_mask_128,
                           ptag);

    // During decrypt, tag generated should be compared with
    // input Tag.
    if (!m_isEnc_aes) {
        if (utils::CompareConstTime(ptag, tagInput, tagLen) == 0) {
            // printf("\n Error: Tag mismatch");
            // clear data
            memset(ptag, 0, tagLen);
            memset(tagInput, 0, tagLen);
            return ALC_ERROR_TAG_MISMATCH;
        }
    }

    return err;
}

alc_error_t
GcmAuth::setTagLength(alc_cipher_data_t* ctx, Uint64 tagLength)
{
    return ALC_ERROR_NONE;
}

#define CRYPT_AEAD_WRAPPER_FUNC_N(                                             \
    NAMESPACE, CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, PKEY, NUM_ROUNDS, IS_ENC)  \
    alc_error_t CLASS_NAME##_##NAMESPACE::WRAPPER_FUNC(alc_cipher_data_t* ctx, \
                                                       const Uint8* pinput,    \
                                                       Uint8*       pOutput,   \
                                                       Uint64       len)       \
    {                                                                          \
        alc_error_t err = ALC_ERROR_NONE;                                      \
        m_dataLen += len;                                                      \
        m_isEnc_aes = IS_ENC;                                                  \
        /*printf(" datalen %ld ", len);*/                                      \
        bool isFirstUpdate = false;                                            \
        if (len == m_dataLen) {                                                \
            isFirstUpdate = true;                                              \
        }                                                                      \
        err = NAMESPACE::FUNC_NAME(                                            \
            pinput,                                                            \
            pOutput,                                                           \
            len,                                                               \
            isFirstUpdate,                                                     \
            PKEY,                                                              \
            NUM_ROUNDS,                                                        \
            &m_gcm_local_data,                                                 \
            ctx,                                                               \
            m_gcm_local_data.m_gcm                                             \
                .m_hashSubkeyTable); /*ctx->m_gcm.m_hashSubkeyTable);*/        \
        return err;                                                            \
    }
// vaes512 member functions
CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm128,
                          decrypt,
                          decryptGcm128,
                          m_cipher_key_data.m_enc_key,
                          10,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm192,
                          decrypt,
                          decryptGcm192,
                          m_cipher_key_data.m_enc_key,
                          12,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm256,
                          decrypt,
                          decryptGcm256,
                          m_cipher_key_data.m_enc_key,
                          14,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm128,
                          encrypt,
                          encryptGcm128,
                          m_cipher_key_data.m_enc_key,
                          10,
                          ALCP_ENC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm192,
                          encrypt,
                          encryptGcm192,
                          m_cipher_key_data.m_enc_key,
                          12,
                          ALCP_ENC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes512,
                          Gcm256,
                          encrypt,
                          encryptGcm256,
                          m_cipher_key_data.m_enc_key,
                          14,
                          ALCP_ENC)

// vaes member functions
CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm128,
                          decrypt,
                          decryptGcm128,
                          m_cipher_key_data.m_enc_key,
                          10,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm192,
                          decrypt,
                          decryptGcm192,
                          m_cipher_key_data.m_enc_key,
                          12,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm256,
                          decrypt,
                          decryptGcm256,
                          m_cipher_key_data.m_enc_key,
                          14,
                          ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm128,
                          encrypt,
                          encryptGcm128,
                          m_cipher_key_data.m_enc_key,
                          10,
                          ALCP_ENC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm192,
                          encrypt,
                          encryptGcm192,
                          m_cipher_key_data.m_enc_key,
                          12,
                          ALCP_ENC)

CRYPT_AEAD_WRAPPER_FUNC_N(vaes,
                          Gcm256,
                          encrypt,
                          encryptGcm256,
                          m_cipher_key_data.m_enc_key,
                          14,
                          ALCP_ENC)

// aesni member functions

// below code to be re-written to use CRYPT_AEAD_WRAPPER_FUNC wrapper
// itself.

alc_error_t
Gcm128_aesni::decrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 0;
    // to be modified to decryptGcm128 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        false,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

alc_error_t
Gcm192_aesni::decrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 0;
    // to be modified to decryptGcm192 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        false,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

alc_error_t
Gcm256_aesni::decrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 0;
    // to be modified to decryptGcm256 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        false,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

alc_error_t
Gcm128_aesni::encrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 1;
    // to be modified to encryptGcm128 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        true,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

alc_error_t
Gcm192_aesni::encrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 1;
    // to be modified to encryptGcm192 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        true,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

alc_error_t
Gcm256_aesni::encrypt(alc_cipher_data_t* ctx,
                      const Uint8*       pInput,
                      Uint8*             pOutput,
                      Uint64             len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_dataLen += len;
    m_isEnc_aes = 1;
    // to be modified to encryptGcm192 function
    err = aesni::CryptGcm(
        pInput,
        pOutput,
        len,
        m_cipher_key_data.m_enc_key,
        m_nrounds,
        &m_gcm_local_data,
        ctx,
        true,
        m_gcm_local_data.m_gcm
            .m_hashSubkeyTable); // ctx->m_gcm.m_hashSubkeyTable);
    return err;
}

} // namespace alcp::cipher
