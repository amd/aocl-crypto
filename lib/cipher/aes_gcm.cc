/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

#define DEBUG_PROV_GCM_INIT 0

namespace alcp::cipher {
// init & finish implementation
alc_error_t
Gcm::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    // Uint8*      pExpKey = nullptr;
    if (pKey != NULL && keyLen != 0) {
        // err = setKey(pKey, pExpKey, keyLen);
        err                        = setKey(pKey, keyLen);
        m_gcm_ctx.m_update_counter = 0; // reset counter
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    if (pIv != NULL && ivLen != 0) {
        err                        = setIv(pIv, ivLen);
        m_gcm_ctx.m_update_counter = 0; // reset counter
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    // In init call, we generate HashSubKey, partial
    // tag data.
    if (m_ivState_aes && m_isKeySet_aes) {
        m_gcm_ctx.m_gHash_128       = _mm_setzero_si128();
        m_gcm_ctx.m_hash_subKey_128 = _mm_setzero_si128();
        m_dataLen                   = 0;
        // printf("\n gcm init");
        err = aesni::InitGcm(m_cipher_key_data.m_enc_key,
                             m_nrounds,
                             m_pIv_aes,
                             m_ivLen_aes,
                             m_gcm_ctx.m_hash_subKey_128,
                             m_gcm_ctx.m_tag_128,
                             m_gcm_ctx.m_counter_128,
                             m_gcm_ctx.m_reverse_mask_128);
    }

    return err;
}

// authentication api implementation
alc_error_t
GcmAuth::setAad(const Uint8* pInput, Uint64 aadLen)
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
    const Uint8* pAdditionalData  = pInput;
    m_gcm_ctx.m_additionalDataLen = aadLen;
#if DEBUG_PROV_GCM_INIT
    printf("processAad adlen %ld \n", m_gcm_ctx.m_additionalDataLen);
#endif
    // printf("\n gcm aad");
    err = aesni::processAdditionalDataGcm(pAdditionalData,
                                          m_gcm_ctx.m_additionalDataLen,
                                          m_gcm_ctx.m_gHash_128,
                                          m_gcm_ctx.m_hash_subKey_128,
                                          m_gcm_ctx.m_reverse_mask_128);

    return err;
}

// Internal tag matching is disable for ipp compat support
#define INTERNAL_TAG_MATCH 0

alc_error_t
GcmAuth::getTag(Uint8* ptag, Uint64 tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_pIv_aes == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    } else if (tagLen > 16 || tagLen == 0) {
        return ALC_ERROR_INVALID_SIZE;
    }
#if DEBUG_PROV_GCM_INIT
    printf("getTag taglen %ld \n\n", tagLen);
#endif

#if INTERNAL_TAG_MATCH
    // During decrypt, tag generated should be compared with
    // input Tag.
    Uint8 tagInput[ALCP_GCM_TAG_MAX_SIZE];
    if (!m_isEnc_aes) {
        // create a copy of input
        memcpy(tagInput, ptag, tagLen);
    }
#endif

    err = aesni::GetTagGcm(tagLen,
                           m_dataLen,
                           m_gcm_ctx.m_additionalDataLen,
                           m_gcm_ctx.m_gHash_128,
                           m_gcm_ctx.m_tag_128,
                           m_gcm_ctx.m_hash_subKey_128,
                           m_gcm_ctx.m_reverse_mask_128,
                           ptag);

#if INTERNAL_TAG_MATCH
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
#endif

    return err;
}

alc_error_t
GcmAuth::setTagLength(Uint64 tagLength)
{
    return ALC_ERROR_NONE;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
GcmT<keyLenBits, arch>::decrypt(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_DEC;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    m_dataLen += len;

#if DEBUG_PROV_GCM_INIT
    printf("decrypt len %ld \n", len);
#endif

    m_gcm_ctx.m_update_counter++;

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        if constexpr (keyLenBits == alcp::cipher::CipherKeyLen::eKey128Bit) {
            err = vaes512::decryptGcm128(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey192Bit) {
            err = vaes512::decryptGcm192(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey256Bit) {
            err = vaes512::decryptGcm256(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        if (keyLenBits == alcp::cipher::CipherKeyLen::eKey128Bit) {
            err = vaes::decryptGcm128(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey192Bit) {
            err = vaes::decryptGcm192(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey256Bit) {
            err = vaes::decryptGcm256(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::CryptGcm(pInput,
                              pOutput,
                              len,
                              m_cipher_key_data.m_enc_key,
                              m_nrounds,
                              &m_gcm_ctx,
                              false);
        return err;
    }

    return ALC_ERROR_NOT_SUPPORTED;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
GcmT<keyLenBits, arch>::encrypt(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    m_dataLen += len;

#if DEBUG_PROV_GCM_INIT
    printf("encrypt len %ld \n", len);
#endif

    m_gcm_ctx.m_update_counter++;
    // printf("\n update counter %ld \n", m_gcm_ctx.m_update_counter);

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        if constexpr (keyLenBits == alcp::cipher::CipherKeyLen::eKey128Bit) {
            err = vaes512::encryptGcm128(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey192Bit) {
            err = vaes512::encryptGcm192(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey256Bit) {
            err = vaes512::encryptGcm256(pInput,
                                         pOutput,
                                         len,
                                         m_gcm_ctx.m_update_counter,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        if constexpr (keyLenBits == alcp::cipher::CipherKeyLen::eKey128Bit) {
            err = vaes::encryptGcm128(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey192Bit) {
            err = vaes::encryptGcm192(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        } else if constexpr (keyLenBits
                             == alcp::cipher::CipherKeyLen::eKey256Bit) {
            err = vaes::encryptGcm256(pInput,
                                      pOutput,
                                      len,
                                      m_gcm_ctx.m_update_counter,
                                      m_cipher_key_data.m_enc_key,
                                      getRounds(),
                                      &m_gcm_ctx);
            return err;
        }
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::CryptGcm(pInput,
                              pOutput,
                              len,
                              m_cipher_key_data.m_enc_key,
                              m_nrounds,
                              &m_gcm_ctx,
                              true);
        return err;
    }

    return ALC_ERROR_NOT_SUPPORTED;
}

template class GcmT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes512>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes512>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes512>;

template class GcmT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes256>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes256>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes256>;

template class GcmT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eAesni>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eAesni>;
template class GcmT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher
