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
#include <string.h>
#include <wmmintrin.h>

namespace alcp::cipher {

alc_error_t
Ccm::decrypt(const uint8_t* pInput,
             uint8_t*       pOutput,
             uint64_t       len,
             const uint8_t* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::encrypt(const uint8_t* pInput,
             uint8_t*       pOutput,
             uint64_t       len,
             const uint8_t* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::cryptUpdate(const uint8_t* pInput,
                 uint8_t*       pOutput,
                 uint64_t       len,
                 const uint8_t* pIv,
                 bool           isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;

    /*  Follow in Ccm:
     *  InitCcm -> processAdditionalDataCcm ->CryptCcm-> GetTagCcm */

    // Ccm init, both input and output pointers are NULL
    if ((pInput == NULL) && (pOutput == NULL)) {
        // Ccm init call
        // len is used as ivlen
        // In init call, we generate HashSubKey, partial tag data.
        if (len == 0) {
            // Error::setDetail(err, ALC_ERROR_INVALID_SIZE);
            err = ALC_ERROR_INVALID_SIZE;
            return err;
        }
        m_ivLen = len;
    } else if ((pInput != NULL) && (pOutput == NULL)) {
        // additional data processing, when input is additional data &
        if (len == 0) {
            // Error::setDetail(err, ALC_ERROR_INVALID_SIZE);
            err = ALC_ERROR_INVALID_SIZE;
            return err;
        }

        m_additionalData    = pInput;
        m_additionalDataLen = len;

    } else if ((pInput != NULL) && (pOutput != NULL)) {
        // CTR encrypt and Hash
        m_len = len;

        bool isAvx512Cap = false;
        if (Cipher::isVaesAvailable()) {
            if (Cipher::isAvx512Has(cipher::AVX512_F)
                && Cipher::isAvx512Has(cipher::AVX512_DQ)
                && Cipher::isAvx512Has(cipher::AVX512_BW)) {
                isAvx512Cap = true;
            }
        }
        // FIXME: Convincing compiler to not complain
        isAvx512Cap = isAvx512Cap;

        if (Cipher::isAesniAvailable()) {
            const Uint8* keys   = getEncryptKeys();
            const Uint32 rounds = getRounds();

            if (isEncrypt) {
                m_ccm_data.blocks = 0;
                m_ccm_data.key    = nullptr;
                m_ccm_data.rounds = 0;
                memset(m_ccm_data.cmac, 0, 16);
                memset(m_ccm_data.nonce, 0, 16);
#ifndef NDEBUG
                std::cout << "Init" << std::endl;
#endif
                aesni::CcmInit(&m_ccm_data, m_tagLen, 8, keys, rounds);
#ifndef NDEBUG
                std::cout << "IV" << std::endl;
#endif
                aesni::CcmSetIv(&m_ccm_data, pIv, m_ivLen, len);
#ifndef NDEBUG
                std::cout << "AAD" << std::endl;
#endif
                aesni::CcmSetAad(
                    &m_ccm_data, m_additionalData, m_additionalDataLen);
#ifndef NDEBUG
                std::cout << "ENC" << std::endl;
#endif
                aesni::CcmEncrypt(&m_ccm_data, pInput, pOutput, len);
            } else {
                m_ccm_data.blocks = 0;
                m_ccm_data.key    = nullptr;
                m_ccm_data.rounds = 0;
                memset(m_ccm_data.cmac, 0, 16);
                memset(m_ccm_data.nonce, 0, 16);

#ifndef NDEBUG
                std::cout << "Init" << std::endl;
#endif
                aesni::CcmInit(
                    &m_ccm_data, m_tagLen, 8, getEncryptKeys(), getRounds());
#ifndef NDEBUG
                std::cout << "IV" << std::endl;
#endif
                aesni::CcmSetIv(&m_ccm_data, pIv, m_ivLen, len);
#ifndef NDEBUG
                std::cout << "AAD" << std::endl;
#endif
                aesni::CcmSetAad(
                    &m_ccm_data, m_additionalData, m_additionalDataLen);
#ifndef NDEBUG
                std::cout << "DEC" << std::endl;
#endif
                aesni::CcmDecrypt(&m_ccm_data, pInput, pOutput, len);
            }
        }
    } else if ((pInput == NULL) && (pOutput != NULL)) {
        std::cout << "TAG" << std::endl;
        if (len == 0) {
            // Error::setDetail(err, ALC_ERROR_INVALID_SIZE);
            err = ALC_ERROR_INVALID_SIZE;
            return err;
        }
        // If tagLen is 0 that means it's a set call
        if (m_tagLen == 0) {
            m_tagLen = len;
        } else {
            bool ret = aesni::CcmGetTag(&m_ccm_data, pOutput, len);

            if (ret == 0) {
                std::cout << "TAG Error Occured!\n" << std::endl;
                // Error::setDetail(err, ALC_ERROR_BAD_STATE);
                err = ALC_ERROR_BAD_STATE;
                return err;
            }
        }
    }
    return err;
}

alc_error_t
Ccm::decryptUpdate(const uint8_t* pInput,
                   uint8_t*       pOutput,
                   uint64_t       len,
                   const uint8_t* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, false);
    return err;
}

alc_error_t
Ccm::encryptUpdate(const uint8_t* pInput,
                   uint8_t*       pOutput,
                   uint64_t       len,
                   const uint8_t* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, true);
    return err;
}

} // namespace alcp::cipher
