/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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
Ccm::decrypt(const Uint8* pInput,
             Uint8*       pOutput,
             Uint64       len,
             const Uint8* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::encrypt(const Uint8* pInput,
             Uint8*       pOutput,
             Uint64       len,
             const Uint8* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::cryptUpdate(const Uint8* pInput,
                 Uint8*       pOutput,
                 Uint64       len,
                 const Uint8* pIv,
                 bool         isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;

    if ((pInput != NULL) && (pOutput != NULL)) {
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

        const Uint8* keys   = getEncryptKeys();
        const Uint32 rounds = getRounds();
        m_ccm_data.key      = keys;
        m_ccm_data.rounds   = rounds;

        if (Cipher::isAesniAvailable()) {

            // Below operations has to be done in order.
            if (isEncrypt) {
                aesni::CcmSetIv(&m_ccm_data, pIv, m_ivLen, len);
                aesni::CcmSetAad(
                    &m_ccm_data, m_additionalData, m_additionalDataLen);
                aesni::CcmEncrypt(&m_ccm_data, pInput, pOutput, len);
            } else {
                aesni::CcmSetIv(&m_ccm_data, pIv, m_ivLen, len);
                aesni::CcmSetAad(
                    &m_ccm_data, m_additionalData, m_additionalDataLen);
                aesni::CcmDecrypt(&m_ccm_data, pInput, pOutput, len);
            }
        }
    } else {
        err = ALC_ERROR_INVALID_ARG;
    }
    return err;
}

alc_error_t
Ccm::decryptUpdate(const Uint8* pInput,
                   Uint8*       pOutput,
                   Uint64       len,
                   const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, false);
    return err;
}

alc_error_t
Ccm::encryptUpdate(const Uint8* pInput,
                   Uint8*       pOutput,
                   Uint64       len,
                   const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, true);
    return err;
}

alc_error_t
Ccm::setIv(Uint64 len, const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len == 0 || len < 7 || len > 13) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    m_ivLen = len;

    // Initialize ccm_data
    m_ccm_data.blocks = 0;
    m_ccm_data.key    = nullptr;
    m_ccm_data.rounds = 0;
    memset(m_ccm_data.cmac, 0, 16);
    memset(m_ccm_data.nonce, 0, 16);
    // 8 is the length required to store length of plain text.
    aesni::CcmInit(&m_ccm_data, m_tagLen, 8);
    return err;
}

alc_error_t
Ccm::setAad(const Uint8* pInput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    // additional data processing, when input is additional data &
    if (len == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }

    m_additionalData    = pInput;
    m_additionalDataLen = len;
    return err;
}

alc_error_t
Ccm::getTag(Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len < 4 || len > 16 || len == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    // If tagLen is 0 that means it's a set call
    if (m_tagLen == 0) {
        m_tagLen = len;
    } else {
        bool ret = aesni::CcmGetTag(&m_ccm_data, pOutput, len);

        if (ret == 0) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
    }
    return err;
}

alc_error_t
Ccm::setTagLength(Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len < 4 || len > 16 || len == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    m_tagLen = len;

    return err;
}

} // namespace alcp::cipher
