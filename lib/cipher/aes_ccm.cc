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

#include "alcp/cipher/aes_ccm.hh"

#include <immintrin.h>
#include <sstream>
#include <string.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;
namespace alcp::cipher {

inline void
ctrInc(Uint8 ctr[])
{
    // From 8 Counter starts, added in reverse.
    Uint64 ind = 7;
    while (ind != 0) {
        ctr[ind + 8]++;
        if (ctr[ind + 8]) {
            return;
        }
        ind--;
    }
}

alc_error_t
Ccm::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    int t = m_tagLen;
    int q = 15 - ivLen;

    // ptr keys for pKey and pIv done in Aes:init
    // init can be called separately for setKey and setIv
    alc_error_t err = Aes::init(pKey, keyLen, pIv, ivLen);
    if (alcp_is_error(err)) {
        return err;
    }
    if (pKey != nullptr) {

        const Uint8* p_keys  = getEncryptKeys();
        const Uint32 cRounds = m_nrounds;
        m_ccm_data.key       = p_keys;
        m_ccm_data.rounds    = cRounds;
    }

#ifdef CCM_MULTI_UPDATE
    if (ivLen != 0 && (m_is_plaintext_len_set == false)) {
        return ALC_ERROR_BAD_STATE;
    }
#endif
    if (ivLen != 0 && m_tagLen != 0) {
        if (ivLen < 7 || ivLen > 13) {
            // s = status::InvalidValue(
            //     "IV length needs to be between 7 and 13 both not
            //     included!");
            return ALC_ERROR_INVALID_SIZE;
        }
        // Initialize ccm_data
        memset(m_ccm_data.cmac, 0, 16);
        memset(m_ccm_data.nonce, 0, 16);
        // 15 = n + q where n is size of nonce (iv) and q is the size of
        // size in bytes of size in bytes of plaintext. Basically size of
        // the variable which can store size of plaintext. This size can be
        // fixed to a max of q = 15 - n.
        std::fill(
            m_ccm_data.nonce, m_ccm_data.nonce + sizeof(m_ccm_data.nonce), 0);
        std::fill(
            m_ccm_data.cmac, m_ccm_data.cmac + sizeof(m_ccm_data.cmac), 0);
        m_ccm_data.nonce[0] = (static_cast<Uint8>(q - 1) & 7)
                              | static_cast<Uint8>(((t - 2) / 2) & 7) << 3;

#ifdef CCM_MULTI_UPDATE
        setIv(&(m_ccm_data), pIv, ivLen, m_plainTextLength);
#endif
    }
    m_ccm_data.blocks = 0;
    return ALC_ERROR_NONE;
}

alc_error_t
copyTag(ccm_data_t* ctx, Uint8 ptag[], Uint64 tagLen)
{
    // Retrieve the tag length

    if (ptag == nullptr) {
        // InvalidValue("Null Pointer is not expected!")
        return ALC_ERROR_INVALID_ARG;
    }
    unsigned int t = (ctx->nonce[0] >> 3) & 7;

    t *= 2;
    t += 2;
    if (tagLen != t) {
        // InvalidValue(
        //     "Tag length is not what we agreed upon during start!");
        return ALC_ERROR_INVALID_ARG;
    }
    utils::CopyBytes(ptag, ctx->cmac, t);
    memset(ctx->cmac, 0, tagLen);

    return ALC_ERROR_NONE;
}

// FIXME: nRounds needs to be constexpr to be more efficient
alc_error_t
Ccm::cryptUpdate(const Uint8 pInput[],
                 Uint8       pOutput[],
                 Uint64      dataLen,
                 bool        isEncrypt)
{

#ifdef CCM_MULTI_UPDATE
    if (!m_ccm_data.key) {
        // InvalidValue : Key has to be set before update
        return ALC_ERROR_BAD_STATE;
    }
#endif
    alc_error_t err = ALC_ERROR_NONE;
    if ((pInput == NULL) || (pOutput == NULL)) {
        // InvalidValue: "Input or Output Null Pointer!"
        return ALC_ERROR_INVALID_ARG;
    }

#ifndef CCM_MULTI_UPDATE
    const Uint8* p_keys  = getEncryptKeys();
    const Uint32 cRounds = m_nrounds;
    m_ccm_data.key       = p_keys;
    m_ccm_data.rounds    = cRounds;

    // Below Operations has to be done in order
    err = setIv(&m_ccm_data, m_iv_aes, m_ivLen_aes, dataLen);
#endif
    // Accelerate with AESNI
    if (m_updatedLength == 0) {
        aesni::ccm::SetAad(&m_ccm_data,
                           m_additionalData,
                           m_additionalDataLen,
                           m_plainTextLength);
    }
    if (isEncrypt) {
        CCM_ERROR ccm_err =
            aesni::ccm::Encrypt(&m_ccm_data, pInput, pOutput, dataLen);
        switch (ccm_err) {
            case CCM_ERROR::LEN_MISMATCH:
                // EncryptFailed("Length of plainText mismatch!")
                err = ALC_ERROR_INVALID_DATA;
                break;
            case CCM_ERROR::DATA_OVERFLOW:
                // EncryptFailed("Overload of plaintext. Please reduce it!"
                err = ALC_ERROR_INVALID_DATA;
                break;
            default:
                break;
        }
    } else {
        CCM_ERROR ccm_err =
            aesni::ccm::Decrypt(&m_ccm_data, pInput, pOutput, dataLen);
        switch (ccm_err) {
            // DecryptFailed("Length of plainText mismatch!")
            case CCM_ERROR::LEN_MISMATCH:
                err = ALC_ERROR_INVALID_DATA;
                break;
            default:
                break;
        }
    }
    if (alcp_is_error(err)) {
        // Burn everything
        memset(m_ccm_data.nonce, 0, 16);
        memset(m_ccm_data.cmac, 0, 16);
        memset(pOutput, 0, dataLen);
        return err;
    }
#ifdef CCM_MULTI_UPDATE
    if (!alcp_is_error(err)) {
        m_updatedLength += dataLen;
    }
#endif
    return err;
}

alc_error_t
Ccm::setIv(ccm_data_t* ccm_data,
           const Uint8 pIv[],
           Uint64      ivLen,
           Uint64      dataLen)
{
    unsigned int q;
    Uint64       len = dataLen;
#ifdef CCM_MULTI_UPDATE
    len = m_plainTextLength;
#endif

    if (ccm_data == nullptr || pIv == nullptr) {
        // InvalidValue("Null Pointer is not expected!")
        return ALC_ERROR_INVALID_ARG;
    }

    q = ccm_data->nonce[0] & 7;

    if (ivLen < (14 - q)) {
        // InvalidValue("Length of nonce is too small!")
        return ALC_ERROR_INVALID_ARG;
    }

    if (q >= 3) {
        ccm_data->nonce[8]  = static_cast<Uint8>(len >> 56);
        ccm_data->nonce[9]  = static_cast<Uint8>(len >> 48);
        ccm_data->nonce[10] = static_cast<Uint8>(len >> 40);
        ccm_data->nonce[11] = static_cast<Uint8>(len >> 32);
    } else {
        memset(ccm_data->nonce + 8, 0, 8);
    }

    ccm_data->nonce[12] = static_cast<Uint8>(len >> 24);
    ccm_data->nonce[13] = static_cast<Uint8>(len >> 16);
    ccm_data->nonce[14] = static_cast<Uint8>(len >> 8);
    ccm_data->nonce[15] = static_cast<Uint8>(len);

    ccm_data->nonce[0] &= ~0x40; /* clear Adata flag */
    utils::CopyBytes(&ccm_data->nonce[1], pIv, 14 - q);

    m_ivState_aes = 1;
    // EXITG();
    return ALC_ERROR_NONE;
}

// Auth class definitions
alc_error_t
CcmHash::setTagLength(Uint64 tagLen)
{
    if (tagLen < 4 || tagLen > 16) {
        // InvalidValue("Length of tag should be 4 < len < 16 ");
        return ALC_ERROR_INVALID_ARG;
    }
    // Stored to verify in the getTagLength API
    m_tagLen = tagLen;
    return ALC_ERROR_NONE;
}

alc_error_t
CcmHash::setPlainTextLength(Uint64 len)
{
    m_plainTextLength      = len;
    m_updatedLength        = 0;
    m_is_plaintext_len_set = true;
    return ALC_ERROR_NONE;
}

alc_error_t
CcmHash::setAad(const Uint8* pInput, Uint64 aadLen)
{

    m_additionalData    = pInput;
    m_additionalDataLen = aadLen;

    return ALC_ERROR_NONE;
}

alc_error_t
CcmHash::getTag(Uint8* pOutput, Uint64 tagLen)
{
    alc_error_t err = ALC_ERROR_NONE;
#ifdef CCM_MULTI_UPDATE
    // Check if total updated data so far has exceeded the preestablished
    // plaintext Length. This check is here rather than in encrypt/decrypt
    // to allow multiupdate calls in benchmarking.
    if (m_updatedLength > m_plainTextLength) {
        return ALC_ERROR_INVALID_DATA;
    }
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        // InvalidValue("Tag length is not what we agreed upon during start!")
        return ALC_ERROR_INVALID_ARG;
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        // InvalidValue("Tag length is unknown!, need to agree on tag before
        // hand!")
        return ALC_ERROR_BAD_STATE;

    } else {
        aesni::ccm::Finalize(&m_ccm_data);
        err = copyTag(&m_ccm_data, pOutput, tagLen);
    }
    return err;
#else
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        // InvalidValue("Tag length is not what we agreed upon during start!")
        return ALC_ERROR_INVALID_ARG;
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen != 0) {
        err = copyTag(&m_ccm_data, pOutput, tagLen);
    } else {
        // InvalidValue("Tag length is unknown!, need to agree on tag before
        // hand!")
        return ALC_ERROR_BAD_STATE;
    }
    return err;
#endif
}

// Aead class definitions

// aesni member functions

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
CcmT<keyLenBits, arch>::encrypt(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    err = Ccm::cryptUpdate(pInput, pOutput, len, 1);
    return err;
}

template<CipherKeyLen keyLenBits, CpuCipherFeatures arch>
alc_error_t
CcmT<keyLenBits, arch>::decrypt(const Uint8* pInput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_DEC;
    if (!(m_ivState_aes && m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    err = Ccm::cryptUpdate(pInput, pOutput, len, 0);
    return err;
}

template class CcmT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eAesni>;
template class CcmT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eAesni>;
template class CcmT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher