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
#include "alcp/cipher/cipher_error.hh"

#include <immintrin.h>
#include <sstream>
#include <string.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;
namespace alcp::cipher {

#define CRYPT_AEAD_WRAPPER_FUNC_N(                                             \
    NAMESPACE, CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, IS_ENC)                    \
    alc_error_t CLASS_NAME##_##NAMESPACE::WRAPPER_FUNC(                        \
        const Uint8* pInput, Uint8* pOutput, Uint64 len)                       \
    {                                                                          \
        Status s    = StatusOk();                                              \
        m_isEnc_aes = IS_ENC;                                                  \
        s           = Ccm::FUNC_NAME(pInput, pOutput, len, IS_ENC);            \
        return s.code();                                                       \
    } // namespace alcp::cipher

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

Status
copyTag(ccm_data_t* ctx, Uint8 ptag[], Uint64 tagLen)
{
    // Retrieve the tag length
    Status s = StatusOk();

    if (ptag == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    unsigned int t = (ctx->nonce[0] >> 3) & 7;

    t *= 2;
    t += 2;
    if (tagLen != t) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s;
    }
    utils::CopyBytes(ptag, ctx->cmac, t);
    memset(ctx->cmac, 0, tagLen);

    return s;
}

// FIXME: nRounds needs to be constexpr to be more efficient
Status
Ccm::cryptUpdate(const Uint8 pInput[],
                 Uint8       pOutput[],
                 Uint64      dataLen,
                 bool        isEncrypt)
{

#ifdef CCM_MULTI_UPDATE
    if (!m_ccm_data.key) {
        return status::InvalidValue("Key has to be set before update");
    }
#endif
    Status s = StatusOk();
    if ((pInput == NULL) || (pOutput == NULL)) {
        s = status::InvalidValue("Input or Output Null Pointer!");
    }

#ifndef CCM_MULTI_UPDATE
    const Uint8* p_keys  = getEncryptKeys();
    const Uint32 cRounds = m_nrounds;
    m_ccm_data.key       = p_keys;
    m_ccm_data.rounds    = cRounds;

    // Below Operations has to be done in order
    s.update(setIv(&m_ccm_data, m_iv_aes, m_ivLen_aes, dataLen));
#endif
    // Accelerate with AESNI
    if (m_updatedLength == 0) {
        aesni::ccm::SetAad(&m_ccm_data,
                           m_additionalData,
                           m_additionalDataLen,
                           m_plainTextLength);
    }
    if (isEncrypt) {
        CCM_ERROR err =
            aesni::ccm::Encrypt(&m_ccm_data, pInput, pOutput, dataLen);
        switch (err) {
            case CCM_ERROR::LEN_MISMATCH:
                s = status::EncryptFailed("Length of plainText mismatch!");
                break;
            case CCM_ERROR::DATA_OVERFLOW:
                s = status::EncryptFailed(
                    "Overload of plaintext. Please reduce it!");
                break;
            default:
                break;
        }
    } else {
        CCM_ERROR err =
            aesni::ccm::Decrypt(&m_ccm_data, pInput, pOutput, dataLen);
        switch (err) {
            case CCM_ERROR::LEN_MISMATCH:
                s = status::DecryptFailed("Length of plainText mismatch!");
                break;
            default:
                break;
        }
    }
    if (s.ok() != true) {
        // Burn everything
        memset(m_ccm_data.nonce, 0, 16);
        memset(m_ccm_data.cmac, 0, 16);
        memset(pOutput, 0, dataLen);
        return s;
    }
#ifdef CCM_MULTI_UPDATE
    if (s.ok()) {
        m_updatedLength += dataLen;
    }
#endif
    return s;

#ifdef CCM_MULTI_UPDATE
    if (s.ok()) {
        m_updatedLength += dataLen;
    }
#endif
    return s;
}

Status
Ccm::setIv(ccm_data_t* ccm_data,
           const Uint8 pIv[],
           Uint64      ivLen,
           Uint64      dataLen)
{
    Status       s   = StatusOk();
    unsigned int q   = ccm_data->nonce[0] & 7;
    Uint64       len = dataLen;
#ifdef CCM_MULTI_UPDATE
    len = m_plainTextLength;
#endif

    if (ccm_data == nullptr || pIv == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

    if (ivLen < (14 - q)) {
        s = status::InvalidValue("Length of nonce is too small!");
        return s;
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
    // EXITG();
    return s;
}

// Auth class definitions
alc_error_t
CcmHash::setTagLength(Uint64 tagLen)
{
    Status s = StatusOk();
    if (tagLen < 4 || tagLen > 16) {
        s = status::InvalidValue("Length of tag should be 4 < len < 16 ");
        return s.code();
    }
    // Stored to verify in the getTagLength API
    m_tagLen = tagLen;
    return s.code();
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
#ifdef CCM_MULTI_UPDATE
    Status s = StatusOk();
    // Check if total updated data so far has exceeded the preestablished
    // plaintext Length. This check is here rather than in encrypt/decrypt
    // to allow multiupdate calls in benchmarking.
    if (m_updatedLength > m_plainTextLength) {
        return ALC_ERROR_INVALID_DATA;
    }
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s.code();
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is unknown!, need to agree on tag before hand!");
    } else {
        aesni::ccm::Finalize(&m_ccm_data);
        s.update(copyTag(&m_ccm_data, pOutput, tagLen));
    }
    return s.code();
#else
    Status s = StatusOk();
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s.code();
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen != 0) {
        s.update(copyTag(&m_ccm_data, pOutput, tagLen));
    } else {
        s = status::InvalidValue(
            "Tag length is unknown!, need to agree on tag before hand!");
    }
    return s.code();
#endif
}

// Aead class definitions

// aesni member functions
CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm128, encrypt, cryptUpdate, ALCP_ENC)
CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm128, decrypt, cryptUpdate, ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm192, encrypt, cryptUpdate, ALCP_ENC)
CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm192, decrypt, cryptUpdate, ALCP_DEC)

CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm256, encrypt, cryptUpdate, ALCP_ENC)
CRYPT_AEAD_WRAPPER_FUNC_N(aesni, Ccm256, decrypt, cryptUpdate, ALCP_DEC)

} // namespace alcp::cipher