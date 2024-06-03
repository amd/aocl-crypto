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
#pragma once

#include "aes.hh"
#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include <cstdint>
#include <immintrin.h>

#include "alcp/cipher/cipher_common.hh"

namespace alcp::cipher {

/**
 * @brief CCM mode (Copy of GCM class)
 * @struct ccm_data_t
 */

struct ccm_data_t
{
    alignas(16) Uint8 nonce[16];
    alignas(16) Uint8 cmac[16];
    const Uint8*  key    = nullptr;
    Uint64        blocks = 0;
    Uint32        rounds = 0;
    unsigned char flags0;
};

enum class CCM_ERROR
{
    NO_ERROR      = 0,
    LEN_MISMATCH  = -1,
    DATA_OVERFLOW = -2,
};

namespace aesni::ccm {
    // Defined in arch/zen3
    CCM_ERROR SetAad(ccm_data_t* ctx,
                     const Uint8 aad[],
                     size_t      alen,
                     size_t      plen);
    CCM_ERROR Finalize(ccm_data_t* ctx);

    CCM_ERROR Encrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      size_t      dataLen);

    CCM_ERROR Decrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      size_t      len);
} // namespace aesni::ccm

class ALCP_API_EXPORT Ccm : public Aes
{
    // Needs to be protected as class CcmHash should use it
  protected:
    // For AES CCM set default taglen as 12. When init is called and if tag
    // length is not set then default tag length will be assumed.
    Uint64       m_tagLen            = 12;
    Uint64       m_additionalDataLen = 0;
    const Uint8* m_additionalData;
    Uint64       m_plainTextLength      = 0;
    bool         m_is_plaintext_len_set = false;
    Uint64       m_updatedLength        = 0;
    ccm_data_t   m_ccm_data;

  protected:
    /**
     * @brief Set IV(nonce)
     * @param ccm_data Intermediate Data
     * @param pnonce Nonce Pointer
     * @param nlen Length of Nonce
     * @param mlen Message length
     * @return
     */
    Status setIv(ccm_data_t* ccm_data,
                 const Uint8 pIv[],
                 size_t      ivLen,
                 size_t      dataLen);

  public:
    explicit Ccm(alc_cipher_data_t* ctx);

    Ccm()  = default;
    ~Ccm() = default;

    /**
     * @brief Set tag length to adjust nonce value
     *
     *
     * @param ctx  - Context
     * @param len  - Length of Tag
     * @return Error code
     */
    alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 tagLen);

#ifdef CCM_MULTI_UPDATE
    /**
     * @brief Set plaintext length
     *
     *
     * @param ctx  - Context
     * @param len  - Length of plaintext
     * @return Error code
     */
    alc_error_t setPlainTextLength(alc_cipher_data_t* ctx, Uint64 len);
#endif

    // FIXME: This internal function needs to be protected/private
    // as there is 2 levels of inheritance down which this function
    // needs to be used, there is no way to make it protected/private
    /**
     * @brief Encrypt/Decrypt for CCM
     *
     *
     * @param pInput     Input data PlainText Or CipherText
     * @param pOutput    Output data CipherText Or PlainText
     * @param len        Length of the Input
     * @param pIv        Pointer to IV
     * @param ivLen      Length of IV
     * @param isEncrypt  Encrypt if true
     * @return           Status
     */
    Status cryptUpdate(const Uint8 pInput[],
                       Uint8       pOutput[],
                       Uint64      dataLen,
                       bool        isEncrypt);

    // FIXME: Move Ref implemntation to arch/reference
  protected:
    /**
     * @brief Reference decrypt function
     *
     *
     * @param ccm_data  State
     * @param pInput    Cipher Text
     * @param pOutput   Plain Text
     * @param len       Length of Cipher Text
     * @return          Status
     */
    Status decryptRef(ccm_data_t* ccm_data,
                      const Uint8 pCipherText[],
                      Uint8       pPlainText[],
                      Uint64      ctLen);

#ifdef CCM_MULTI_UPDATE
    /**
     * @brief Set Ad
     * ditional Data.
     * @param pccm_data Intermediate Data
     * @param paad Additional Data Pointer
     * @param alen Length of additional data
     */
    Status setAadRef(ccm_data_t* pccm_data,
                     const Uint8 paad[],
                     size_t      aadLen,
                     size_t      plen);
#else
    Status setAadRef(ccm_data_t* pccm_data, const Uint8 paad[], size_t aadLen);
#endif

#ifdef CCM_MULTI_UPDATE
    /**
     * @brief Finalize the encrypt/decrypt operations for Reference Algorithm
     * @param pccm_data Intermediate Data
     */
    Status finalizeRef(ccm_data_t* pccm_data);

#endif
    /**
     * @brief Reference encryption function
     *
     *
     * @param ccm_data  State
     * @param pInput    Plain Text
     * @param pOutput   Cipher Text
     * @param len       Length of Plain Text
     * @return          Status
     */
    Status encryptRef(ccm_data_t* ccm_data,
                      const Uint8 pPlainText[],
                      Uint8       pCipherText[],
                      Uint64      ptLen);

    /**
     * @brief Get CCM Tag
     * @param ctx Intermediate Data
     * @param ptag tag memory
     * @param len Length of the tag
     * @return
     */
    Status getTagRef(ccm_data_t* ctx, Uint8 ptag[], size_t tagLen);
};

AEAD_AUTH_CLASS_GEN(CcmHash, Ccm);

namespace vaes512 {
    CIPHER_CLASS_GEN(CcmAead128, CcmHash);
    CIPHER_CLASS_GEN(CcmAead192, CcmHash);
    CIPHER_CLASS_GEN(CcmAead256, CcmHash);
} // namespace vaes512

namespace vaes {
    CIPHER_CLASS_GEN(CcmAead128, CcmHash);
    CIPHER_CLASS_GEN(CcmAead192, CcmHash);
    CIPHER_CLASS_GEN(CcmAead256, CcmHash);
} // namespace vaes

namespace aesni {
    CIPHER_CLASS_GEN(CcmAead128, CcmHash);
    CIPHER_CLASS_GEN(CcmAead192, CcmHash);
    CIPHER_CLASS_GEN(CcmAead256, CcmHash);
} // namespace aesni

} // namespace alcp::cipher