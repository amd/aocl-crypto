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

namespace alcp::cipher {

/**
 * @brief CCM mode (Copy of GCM class)
 * Uses encryptUpdate and decryptUpdate instead of
 * encrypt and decrypt.
 * @struct ccm_data_t
 */

struct ccm_data_t
{
    alignas(16) Uint8 nonce[16];
    alignas(16) Uint8 cmac[16];
    const Uint8* key    = nullptr;
    Uint64       blocks = 0;
    Uint32       rounds = 0;
};

enum class CCM_ERROR
{
    NO_ERROR      = 0,
    LEN_MISMATCH  = -1,
    DATA_OVERFLOW = -2,
};

namespace aesni::ccm {
    void SetAad(ccm_data_t* ctx, const Uint8 aad[], size_t alen);

    CCM_ERROR Encrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      size_t      len);

    CCM_ERROR Decrypt(ccm_data_t* ctx,
                      const Uint8 inp[],
                      Uint8       out[],
                      size_t      len);
} // namespace aesni::ccm

class ALCP_API_EXPORT Ccm final : public Aes
//, cipher::IDecryptUpdater
//, cipher::IEncryptUpdater
{
  private:
    Uint64       m_dataLen           = 0;
    Uint64       m_ivLen             = 0;
    Uint64       m_tagLen            = 0;
    Uint64       m_additionalDataLen = 0;
    const Uint8* m_additionalData;

    ccm_data_t m_ccm_data;

  public:
    explicit Ccm(const Uint8* pKey, const Uint32 keyLen);
    explicit Ccm(alc_cipher_data_t* ctx);

    Ccm();
    ~Ccm();

    void init(ccm_data_t* ccm_data, unsigned int t, unsigned int q);

    /**
     * @brief Intialize CCM
     *
     * @param ctx - Context
     * @param pKey - Key for encryption
     * @param keyLen
     * @param pIv
     * @param ivLen
     * @return
     */
    alc_error_t init(alc_cipher_data_t* ctx,
                     const Uint8*       pKey,
                     Uint64             keyLen,
                     const Uint8*       pIv,
                     Uint64             ivLen);

    virtual alc_error_t getTag(alc_cipher_data_t* ctx,
                               Uint8*             pOutput,
                               Uint64             len);

    /**
     * @brief Get CCM Tag
     * @param ctx Intermediate Data
     * @param ptag tag memory
     * @param len Length of the tag
     * @return
     */
    Status getTag(ccm_data_t* ctx, Uint8 ptag[], size_t len);

    /**
     * @brief Set IV(nonce)
     * @param ccm_data Intermediate Data
     * @param pnonce Nonce Pointer
     * @param nlen Length of Nonce
     * @param mlen Message length
     * @return
     */
    Status setIv(ccm_data_t* ccm_data,
                 const Uint8 pnonce[],
                 size_t      nlen,
                 size_t      mlen);

    // FIXME: Too many setAad calls, fix it
    virtual alc_error_t setAad(alc_cipher_data_t* ctx,
                               const Uint8*       pInput,
                               Uint64             len);

    /**
     * @brief Set tag length to adjust nonce value
     *
     *
     * @param ctx  - Context
     * @param len  - Length of Tag
     * @return
     */
    virtual alc_error_t setTagLength(alc_cipher_data_t* ctx, Uint64 len);

    /**
     * @brief Set Ad
     * ditional Data.
     * @param pccm_data Intermediate Data
     * @param paad Additional Data Pointer
     * @param alen Length of additional data
     */
    Status setAadRef(ccm_data_t* pccm_data, const Uint8 paad[], size_t alen);

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
                       Uint64      len,
                       const Uint8 pIv[],
                       Uint64      ivLen,
                       bool        isEncrypt);

    /**
     * @brief   CCM Encrypt Operation
     * @note
     * @param   pInput      Pointer to input buffer
     *                          (plainText or Additional data)
     * @param   pOuput          Pointer to encrypted buffer
     *                          when pointer NULL, input is additional data
     * @param   len             Len of input buffer
     *                          (plainText or Additional data)
     * @param   pIv             Pointer to Initialization Vector @return
     * alc_error_t     Error code
     */
    virtual alc_error_t encryptUpdate(alc_cipher_data_t* ctx,
                                      const Uint8*       pInput,
                                      Uint8*             pOutput,
                                      Uint64             len);

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
                      const Uint8 pInput[],
                      Uint8       pOutput[],
                      Uint64      len);

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
                      const Uint8 pInput[],
                      Uint8       pOutput[],
                      Uint64      len);

    /**
     * @brief   CCM Decrypt Operation
     * @note
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decryptUpdate(alc_cipher_data_t* ctx,
                                      const Uint8*       pCipherText,
                                      Uint8*             pPlainText,
                                      Uint64             len);
};

} // namespace alcp::cipher
