/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

struct _ccm_data_t
{
    alignas(16) Uint8 nonce[16];
    alignas(16) Uint8 cmac[16];
    const Uint8* key    = nullptr;
    Uint64       blocks = 0;
    Uint32       rounds = 0;
};
typedef _ccm_data_t *ccm_data_p, ccm_data_t;

namespace aesni {
    /**
     * @brief Initializes CCM
     *
     * @param ctx - Context
     * @param t - Tag Length
     * @param q - Length required to store length of Plain text
     * @param key - Key used for encryption
     * @param block
     */

    void CcmInit(ccm_data_p ctx, unsigned int t, unsigned int q);

    int CcmSetIv(ccm_data_p ctx, const Uint8* nonce, size_t nlen, size_t mlen);

    void CcmSetAad(ccm_data_p ctx, const Uint8* aad, size_t alen);

    int CcmEncrypt(ccm_data_p ctx, const Uint8* inp, Uint8* out, size_t len);

    int CcmDecrypt(ccm_data_p ctx, const Uint8* inp, Uint8* out, size_t len);

    void ctr64_add(Uint8* counter, size_t inc);

    size_t CcmGetTag(ccm_data_p ctx, Uint8* tag, size_t len);
} // namespace aesni

class ALCP_API_EXPORT Ccm final
    : public Aes
    , cipher::IDecryptUpdater
    , cipher::IEncryptUpdater
{

  public:
    Uint64       m_len               = 0;
    Uint64       m_message_len       = 0;
    Uint64       m_ivLen             = 0;
    Uint64       m_tagLen            = 0;
    Uint64       m_additionalDataLen = 0;
    const Uint8* m_additionalData;

    ccm_data_t m_ccm_data;

    explicit Ccm(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo);

    ~Ccm();

    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_CCM) {
                return true;
            }
        }

        return false;
    }

    virtual alc_error_t getTag(Uint8* pOutput, Uint64 len);

    virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

    virtual alc_error_t setAad(const Uint8* pInput, Uint64 len);

    virtual alc_error_t setTagLength(Uint64 len);

    void CcmSetAad(ccm_data_p pccm_data, const Uint8* paad, size_t alen);

    int CcmEncrypt(ccm_data_p   ccm_data,
                   const Uint8* pinp,
                   Uint8*       pout,
                   size_t       len);

    int CcmDecrypt(ccm_data_p   ccm_data,
                   const Uint8* pinp,
                   Uint8*       pout,
                   size_t       len);

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
    virtual alc_error_t encrypt(const Uint8* pInput,
                                Uint8*       pOutput,
                                Uint64       len,
                                const Uint8* pIv) const final;

    virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                      Uint8*       pOutput,
                                      Uint64       len,
                                      const Uint8* pIv) override;

    /**
     * @brief   CCM Decrypt Operation
     * @note
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                      Uint8*       pPlainText,
                                      Uint64       len,
                                      const Uint8* pIv) override;
    Ccm() = default;

  private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace alcp::cipher
