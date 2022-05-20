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

#ifndef _CIPHER_AES_HH_
#define _CIPHER_AES_HH_ 2

#include "alcp/cipher.h"

//#include "algorithm.hh"
#include "cipher.hh"
#include "cipher/rijndael.hh"
#include "exception.hh"
#include "utils/bits.hh"
#include <immintrin.h>
#include <wmmintrin.h>

namespace alcp::cipher {

/*
 * \brief       AES (Advanced Encryption Standard)
 *
 * \notes       AES is currently same as Rijndael, This may be renamed to
 *              other as well in the future.
 *
 * TODO: We need to move the exception to an init() function. as the constructor
 * is notes fully complete, and exception would cause destructor to be called on
 * object that is not fully constructed
 */
class Aes : public Rijndael
{
  public:
    explicit Aes(const alc_cipher_algo_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.ai_mode }
    {}

  protected:
    Aes() { m_this = this; }
    virtual ~Aes() {}

    void setKey(const uint8_t* pUserKey, uint64_t len) override;

  protected:
    alc_cipher_mode_t     m_mode;
    void*                 m_this;
};

/*
 * \brief        AES Encryption in CBC(Cipher block chaining)
 * \notes        TODO: Move this to a aes_cbc.hh or other
 */
class Cbc final : public Aes
{
  public:
    explicit Cbc(const alc_cipher_algo_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Cbc() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t& keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err) override
    {
        Error::setDetail(err, ALC_ERROR_NOT_SUPPORTED);

        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_CBC) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief   CBC Encrypt Operation
     * \notes
     * \param   pPlainText      Pointer to output buffer
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const uint8_t* pPlainText,
                                uint8_t*       pCipherText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t encryptUpdate(const uint8_t* pPlainText,
                                      uint8_t*       pCipherText,
                                      uint64_t       len,
                                      const uint8_t* pIv);
    /**
     * \brief   CBC Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t decryptUpdate(const uint8_t* pCipherText,
                                      uint8_t*       pPlainText,
                                      uint64_t       len,
                                      const uint8_t* pIv);

  private:
    Cbc(){};

  private:
};

/*
 * \brief        AES Encryption in OFB(Output Feedback)
 * \notes        TODO: Move this to a aes_ofb.hh or other
 */
class Ofb final : public Aes
{
  public:
    explicit Ofb(const alc_cipher_algo_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Ofb() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t& keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err) override
    {
        Error::setDetail(err, ALC_ERROR_NOT_SUPPORTED);

        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_OFB) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief   OFB Encrypt Operation
     * \notes
     * \param   pPlainText      Pointer to output buffer
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const uint8_t* pPlainText,
                                uint8_t*       pCipherText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t encryptUpdate(const uint8_t* pPlainText,
                                      uint8_t*       pCipherText,
                                      uint64_t       len,
                                      const uint8_t* pIv);
    /**
     * \brief   OFB Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t decryptUpdate(const uint8_t* pCipherText,
                                      uint8_t*       pPlainText,
                                      uint64_t       len,
                                      const uint8_t* pIv);

  private:
    Ofb(){};

  private:
};

/*
 * \brief        AES Encryption in Ctr(Counter mode)
 * \notes        TODO: Move this to a aes_Ctr.hh or other
 */
class Ctr final : public Aes
{
  public:
    explicit Ctr(const alc_cipher_algo_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Ctr() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t& keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err) override
    {
        Error::setDetail(err, ALC_ERROR_NOT_SUPPORTED);

        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_CTR) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief   CTR Encrypt Operation
     * \notes
     * \param   pPlainText      Pointer to output buffer
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const uint8_t* pPlainText,
                                uint8_t*       pCipherText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t encryptUpdate(const uint8_t* pPlainText,
                                      uint8_t*       pCipherText,
                                      uint64_t       len,
                                      const uint8_t* pIv);

    /**
     * \brief   CTR Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t decryptUpdate(const uint8_t* pCipherText,
                                      uint8_t*       pPlainText,
                                      uint64_t       len,
                                      const uint8_t* pIv);

  private:
    Ctr(){};

  private:
};

/*
 * \brief        AES Encryption in GCM(Galois Counter mode)
 * \notes        TODO: Move this to a aes_Gcm.hh or other
 */
class Gcm final : public Aes
{

  public:
    // union to be used here: tbd
    // uint8_t m_hash_subKey[16];
    __m128i m_hash_subKey_128;

    // uint8_t m_gHash[16];
    __m128i m_gHash_128;

    // uint8_t m_tag[16];
    __m128i m_tag_128;

    __m128i m_reverse_mask_128;

    __m128i m_iv_128;

    uint64_t m_len;
    uint64_t m_additionalDataLen;
    uint64_t m_ivLen;
    uint64_t m_tagLen;
    uint64_t m_isHashSubKeyGenerated = false;

  public:
    explicit Gcm(const alc_cipher_algo_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {
        m_reverse_mask_128 =
            _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        m_gHash_128         = _mm_setzero_si128();
        m_hash_subKey_128   = _mm_setzero_si128();
        m_len               = 0;
        m_additionalDataLen = 0;
        m_tagLen            = 0;
        m_ivLen             = 12; // default 12 bytes or 96bits
    }

    ~Gcm() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t& keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo,
                             alc_error_t&             err) override
    {
        Error::setDetail(err, ALC_ERROR_NOT_SUPPORTED);

        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_GCM) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief   GCM Encrypt Operation
     * \notes
     * \param   pInput      Pointer to input buffer
     *                          (plainText or Additional data)
     * \param   pOuput          Pointer to encrypted buffer
     *                          when pointer NULL, input is additional data
     * \param   len             Len of input buffer
     *                          (plainText or Additional data)
     * \param   pIv             Pointer to Initialization Vector \return
     * alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const uint8_t* pInput,
                                uint8_t*       pOutput,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t encryptUpdate(const uint8_t* pInput,
                                      uint8_t*       pOutput,
                                      uint64_t       len,
                                      const uint8_t* pIv);

    /**
     * \brief   GCM Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    virtual alc_error_t decryptUpdate(const uint8_t* pCipherText,
                                      uint8_t*       pPlainText,
                                      uint64_t       len,
                                      const uint8_t* pIv);

  private:
    virtual alc_error_t cryptUpdate(const uint8_t* pInput,
                                    uint8_t*       pOutput,
                                    uint64_t       len,
                                    const uint8_t* pIv,
                                    bool           isEncrypt);
    Gcm(){};

  private:
};

} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
