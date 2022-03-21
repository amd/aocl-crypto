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
    explicit Aes(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.ai_mode }
    {}

  protected:
    Aes() { m_this = this; }
    virtual ~Aes() {}

    void setKey(const uint8_t* pUserKey, uint64_t len) override;

  protected:
    alc_aes_mode_t m_mode;
    void*          m_this;
};

/*
 * \brief        AES Encryption in CFB(Cipher Feedback mode)
 * \notes        TODO: Move this to a aes_cbc.hh or other
 */
class Cfb final : public Aes
{
  public:
    explicit Cfb(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Cfb() {}

  public:
    static bool isSupported(const alc_aes_info_t& cipherInfo,
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
            auto aip = &cipherInfo.ci_mode_data.cm_aes;
            if (aip->ai_mode == ALC_AES_MODE_CFB) {
                Error::setDetail(err, ALC_ERROR_NONE);
                return true;
            }
        }

        return false;
    }

    /**
     * \brief   CFB Encrypt Operation
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

    /**
     * \brief   CFB Decrypt Operation
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

  private:
    Cfb(){};

  private:
};

/*
 * \brief        AES Encryption in CBC(Cipher block chaining)
 * \notes        TODO: Move this to a aes_cbc.hh or other
 */
class Cbc final : public Aes
{
  public:
    explicit Cbc(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Cbc() {}

  public:
    static bool isSupported(const alc_aes_info_t& cipherInfo,
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
            auto aip = &cipherInfo.ci_mode_data.cm_aes;
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
    explicit Ofb(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Ofb() {}

  public:
    static bool isSupported(const alc_aes_info_t& cipherInfo,
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
            auto aip = &cipherInfo.ci_mode_data.cm_aes;
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
    explicit Ctr(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Ctr() {}

  public:
    static bool isSupported(const alc_aes_info_t& cipherInfo,
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
            auto aip = &cipherInfo.ci_mode_data.cm_aes;
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

  private:
    Ctr(){};

  private:
};
} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
