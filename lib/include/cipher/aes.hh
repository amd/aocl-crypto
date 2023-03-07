/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

// #include "algorithm.hh"
#include "alcp/base.hh"
#include "cipher.hh"
#include "cipher/rijndael.hh"
#include "utils/bits.hh"

#include <immintrin.h>
#include <wmmintrin.h>

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)

namespace alcp::cipher {

using Status = alcp::base::Status;

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
    explicit Aes(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.ai_mode }
    {
    }

  protected:
    virtual ~Aes() {}

    // FIXME:
    // Without CMAC-SIV extending AES, we cannot access it with protected,
    // Please change to protected if needed in future
  public:
    Aes() { m_this = this; }

    ALCP_API_EXPORT virtual Status setKey(const Uint8* pUserKey,
                                          Uint64       len) override;

  protected:
    ALCP_API_EXPORT virtual Status setMode(alc_cipher_mode_t mode);

  protected:
    alc_cipher_mode_t m_mode;
    void*             m_this;
};

/*
 * \brief        AES Encryption in CBC(Cipher block chaining)
 * \notes        TODO: Move this to a aes_cbc.hh or other
 */
class ALCP_API_EXPORT Cbc final : public Aes
{
  public:
    explicit Cbc(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {
    }

    ~Cbc() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_CBC) {
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
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * \brief   CBC Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

  private:
    Cbc(){};

  private:
};

/*
 * \brief        AES Encryption in OFB(Output Feedback)
 * \notes        TODO: Move this to a aes_ofb.hh or other
 */
class ALCP_API_EXPORT Ofb final : public Aes
{
  public:
    explicit Ofb(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {
    }

    ~Ofb() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_OFB) {
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
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * \brief   OFB Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

  private:
    Ofb(){};

  private:
};

/*
 * \brief        AES Encryption in Ctr(Counter mode)
 * \notes        TODO: Move this to a aes_Ctr.hh or other
 */
class ALCP_API_EXPORT Ctr final : public Aes
{
  public:
    Ctr() { Aes::setMode(ALC_AES_MODE_CTR); };
    explicit Ctr(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {
    }

    ~Ctr() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo)
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_CTR) {
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
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * \brief   CTR Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

  private:
};

/*
 * \brief        AES Encryption in GCM(Galois Counter mode)
 * \notes        TODO: Move this to a aes_Gcm.hh or other
 */
class ALCP_API_EXPORT Gcm final
    : public Aes
    , cipher::IDecryptUpdater
    , cipher::IEncryptUpdater
{

  public:
    // union to be used here: tbd
    // Uint8 m_hash_subKey[16];
    __m128i m_hash_subKey_128;

    // Uint8 m_gHash[16];
    __m128i m_gHash_128;

    // Uint8 m_tag[16];
    __m128i m_tag_128;

    __m128i m_reverse_mask_128;

    __m128i m_iv_128;

    const Uint8* m_iv = nullptr;

    Uint64 m_len;
    Uint64 m_additionalDataLen;
    Uint64 m_ivLen;
    Uint64 m_tagLen;
    Uint64 m_isHashSubKeyGenerated = false;

  public:
    explicit Gcm(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
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
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_GCM) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Get a copy of the Tag
     *
     * @param pOutput Memory to write tag into
     * @param len     Length of the tag in bytes
     * @return alc_error_t Error code
     */
    virtual alc_error_t getTag(Uint8* pOutput, Uint64 len);

    /**
     * @brief Set the Iv in bytes
     *
     * @param len Length of IV in bytes
     * @param pIv Address to read the IV from
     * @return alc_error_t Error code
     */
    virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

    /**
     * @brief Set the Additional Data in bytes
     *
     * @param pInput Address to Read Additional Data from
     * @param len Length of Additional Data in Bytes
     * @return alc_error_t
     */
    virtual alc_error_t setAad(const Uint8* pInput, Uint64 len);

    /**
     * \brief  GCM Invalid Encrypt Operartion
     * \notes  Use encryptUpdate instead
     * \param   pInput      Pointer to input buffer
     *                          (plainText or Additional data)
     * \param   pOuput          Pointer to encrypted buffer
     *                          when pointer NULL, input is additional data
     * \param   len             Len of input buffer
     *                          (plainText or Additional data)
     * \param   pIv             Pointer to Initialization Vector \return
     * alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const Uint8* pInput,
                                Uint8*       pOutput,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * @brief   GCM Encrypt Operation
     *
     * @param   pInput      Pointer to input buffer
     *                          (plainText or Additional data)
     * @param   pOuput          Pointer to encrypted buffer
     *                          when pointer NULL, input is additional data
     * @param   len             Len of input buffer
     *                          (plainText or Additional data)
     * @param   pIv             Pointer to Initialization Vector \return
     * @return alc_error_t
     */
    virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                      Uint8*       pOutput,
                                      Uint64       len,
                                      const Uint8* pIv) override;

    /**
     * \brief   GCM Invalid Decrypt Operation
     * \notes   Use decryptUpdate instead
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * @brief   GCM Decrypt Operation
     *
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                      Uint8*       pPlainText,
                                      Uint64       len,
                                      const Uint8* pIv) override;

  private:
    /**
     * @brief   GCM Encrypt/Decrypt Operation
     *
     * @param   pCipherText     Pointer to input buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t cryptUpdate(const Uint8* pInput,
                                    Uint8*       pOutput,
                                    Uint64       len,
                                    const Uint8* pIv,
                                    bool         isEncrypt);
    Gcm(){};

  private:
};

/**
 * @brief CCM mode (Copy of GCM class)
 * Uses encryptUpdate and decryptUpdate instead of
 * encrypt and decrypt.
 */

struct _ccm_data_t
{
    alignas(16) Uint8 nonce[16];
    alignas(16) Uint8 cmac[16];
    const Uint8* key    = nullptr;
    Uint64       blocks = 0;
    Uint32       rounds = 0;
};
typedef _ccm_data_t *     ccm_data_p, ccm_data_t;
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
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {
    }

    ~Ccm() {}

    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo)
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
     * \brief   CCM Encrypt Operation
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
    virtual alc_error_t encrypt(const Uint8* pInput,
                                Uint8*       pOutput,
                                Uint64       len,
                                const Uint8* pIv) const final;

    virtual alc_error_t encryptUpdate(const Uint8* pInput,
                                      Uint8*       pOutput,
                                      Uint64       len,
                                      const Uint8* pIv) override;

    /**
     * \brief   CCM Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    virtual alc_error_t decryptUpdate(const Uint8* pCipherText,
                                      Uint8*       pPlainText,
                                      Uint64       len,
                                      const Uint8* pIv) override;

  private:
    virtual alc_error_t cryptUpdate(const Uint8* pInput,
                                    Uint8*       pOutput,
                                    Uint64       len,
                                    const Uint8* pIv,
                                    bool         isEncrypt);
    virtual void   CcmInit(ccm_data_p ccm_data, unsigned int t, unsigned int q);
    virtual int    CcmSetIv(ccm_data_p   ccm_data,
                            const Uint8* pnonce,
                            size_t       nlen,
                            size_t       mlen);
    virtual size_t CcmGetTag(ccm_data_p ctx, Uint8* ptag, size_t len);
    Ccm(){};
};

/*
 * \brief        AES Encryption in XTS(XEX Tweakable Block Ciphertext
 * Stealing Mode)
 */
class ALCP_API_EXPORT Xts final : public Aes
{

  public:
    explicit Xts(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {
        p_tweak_key = &m_tweak_round_key[0];
        expandTweakKeys(aesInfo.ai_xts.xi_tweak_key->key,
                        aesInfo.ai_xts.xi_tweak_key->len);
    }

    ~Xts() {}

  public:
    virtual alc_error_t setIv(Uint64 len, const Uint8* pIv);

    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_XTS)
                return true;
        }

        return false;
    }

    /**
     * \brief   XTS Encrypt Operation
     * \notes
     * \param   pPlainText      Pointer to output buffer
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * \brief   XTS Decrypt Operation
     * \notes
     * \param   pCipherText     Pointer to encrypted buffer
     * \param   pPlainText      Pointer to output buffer
     * \param   len             Len of plain and encrypted text
     * \param   pIv             Pointer to Initialization Vector
     * \return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    virtual void expandTweakKeys(const Uint8* pUserKey, int len);

  private:
    Xts() { p_tweak_key = &m_tweak_round_key[0]; };

  private:
    Uint8  m_tweak_round_key[(RIJ_SIZE_ALIGNED(32) * (16))];
    Uint8* p_tweak_key; /* Tweak key(for aes-xts mode): points to offset in
                           'm_tweak_key' */
};

} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
