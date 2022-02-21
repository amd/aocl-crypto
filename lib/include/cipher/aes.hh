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

#include <cstdalign>
#include <cstdint>
#include <map>

#include <immintrin.h>

#include "alcp/cipher.h"

//#include "algorithm.hh"
#include "cipher.hh"
#include "exception.hh"

#include "utils/bits.hh"

namespace alcp::cipher {

class Rijndael : public alcp::BlockCipher
//, public Algorithm
{
  public:
    static uint32 constexpr cAlignment     = 16;
    static uint32 constexpr cAlignmentWord = cAlignment / utils::BytesPerWord;

    static uint32 constexpr cMinKeySizeBits = 128;
    static uint32 constexpr cMaxKeySizeBits = 256;
    static uint32 constexpr cMaxKeySize = cMaxKeySizeBits / utils::BitsPerByte;

    /*
     * FIPS-197  Chapter5, Figure-4
     *                Key Length         Block Size     No. of Rounds
     *                (Nk words)         (Nb words)      (Nr)
     *   AES-128         4               4               10
     *   AES-192         6               4               12
     *   AES-256         8               4               14
     *
     */
    static uint32 constexpr cBlockSizeBits = 128;
    static uint32 constexpr cBlockSize = cBlockSizeBits / utils::BitsPerByte;
    static uint32 constexpr cBlockSizeWord = cBlockSize / utils::BytesPerWord;

    static uint32 constexpr cMaxRounds = 14;

    /* Message size, key size, etc */
    enum BlockSize : uint32_t
    {
        eBits128 = 128,
        eBits192 = 192,
        eBits256 = 256,
    };

    struct Params
    {
        uint32 Nk;
        uint32 Nb;
        uint32 Nr;
    };

    const std::map<BlockSize, Params> ParamsMap = {
        { eBits128, { 4, 4, 10 } },
        { eBits192, { 6, 4, 12 } },
        { eBits256, { 8, 4, 14 } },
    };

    static BlockSize BitsToBlockSize(int iVal)
    {
        BlockSize bs;
        // clang-format off
        switch (iVal) {
            case 128: bs = eBits128; break;
            case 192: bs = eBits192; break;
            case 256: bs = eBits256; break;
            default:  assert(false); break;
        }
        // clang-format on
        return bs;
    }

    /* TODO: Use bit/byte conversion from utils */
    constexpr uint32_t BitsToWords(uint32_t cBits)
    {
        return utils::BytesInBits(int(m_block_size));
    }

    /* Nk - number of words in key128/key192/key256 */
    constexpr uint32 getNk() { return m_nk; }

    /* Nr - Number of rounds */
    constexpr uint32 getNr() { return m_nrounds; }

    /* Nb - No of words in a block (block is always 128-bits) */
    constexpr uint32_t getNb() { return 4 * utils::BytesPerWord; }

  public:
    uint64_t       getRounds() { return m_nrounds; }
    uint64_t       getKeySize() { return m_key_size; }
    const uint8_t* getRoundKey() { return m_round_key; }

  protected:
    Rijndael() {}

    Rijndael(const alc_key_info_t& rKeyInfo)
        : Rijndael{}
    {
        setUp(rKeyInfo);
    }

    void setUp(const alc_key_info_t& rKeyInfo)
    {
        int len           = rKeyInfo.len;
        m_block_size      = BitsToBlockSize(len);
        const Params& prm = ParamsMap.at(m_block_size);
        m_nrounds         = prm.Nr;
        m_nk              = prm.Nk;

        m_key_size = len / utils::BitsPerByte;

        /* Encryption and Decryption key offsets */
        m_enc_key = &m_round_key[0];
        /* +1 as the actual key is also stored  */
        m_dec_key = m_enc_key + ((m_nrounds + 1) * m_key_size);

        expandKeys(rKeyInfo.key, m_enc_key, m_dec_key);
    }

    virtual ~Rijndael();

    void expandKeys(const uint8_t* pUserKey,
                    uint8_t*       pEncKey,
                    uint8_t*       pDecKey) noexcept;

    void subBytes(uint8_t state[][4]) noexcept;
    void shiftRows(uint8_t state[][4]) noexcept;
    void mixColumns(uint8_t state[][4]) noexcept;
    void addRoundKey(uint8_t state[][4], uint8_t k[][4]) noexcept;

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)
#define RIJ_ALIGN           (16)
  protected:
    /* +2 as we store actual key as well */
    uint8_t  m_round_key[RIJ_SIZE_ALIGNED(cMaxKeySize) * (cMaxRounds + 2)];
    uint8_t* m_enc_key; /* encryption key: points to offset in 'm_key' */
    uint8_t* m_dec_key; /* decryption key: points to offset in 'm_key' */

    uint64_t  m_nrounds;  /* no of rounds */
    uint64_t  m_ncolumns; /* no of columns in a input block seen as matrix */
    uint64_t  m_key_size; /* key size in bits */
    uint64_t  m_nk;       /* Nk of FIPS-197 */
    BlockSize m_block_size;

  private:
};

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
        , m_mode{ aesInfo.mode }

    { // clang-format off
        switch (keyInfo.len_type) {
            case ALC_KEY_LEN_128: m_ncolumns = 4; m_nk = 4; break;
            case ALC_KEY_LEN_192: m_ncolumns = 5; m_nk = 6; break;
            case ALC_KEY_LEN_256: m_ncolumns = 6; m_nk = 8; break;
            default:
                InvalidArgumentException("Length not supported");
                break;
        }
        // clang-format on
    }

  protected:
    Aes() { m_this = this; }
    virtual ~Aes() {}

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

        if (cipherInfo.cipher_type == ALC_CIPHER_TYPE_AES) {
            if (cipherInfo.mode_data.aes.mode == ALC_AES_MODE_CFB) {
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
                                const uint8_t* pIv) const override final;

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

        if (cipherInfo.cipher_type == ALC_CIPHER_TYPE_AES) {
            if (cipherInfo.mode_data.aes.mode == ALC_AES_MODE_CBC) {
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

        if (cipherInfo.cipher_type == ALC_CIPHER_TYPE_AES) {
            if (cipherInfo.mode_data.aes.mode == ALC_AES_MODE_OFB) {
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
} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
