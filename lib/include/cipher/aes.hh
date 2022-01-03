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
#include "error.hh"

namespace alcp::cipher {

class Rijndael : public alcp::BlockCipher
//, public Algorithm
{
  public:
    static int constexpr cAlignment     = 16;
    static int constexpr cAlignmentWord = cAlignment / 4;

    static int constexpr cMinKeySize      = 128;
    static int constexpr cMaxKeySize      = 256;
    static int constexpr cMaxKeySizeBytes = cMaxKeySize / 8;

    static int constexpr cMaxRounds = 14;

    /* Message size, key size, etc */
    enum BlockSize
    {
        eBits128 = 128,
        eBits192 = 192,
        eBits256 = 256,

        eBytes128 = eBits128 / 8,
        eBytes192 = eBits192 / 8,
        eBytes256 = eBits256 / 8,

        eWords128 = eBytes128 / 4,
        eWords192 = eBytes192 / 4,
        eWords256 = eBytes256 / 4,
    };

    static BlockSize BitsToBlockSize(int iVal)
    {
        switch (iVal) {
            case 128:
                return eBits128;
            case 192:
                return eBits192;
            case 256:
                return eBits256;
            default:
                assert(false);
                break;
        }
    }

    const std::map<BlockSize, int> RoundMap = {
        { eBits128, 10 },  { eBits192, 12 },  { eBits256, 14 },
        { eBytes128, 10 }, { eBytes192, 12 }, { eBytes256, 14 },

    };

    constexpr int BitsToBytes(int cBits) { return cBits / 8; }
    constexpr int BitsToWord(int cBits) { return cBits / 32; }
    constexpr int BytesToWord(int cBytes) { return cBytes / 4; }

  public:
    uint64_t       getRounds() { return m_nrounds; }
    uint64_t       getKeySize() { return m_key_size; }
    const uint8_t* getRoundKey() { return m_round_key; }

  protected:
    Rijndael() {}

    Rijndael(const alc_key_info_t& rKeyInfo)
    {
        int len      = rKeyInfo.len;
        m_block_size = BitsToBlockSize(len);
        m_nrounds    = RoundMap.at(m_block_size);

        m_key_size = BitsToBytes(len);

        /* Encryption and Decryption key offsets */
        m_enc_key = &m_round_key[0];
        /* +1 as the actual key is also stored  */
        m_dec_key = m_enc_key + ((m_nrounds + 1) * m_key_size);

        expandKeys(rKeyInfo.key, m_enc_key, m_dec_key);
    }

    virtual ~Rijndael() {}

    void expandKeys(const uint8_t* pUserKey,
                    uint8_t*       pEncKey,
                    uint8_t*       pDecKey);

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)
#define RIJ_ALIGN           (16)
  protected:
    /* +2 as we store actual key as well */
    uint8_t  m_round_key[RIJ_SIZE_ALIGNED(cMaxKeySizeBytes) * (cMaxRounds + 2)];
    uint8_t* m_enc_key; /* encryption key: points to offset in 'm_key' */
    uint8_t* m_dec_key; /* decryption key: points to offset in 'm_key' */

    uint64_t  m_nrounds;
    uint64_t  m_key_size;
    BlockSize m_block_size;

  private:
};

/*
 * \brief       AES (Advanced Encryption Standard)
 *
 * \notes       AES is currently same as Rijndael, This may be renamed to
 *              other as well in the future.
 *
 */
class Aes : public Rijndael
{
  public:
    explicit Aes(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.mode }

    {}

  protected:
    Aes() {}
    virtual ~Aes() {}

  protected:
    alc_aes_mode_t m_mode;
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

class AesBuilder
{
  public:
    static Cipher* Build(const alc_aes_info_t& aesInfo,
                         const alc_key_info_t& keyInfo,
                         Handle&               rHandle,
                         alc_error_t&          err);
};

class CipherBuilder
{
  public:
    static Cipher* Build(const alc_cipher_info_t& cipherInfo,
                         Handle&                  rHandle,
                         alc_error_t&             err);
};

} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
