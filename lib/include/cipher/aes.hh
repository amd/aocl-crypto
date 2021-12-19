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

//#include <array>
#include <cstdalign>
#include <cstdint>

#include <immintrin.h>

#include "alcp/cipher.h"

#include "algorithm.hh"
#include "cipher.hh"
#include "error.hh"
#include "misc/notimplemented.hh"

namespace alcp::cipher {

class Rijndael : public alcp::BlockCipher
//, public Algorithm
{
  public:
    static int constexpr cAlignment     = 16;
    static int constexpr cAlignmentWord = cAlignment / 4;

    static int constexpr cMaxKeySize      = 256;
    static int constexpr cMaxKeySizeBytes = cMaxKeySize / 8;

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

    constexpr int BitsToBytes(int cBits) { return cBits / 8; }
    constexpr int BitsToWord(int cBits) { return cBits / 32; }
    constexpr int BytesToWord(int cBytes) { return cBytes / 4; }

  public:
    uint64_t       getRounds() { return m_nrounds; }
    uint64_t       getKeySize() { return m_key_size; }
    const uint8_t* getKey() { return m_key; }

  protected:
    Rijndael() {}
    Rijndael(const alc_key_info_t& rKeyInfo)
    {
        m_encKey = &m_key[0];
        /* TODO: Fix the decrypt key offset */
        m_decKey = m_encKey + m_nrounds * m_key_size;
    }

    virtual ~Rijndael() {}

    void expandKeys(const uint8_t* pUserKey,
                    uint8_t*       pEncKey,
                    uint8_t*       pDecKey);

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)
#define RIJ_ALIGN           (16)
  protected:
    alignas(cMaxKeySizeBytes) uint8_t m_key[RIJ_SIZE_ALIGNED(cMaxKeySizeBytes)];
    uint8_t* m_encKey; /* encryption key: points to offset in 'm_key' */
    uint8_t* m_decKey; /* decryption key: points to offset in 'm_key' */

    uint64_t m_nrounds;
    uint64_t m_key_size;

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
    Aes(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.mode }

    {

        /* TODO: adjust m_encKey and m_decKey accordingly */
        expandKeys(keyInfo.key, m_encKey, m_decKey);
    }

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
    Cfb(const alc_aes_info_t& aesInfo, const alc_key_info_t& keyInfo)
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
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual alc_error_t encrypt(const uint8_t* pPlainText,
                                uint8_t*       pCipherText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

    /**
     * \brief
     * \notes
     * \param
     * \return
     */
    virtual alc_error_t decrypt(const uint8_t* pCipherText,
                                uint8_t*       pPlainText,
                                uint64_t       len,
                                const uint8_t* pIv) const final;

  private:
    Cfb() = default;

  private:
    /* TODO: Do we really need to store Initialization Vector ? */
    uint8_t m_iv[256];
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

#endif /* _CIPHER_AES_H_ */
