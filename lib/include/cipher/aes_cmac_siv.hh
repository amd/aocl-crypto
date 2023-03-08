/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "cipher/aes.hh"

#include "mac/cmac.hh"
#include "utils/copy.hh"
#include <vector>

using Cmac = alcp::mac::Cmac;

namespace alcp::cipher {
// RFC5297

class ALCP_API_EXPORT CmacSiv : public Aes
{
  private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // FIXME: Need to be private or need some friend function thing
  protected:
    /**
     * @brief Generate Synthetic IV from Additional Data + Plaintext
     * @param plainText Plaintext Data Input
     * @param size Size of Plaintext
     * @return Status, is failure or success status object
     */
    Status s2v(const Uint8 plainText[], Uint64 size);

  public:
    CmacSiv();

    /**
     * @brief Set Keys for SIV and CTR
     * @param key1  Key for SIV
     * @param key2  Key for CTR
     * @param length  Length of each key, same length keys
     * @return Status
     */
    Status setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length);

    /**
     * @brief Set Padding Length
     * @param len length of the already padded data
     * @return
     */
    Status setPaddingLen(Uint64 len);

    // Section 2.4 in RFC
    /**
     * @brief Add An additonal Input into the SIV Algorithm
     * @param memory Pointer which points to the additional data.
     * @param length Length of the additional data
     * @return Status
     */
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);

    /**
     * @brief Write tag into a given buffer (128bits long)
     * @param out Pointer to a vlid memory to write the data into.
     * @return Status
     */
    Status getTag(Uint8 out[]);

    /* FIXME: Possibly need to depriciate this ones also. */
    /**
     * @brief Encrypt data, given all data.
     * @param pPlainText PlainText input
     * @param pCipherText CipherText output
     * @param len Length of PlainText/CipherText
     * @param pIv Unused IV
     * @return alc_error_t
     */
    alc_error_t encrypt(const Uint8* pPlainText,
                        Uint8*       pCipherText,
                        Uint64       len,
                        const Uint8* pIv) const;

    /**
     * @brief Decrypts data, given all data.
     * @param pCipherText CipherText Input
     * @param pPlainText PlainText output
     * @param len Length of PlainText/CipherText
     * @param pIv Previosly Generated Tag
     * @return alc_error_t
     */
    alc_error_t decrypt(const Uint8* pCipherText,
                        Uint8*       pPlainText,
                        Uint64       len,
                        const Uint8* pIv) const;

    /* Depriciated Functions */
    // FIXME: Needs to be removed from Cipher as a whole
    // Cipher support should end in capi
    CmacSiv(const alc_cipher_algo_info_t& aesInfo,
            const alc_key_info_t& keyInfo); // Depriciated, implemented for CAPI
    bool isSupported(const alc_cipher_info_t& cipherInfo);
    /**
     * @brief Depriciated, please use addAdditionalInput
     * @param memory Pointer which points to the additional data.
     * @param length Length of the additional data
     * @return alc_error_t
     */
    alc_error_t setAad(const Uint8 memory[], Uint64 length);
    /**
     * @brief Depriciated, please use getTag (alternative one with Status)
     * @param out Pointer to a valid memory to write the data into.
     * @param len Size of Tag (should be 128bits)
     * @return alc_error_t
     */
    alc_error_t getTag(Uint8 out[], Uint64 len); // Depriciated
};

class CmacSiv::Impl
{
  private:
    /*
       Set of preprocessed Additional Data. Its allocated in a chunk to avoid
       memory issues. Each chunk being 10 slots. Any number of addtional data
       can be given by user but most of the time it will be less than 10. So a
       default size of 10 is allocated.
    */
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    Uint64             m_additionalDataProcessedSize = {};
    const Uint8*       m_key1                        = {};
    const Uint8*       m_key2                        = {};
    Uint64             m_keyLength                   = {};
    const Uint64       m_sizeCmac                    = 128 / 8;
    Uint64             m_padLen                      = {};
    std::vector<Uint8> m_cmacTemp = std::vector<Uint8>(m_sizeCmac, 0);
    Cmac               m_cmac;
    Ctr                m_ctr;

  public:
    Impl(){};

    /**
     * @brief Generate Synthetic IV from Additional Data + Plaintext
     * @param plainText Plaintext Data Input
     * @param size Size of Plaintext
     * @return Status, is failure or success status object
     */
    Status s2v(const Uint8 plainText[], Uint64 size);

    /**
     * @brief Set Keys for SIV and CTR
     * @param key1  Key for SIV
     * @param key2  Key for CTR
     * @param length  Length of each key, same length keys
     * @return Status
     */
    Status setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length);

    // Section 2.4 in RFC
    /**
     * @brief Add An additonal Input into the SIV Algorithm
     * @param memory Pointer which points to the additional data.
     * @param length Length of the additional data
     * @return Status
     */
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);

    /**
     * @brief Set Padding Length
     * @param len length of the already padded data
     * @return
     */
    Status setPaddingLen(Uint64 len);

    /**
     * @brief Encrypt data, given all data.
     * @param pPlainText PlainText input
     * @param pCipherText CipherText output
     * @param len Length of PlainText/CipherText
     * @param pIv Unused IV
     * @return Status
     */
    Status encrypt(const Uint8 plainText[], Uint8 cipherText[], Uint64 len);

    /**
     * @brief Decrypts data, given all data.
     * @param pCipherText CipherText Input
     * @param pPlainText PlainText output
     * @param len Length of PlainText/CipherText
     * @param pIv Previosly Generated Tag
     * @return Status
     */
    Status decrypt(const Uint8  cipherText[],
                   Uint8        plainText[],
                   Uint64       len,
                   const Uint8* iv);

    /**
     * @brief Write tag into a given buffer (128bits long)
     * @param out Pointer to a vlid memory to write the data into.
     * @return Status
     */
    Status getTag(Uint8 out[]);

  private:
    /**
     * @brief Do Cmac implementation
     * @param key  Cmac Key
     * @param keySize Size of Cmac Key
     * @param data Pointer to data to do cmac on
     * @param size Size of the data
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @return Status
     */
    Status cmacWrapper(const Uint8 key[],
                       Uint64      keySize,
                       const Uint8 data[],
                       Uint64      size,
                       Uint8       mac[],
                       Uint64      macSize);

    /**
     * @brief Do Cmac implementation
     * @param key  Cmac Key
     * @param keySize Size of Cmac Key
     * @param data1 Pointer to data1 to do cmac on
     * @param size1 Size of the data1
     * @param data2 Pointer to data2 to do cmac on
     * @param size2 Size of the data2
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @return Status
     */
    Status cmacWrapperMultiData(const Uint8 key[],
                                Uint64      keySize,
                                const Uint8 data1[],
                                Uint64      size1,
                                const Uint8 data2[],
                                Uint64      size2,
                                Uint8       mac[],
                                Uint64      macSize);

    /**
     * @brief Do CTR Encryption/Decryption
     * @param key CTR Key
     * @param keySize Size of CTR Key
     * @param in Pointer to input memory to do CTR on
     * @param out Pointer to output memory
     * @param size Size of the in
     * @param iv Synthetic IV Obtained
     * @param enc If True will be encrypt otherwise Decrypt
     * @return Status
     */
    Status ctrWrapper(const Uint8 key[],
                      Uint64      keySize,
                      const Uint8 in[],
                      Uint8       out[],
                      Uint64      size,
                      Uint8       iv[],
                      bool        enc);
};

} // namespace alcp::cipher