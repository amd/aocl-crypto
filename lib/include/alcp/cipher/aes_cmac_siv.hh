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
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/cipher_error.hh"
#include "alcp/cipher/common.hh"
#include "alcp/utils/cpuid.hh"

#include "alcp/cipher/aes_cmac_siv_arch.hh"

#include "alcp/mac/cmac.hh"
#include "alcp/utils/copy.hh"
#include <new>
#include <vector>

using Cmac = alcp::mac::Cmac;
#define SIZE_CMAC 128 / 8
namespace alcp::cipher {

using utils::CpuId;

// RFC5297

template<typename T1>
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

    CmacSiv(const alc_key_info_t& encKey, const alc_key_info_t& authKey);

    /* Depriciated Functions */
    // FIXME: Needs to be removed from Cipher as a whole

    static bool isSupported(const Uint32 keyLen);

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

template<typename T>
class CmacSiv<T>::Impl
{
  private:
    /*
       Set of preprocessed Additional Data. Its allocated in a chunk to avoid
       memory issues. Each chunk being 10 slots. Any number of addtional data
       can be given by user but most of the time it will be less than 10. So a
       default size of 10 is allocated.
    */
    // std::vector<std::vector<Uint8>> m_additionalDataProcessed =
    //     std::vector<std::vector<Uint8>>(10);
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    Uint64       m_additionalDataProcessedSize = {};
    const Uint8* m_key1                        = {};
    const Uint8* m_key2                        = {};
    Uint64       m_keyLength                   = {};
    Uint64       m_padLen                      = {};
    alignas(16) Uint8 m_cmacTemp[SIZE_CMAC]    = {};
    Cmac m_cmac;
    T    m_ctr; // FIXME: based on the key size appropriate Ctr class
                // to be choosen.

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
     * @param data Pointer to data to do cmac on
     * @param size Size of the data
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @param enc Encrypt (True) or Decrypt (False)
     * @return Status
     */
    Status ctrWrapper(
        const Uint8 in[], Uint8 out[], Uint64 size, Uint8 mac[], bool enc);

    /**
     * @brief Do Cmac implementation
     * @param data1 Pointer to data1 to do cmac on
     * @param size1 Size of the data1
     * @param data2 Pointer to data2 to do cmac on
     * @param size2 Size of the data2
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @return Status
     */
    Status cmacWrapperMultiData(const Uint8 data1[],
                                Uint64      size1,
                                const Uint8 data2[],
                                Uint64      size2,
                                Uint8       mac[],
                                Uint64      macSize);

    /**
     * @brief Do CTR Encryption/Decryption
     * @param in Pointer to input memory to do CTR on
     * @param out Pointer to output memory
     * @param size Size of the in
     * @param iv Synthetic IV Obtained
     * @param enc If True will be encrypt otherwise Decrypt
     * @return Status
     */
    Status cmacWrapper(const Uint8 data[],
                       Uint64      size,
                       Uint8       mac[],
                       Uint64      macSize);
};

template<typename T>
Status
CmacSiv<T>::Impl::cmacWrapper(const Uint8 data[],
                              Uint64      size,
                              Uint8       mac[],
                              Uint64      macSize)
{
    Status s{ StatusOk() };
    s = m_cmac.finalize(data, size);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.copy(mac, macSize);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.reset();
    if (!s.ok()) {
        return s;
    }
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::cmacWrapperMultiData(const Uint8 data1[],
                                       Uint64      size1,
                                       const Uint8 data2[],
                                       Uint64      size2,
                                       Uint8       mac[],
                                       Uint64      macSize)
{
    Status s{ StatusOk() };
    s = m_cmac.update(data1, size1);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.finalize(data2, size2);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.copy(mac, macSize);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.reset();
    if (!s.ok()) {
        return s;
    }
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::ctrWrapper(
    const Uint8 in[], Uint8 out[], Uint64 size, Uint8 mac[], bool enc)
{
    Status s = StatusOk();

    // FIXME: To be removed once we move everything to Status
    alc_error_t err = ALC_ERROR_NONE;
    if (enc) {
        err = m_ctr.encrypt(in, out, size, mac);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s;
        }
    } else {
        err = m_ctr.decrypt(in, out, size, mac);
        if (alcp_is_error(err)) {
            auto cer = status::DecryptFailed("Decryption Kernel Failed!");
            s.update(cer);
            return s;
        }
    }
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::setPaddingLen(Uint64 len)
{
    Status s = StatusOk();
    m_padLen = len;
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    Status             s    = StatusOk();
    std::vector<Uint8> zero = std::vector<Uint8>(SIZE_CMAC, 0);

    // Do a cmac of Zero Vector, first additonal data.
    s = cmacWrapper(&(zero.at(0)), zero.size(), m_cmacTemp, SIZE_CMAC);

    if (!s.ok()) {
        return s;
    }

    // std::cout << "ZERO_VECT:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

    Uint8 rb[16] = {};
    rb[15]       = 0x87;

    // For each user provided additional data do the dbl and xor to complete
    // processing
    if (CpuId::cpuHasAvx2()) {
        avx2::processAad(m_cmacTemp,
                         m_additionalDataProcessed,
                         m_additionalDataProcessedSize);
    } else {
        for (Uint64 i = 0; i < m_additionalDataProcessedSize; i++) {

            alcp::cipher::dbl(&(m_cmacTemp[0]), rb);

            // std::cout << "dbl:" << parseBytesToHexStr(m_cmacTemp) <<
            // std::endl;

            alcp::cipher::xor_a_b(&m_cmacTemp[0],
                                  &(m_additionalDataProcessed.at(i).at(0)),
                                  &m_cmacTemp[0],
                                  SIZE_CMAC);
        }
    }

    // If the size of plaintext is lower there is special case
    if (size >= SIZE_CMAC) {

        // Take out last block
        if (CpuId::cpuIsZen3()) {
            zen3::xor_a_b((plainText + size - SIZE_CMAC),
                          m_cmacTemp,
                          m_cmacTemp,
                          SIZE_CMAC);
        } else {
            xor_a_b((plainText + size - SIZE_CMAC),
                    m_cmacTemp,
                    m_cmacTemp,
                    SIZE_CMAC);
        }

        s = cmacWrapperMultiData(plainText,
                                 (size - SIZE_CMAC),
                                 m_cmacTemp,
                                 SIZE_CMAC,
                                 m_cmacTemp,
                                 SIZE_CMAC);
    } else {
        Uint8 temp_bytes[16] = {};
        // Padding Hack
        temp_bytes[0] = 0x80;
        // Speical case size lower for plain text need to do double and padding
        if (CpuId::cpuHasAvx2()) {
            avx2::dbl(&(m_cmacTemp[0]));
        }
        // alcp::cipher::dbl(&(m_cmacTemp[0]), rb, &(m_cmacTemp[0]));
        // std::cout << "dbl:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        xor_a_b(plainText, m_cmacTemp, m_cmacTemp, size);
        // Padding
        xor_a_b(
            temp_bytes, m_cmacTemp + size, m_cmacTemp + size, (SIZE_CMAC)-size);

        // std::cout << "xor:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        s = cmacWrapper(m_cmacTemp, SIZE_CMAC, m_cmacTemp, SIZE_CMAC);
    }
    if (!s.ok()) {
        return s;
    }
    // std::cout << "V:  " << parseBytesToHexStr(m_cmacTemp) << std::endl;
    // Now m_cmacTemp is the offical SIV
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length)
{
    Status s    = StatusOk();
    m_keyLength = length;

    // Block all unknown keysizes
    switch (length) {
        case 128:
        case 192:
        case 256:
            break;
        default:
            auto cer = cipher::CipherError(cipher::ErrorCode::eInvaidValue);
            s.update(cer, cer.message());
            return s;
    }

    m_key1 = key1;
    m_key2 = key2;

    s = m_cmac.setKey(m_key1, m_keyLength);
    if (!s.ok()) {
        return s;
    }

    s = m_ctr.setKey(m_key2, m_keyLength);
    return s;
}

// Section 2.4 in RFC
template<typename T>
Status
CmacSiv<T>::Impl::addAdditionalInput(const Uint8 memory[], Uint64 length)
{

    Status s = StatusOk();

    // FIXME: Allocate SIZE_CMAC for 10 vectors on intialization to be more
    // optimal.

    // Extend size of additonalDataProcessed Vector in case of overflow
    if ((m_additionalDataProcessedSize + 1)
        == m_additionalDataProcessed.size()) {
        m_additionalDataProcessed.resize(m_additionalDataProcessed.size() + 10);
    }

    // Block Null Keys or non set Keys.
    if (m_key1 == nullptr || m_key2 == nullptr) {
        auto cer = cipher::CipherError(cipher::ErrorCode::eInvaidValue);
        s.update(cer, cer.message());
        return s;
    }

    // Allocate memory for additonal data processed vector
    m_additionalDataProcessed.at(m_additionalDataProcessedSize) =
        std::vector<Uint8>(SIZE_CMAC);

    // Do cmac for additional data and set it to the proceed data.
    s = cmacWrapper(
        memory,
        length,
        &((m_additionalDataProcessed.at(m_additionalDataProcessedSize)).at(0)),
        SIZE_CMAC);

    if (!s.ok()) {
        return s;
    }

    // Increment the size of Data Processed if no errors
    m_additionalDataProcessedSize += 1;
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::encrypt(const Uint8 plainText[],
                          Uint8       cipherText[],
                          Uint64      len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(plainText, len);

    if (!s.ok()) {
        return s;
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    // Do the CTR
    s = ctrWrapper(plainText, cipherText, len + m_padLen, q, true);

    if (!s.ok()) {
        return s;
    }
    return s;
}

template<typename T>
Status
CmacSiv<T>::Impl::decrypt(const Uint8  cipherText[],
                          Uint8        plainText[],
                          Uint64       len,
                          const Uint8* iv)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = iv[i] & q[i];
    }

    // Do the CTR
    s = ctrWrapper(cipherText, plainText, len + m_padLen, q, false);

    if (!s.ok()) {
        return s;
    }

    // Create the tag from generated plain text
    s = s2v(plainText, len);

    // Verify tag, which just got generated
    if (memcmp(&(m_cmacTemp[0]), iv, SIZE_CMAC) != 0) {
        // FIXME: Initiate Wipedown!
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
        return s;
    }
    return s;
}

template<typename T>
CmacSiv<T>::CmacSiv()
    : pImpl{ std::make_unique<Impl>() }
{}

template<typename T>
CmacSiv<T>::CmacSiv(const alc_key_info_t& encKey, const alc_key_info_t& authKey)
    : pImpl{ std::make_unique<Impl>() }
{
    assert(authKey.len == encKey.len);
    setKeys(authKey.key, encKey.key, encKey.len);
}

template<typename T>
Status
CmacSiv<T>::Impl::getTag(Uint8 out[])
{
    Status s = StatusOk();
    utils::CopyBytes(out, &m_cmacTemp[0], SIZE_CMAC);
    memset(&m_cmacTemp[0], 0, 16);
    m_additionalDataProcessedSize = 0;
    return s;
}

template<typename T>
Status
CmacSiv<T>::s2v(const Uint8 plainText[], Uint64 size)
{
    return pImpl->s2v(plainText, size);
}

template<typename T>
Status
CmacSiv<T>::getTag(Uint8 out[])
{
    return pImpl->getTag(out);
}

template<typename T>
alc_error_t
CmacSiv<T>::getTag(Uint8 out[], Uint64 len)
{
    if (len != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    Status s = getTag(out);
    if (s.ok()) {
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_GENERIC;
    }
}

template<typename T>
Status
CmacSiv<T>::setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length)
{
    return pImpl->setKeys(key1, key2, length);
}

template<typename T>
alc_error_t
CmacSiv<T>::setAad(const Uint8 memory[], Uint64 length)
{
    Status s = pImpl->addAdditionalInput(memory, length);
    if (s.ok()) {
        return ALC_ERROR_NONE;
    } else {
        return ALC_ERROR_INVALID_DATA;
    }
}

template<typename T>
Status
CmacSiv<T>::addAdditionalInput(const Uint8 memory[], Uint64 length)
{
    return pImpl->addAdditionalInput(memory, length);
}

template<typename T>
Status
CmacSiv<T>::setPaddingLen(Uint64 len)
{
    return pImpl->setPaddingLen(len);
}

template<typename T>
alc_error_t
CmacSiv<T>::encrypt(const Uint8* pPlainText,
                    Uint8*       pCipherText,
                    Uint64       len,
                    const Uint8* pIv) const
{
    alc_error_t err = ALC_ERROR_NONE;

    Status s = pImpl->encrypt(pPlainText, pCipherText, len);
    if (!s.ok()) {
        err = ALC_ERROR_GENERIC;
    }

    return err;
}

template<typename T>
alc_error_t
CmacSiv<T>::decrypt(const Uint8* pCipherText,
                    Uint8*       pPlainText,
                    Uint64       len,
                    const Uint8* pIv) const

{
    alc_error_t err = ALC_ERROR_NONE;
    Status      s   = pImpl->decrypt(pCipherText, pPlainText, len, pIv);
    if (!s.ok()) {
        err = ALC_ERROR_GENERIC;
        // std::cout << "IV Verify Failed!" << std::endl;
    }
    return err;
}

template<typename T>
bool
CmacSiv<T>::isSupported(const alc_cipher_info_t& cipherInfo)
{
    // Northing much to do here, need to be removed.
    return true;
}

template<typename T>
bool
CmacSiv<T>::isSupported(const Uint32 keyLen)
{
    // FIXME: Tobe Implemented
    return true;
}

} // namespace alcp::cipher