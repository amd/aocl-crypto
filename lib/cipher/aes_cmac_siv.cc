/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/utils/compare.hh"
#include <string.h>

namespace alcp::cipher {

// Class Siv functions

alc_error_t
Siv::setKeys(const Uint8 key1[], Uint64 length)
{

    if (key1 == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    // Block all unknown keysizes
    switch (length) {
        case 128:
        case 192:
        case 256:
            break;
        default:
            return ALC_ERROR_INVALID_SIZE;
    }

    alc_error_t err = m_cmac.init(
        m_key1, length / 8); // m_cmac.init(m_key1, length, NULL, 0);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    return err;
}

alc_error_t
Siv::init(const Uint8* pKey, Uint64 keyLen, const Uint8* pIv, Uint64 ivLen)
{
    alc_error_t err       = ALC_ERROR_NONE;
    Uint64      keyLength = keyLen;

    if (pIv != nullptr) {
        if (ivLen == 16) {
            err = utils::SecureCopy<Uint8>(
                m_iv_aes, MAX_CIPHER_IV_SIZE, pIv, ivLen);
        } else {
            return ALC_ERROR_INVALID_SIZE;
        }
    }

    if (pKey != nullptr) {
        err = utils::SecureCopy<Uint8>(m_key1, 32, pKey, keyLength / 8);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = utils::SecureCopy<Uint8>(
            m_key2, 32, pKey + (keyLength / 8), keyLength / 8);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = setKeys(m_key1, keyLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    return err;
}

alc_error_t
Siv::cmacWrapper(const Uint8 data[], Uint64 size, Uint8 mac[], Uint64 macSize)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (data == nullptr || mac == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    err = m_cmac.update(data, size);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.finalize(mac, macSize);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.reset();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return err;
}

alc_error_t
Siv::cmacWrapperMultiData(const Uint8 data1[],
                          Uint64      size1,
                          const Uint8 data2[],
                          Uint64      size2,
                          Uint8       mac[],
                          Uint64      macSize)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (data1 == nullptr || data2 == nullptr || mac == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    err = m_cmac.update(data1, size1);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.update(data2, size2);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.finalize(mac, macSize);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = m_cmac.reset();
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return err;
}

alc_error_t
Siv::addAdditionalInput(const Uint8* pAad, Uint64 aadLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (pAad == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    // FIXME: Allocate SIZE_CMAC for 10 vectors on intialization to be more
    // optimal.

    // Extend size of additonalDataProcessed Vector in case of overflow
    if ((m_additionalDataProcessedSize + 1)
        == m_additionalDataProcessed.size()) {
        m_additionalDataProcessed.resize(m_additionalDataProcessed.size() + 10);
    }

    // Allocate memory for additonal data processed vector
    m_additionalDataProcessed.at(m_additionalDataProcessedSize) =
        std::vector<Uint8>(SIZE_CMAC);

    // Do cmac for additional data and set it to the proceed data.
    err = cmacWrapper(
        pAad,
        aadLen,
        &((m_additionalDataProcessed.at(m_additionalDataProcessedSize)).at(0)),
        SIZE_CMAC);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Increment the size of Data Processed if no errors
    m_additionalDataProcessedSize += 1;
    return err;
}

alc_error_t
Siv::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    alc_error_t err = ALC_ERROR_NONE;

    if (plainText == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }
    std::vector<Uint8> zero = std::vector<Uint8>(SIZE_CMAC, 0);

    // Do a cmac of Zero Vector, first additonal data.
    err = cmacWrapper(&(zero.at(0)), zero.size(), m_cmacTemp, SIZE_CMAC);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    avx2::processAad(
        m_cmacTemp, m_additionalDataProcessed, m_additionalDataProcessedSize);

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

        err = cmacWrapperMultiData(plainText,
                                   (size - SIZE_CMAC),
                                   m_cmacTemp,
                                   SIZE_CMAC,
                                   m_cmacTemp,
                                   SIZE_CMAC);
    } else {
        Uint8 temp_bytes[16] = {};
        // Padding Hack
        temp_bytes[0] = 0x80;
        // Special case size lower for plain text need to do double and padding
        avx2::dbl(&(m_cmacTemp[0]));

        xor_a_b(plainText, m_cmacTemp, m_cmacTemp, size);
        // Padding
        xor_a_b(
            temp_bytes, m_cmacTemp + size, m_cmacTemp + size, (SIZE_CMAC)-size);

        // std::cout << "xor:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        err = cmacWrapper(m_cmacTemp, SIZE_CMAC, m_cmacTemp, SIZE_CMAC);
    }

    return err;
}
Siv::~Siv()
{
    memset(m_key1, 0, 32);
    memset(m_key2, 0, 32);
}
// class SivHash functions

alc_error_t
SivHash::getTag(Uint8 out[], Uint64 len)
{
    if (out == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (len != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    utils::CopyBytes(out, &m_cmacTemp[0], SIZE_CMAC);
    memset(&m_cmacTemp[0], 0, 16);
    m_additionalDataProcessedSize = 0;
    return ALC_ERROR_NONE;
}

alc_error_t
SivHash::setAad(const Uint8* pAad, Uint64 aadLen)
{
    if (pAad == nullptr) {
        printf("\n nullptr ");
        return ALC_ERROR_INVALID_ARG;
    }
    alc_error_t err = addAdditionalInput(pAad, aadLen);
    return err;
}

alc_error_t
SivHash::setTagLength(Uint64 tagLength)
{
    return ALC_ERROR_NONE;
}

// class SivAead Functions

// aesni functions
template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    err = s2v(pPlainText, len); // Nullptr check inside this function
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }
    ctrobj->init(m_key2, (static_cast<Uint32>(keyLenBits)), q, 16);
    err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    return err;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
SivT<keyLenBits, arch>::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len)

{
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, (static_cast<Uint32>(keyLenBits)), q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    // Create the tag from generated plain text
    err = s2v(pPlainText, len);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        return ALC_ERROR_TAG_MISMATCH;
#endif
    }
    return err;
}

template class SivT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes512>;
template class SivT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes512>;
template class SivT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes512>;

template class SivT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes256>;
template class SivT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes256>;
template class SivT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes256>;

template class SivT<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eAesni>;
template class SivT<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eAesni>;
template class SivT<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher