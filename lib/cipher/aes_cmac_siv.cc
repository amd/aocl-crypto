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

    m_key1 = key1;

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
    Uint64      keyLength = keyLen; // 128/8 = 16
    if (pIv != nullptr) {
        memcpy(m_iv_aes, pIv, ivLen);
    }

    if (pKey != nullptr) {
        m_key1 = pKey;
        m_key2 = pKey + keyLength / 8;
        err    = setKeys(m_key1, keyLength);
        if (err != ALC_ERROR_NONE) {
            return ALC_ERROR_INVALID_ARG;
        }
    }

    return ALC_ERROR_NONE;
}

Status
Siv::cmacWrapper(const Uint8 data[], Uint64 size, Uint8 mac[], Uint64 macSize)
{
    Status s{ StatusOk() };
    if (data == nullptr || mac == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    s = m_cmac.update(data, size);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.finalize(mac, macSize);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.reset();
    if (!s.ok()) {
        return s;
    }
    return s;
}

Status
Siv::cmacWrapperMultiData(const Uint8 data1[],
                          Uint64      size1,
                          const Uint8 data2[],
                          Uint64      size2,
                          Uint8       mac[],
                          Uint64      macSize)
{
    Status s{ StatusOk() };
    if (data1 == nullptr || data2 == nullptr || mac == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    s = m_cmac.update(data1, size1);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.update(data2, size2);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.finalize(mac, macSize);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.reset();
    if (!s.ok()) {
        return s;
    }
    return s;
}

Status
Siv::addAdditionalInput(const Uint8* pAad, Uint64 aadLen)
{
    Status s = StatusOk();

    if (pAad == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

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
        pAad,
        aadLen,
        &((m_additionalDataProcessed.at(m_additionalDataProcessedSize)).at(0)),
        SIZE_CMAC);

    if (!s.ok()) {
        return s;
    }

    // Increment the size of Data Processed if no errors
    m_additionalDataProcessedSize += 1;
    return s;
}

Status
Siv::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    Status s = StatusOk();
    if (plainText == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    std::vector<Uint8> zero = std::vector<Uint8>(SIZE_CMAC, 0);

    // Do a cmac of Zero Vector, first additonal data.
    s = cmacWrapper(&(zero.at(0)), zero.size(), m_cmacTemp, SIZE_CMAC);

    if (!s.ok()) {
        return s;
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
        // Special case size lower for plain text need to do double and padding
        avx2::dbl(&(m_cmacTemp[0]));

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

    return s;
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
    Status s = addAdditionalInput(pAad, aadLen);
    return s.code();
}

alc_error_t
SivHash::setTagLength(Uint64 tagLength)
{
    return ALC_ERROR_NONE;
}

// class SivAead Functions

// aesni functions
alc_error_t
Siv128_aesni::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len); // Nullptr check inside this function

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv128_aesni::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv192_aesni::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv192_aesni::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv256_aesni::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 256, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv256_aesni::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 256, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

// vaes functions
alc_error_t
Siv128_vaes::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv128_vaes::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv192_vaes::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv192_vaes::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv256_vaes::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 256, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv256_vaes::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 256, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

// vaes512 functions
alc_error_t
Siv128_vaes512::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv128_vaes512::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 128, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv192_vaes512::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv192_vaes512::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    ctrobj->init(m_key2, 192, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

alc_error_t
Siv256_vaes512::encrypt(const Uint8* pPlainText, Uint8* pCipherText, Uint64 len)
{
    Status s = StatusOk();

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(pPlainText, len);

    if (!s.ok()) {
        return s.code();
    }

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    // Do the CTR
    // s = ctrWrapper( pPlainText, pCipherText, len + m_padLen, q,
    // true);

    ctrobj->init(m_key2, 256, q, 16);

    alc_error_t err = ctrobj->encrypt(pPlainText, pCipherText, len + m_padLen);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    return s.code();
}

alc_error_t
Siv256_vaes512::decrypt(const Uint8* pCipherText, Uint8* pPlainText, Uint64 len)

{
    Status      s   = StatusOk();
    alc_error_t err = ALC_ERROR_NONE;

    // Mask Vector for disabling 2 bits in the counter
    Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    // Apply the mask and make q the IV
    for (Uint64 i = 0; i < SIZE_CMAC; i++) {
        q[i] = m_iv_aes[i] & q[i];
    }

    // Do the CTR
    // s = ctrWrapper( pCipherText, pPlainText, len + m_padLen, q,
    // false);
    ctrobj->init(m_key2, 256, q, 16);
    err = ctrobj->decrypt(pCipherText, pPlainText, len); //, mac);
    if (alcp_is_error(err)) {
        auto cer = status::EncryptFailed("Encryption Kernel Failed!");
        s.update(cer);
        return s.code();
    }

    if (!s.ok()) {
        return s.code();
    }

    // Create the tag from generated plain text
    s = s2v(pPlainText, len);

    // Verify tag, which just got generated
    if (utils::CompareConstTime(&(m_cmacTemp[0]), m_iv_aes, SIZE_CMAC) == 0) {
// FIXME: Initiate Wipedown!
#if 0
        auto cer =
            cipher::CipherError(cipher::ErrorCode::eAuthenticationFailure);
        s.update(cer, cer.message());
#else
        err = ALC_ERROR_TAG_MISMATCH;
        return err;
#endif
        if (!s.ok()) {
            return s.code();
        }
    }
    return s.code();
}

} // namespace alcp::cipher