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

namespace alcp::cipher {

// Class Siv functions

Siv::Siv(alc_cipher_data_t* ctx)
    : m_cmac{ Cmac(ctx) }
{}

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
Siv::addAdditionalInput(const Uint8 memory[], Uint64 length)
{
    Status s = StatusOk();

    if (memory == nullptr) {
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

Status
Siv::setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length)
{
    Status s = StatusOk();

    if (key1 == nullptr || key2 == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

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

    s = m_cmac.setKey(m_key1, length);
    if (!s.ok()) {
        return s;
    }

    // T::setKey(m_key2, m_keyLength);
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

// class SivHash functions

alc_error_t
SivHash::getTag(alc_cipher_data_t* ctx, Uint8 out[], Uint64 len)
{
    if (ctx == nullptr || out == nullptr) {
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
SivHash::setAad(alc_cipher_data_t* ctx, const Uint8 memory[], Uint64 length)
{
    if (ctx == nullptr || memory == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    Status s = addAdditionalInput(memory, length);
    return s.code();
}

alc_error_t
SivHash::init(alc_cipher_data_t* ctx,
              const Uint8*       pKey,
              Uint64             keyLen,
              const Uint8*       pIv,
              Uint64             ivLen)
{
    Uint64 keyLength = keyLen;
    if (pIv != nullptr) {
        m_iv = pIv;
    }
    if (ctx == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pKey != nullptr) {
        m_key1   = pKey;
        m_key2   = pKey + keyLength / 8;
        Status s = setKeys(m_key1, m_key2, keyLength);
        if (!s.ok()) {
            return ALC_ERROR_INVALID_ARG;
        }
    }

    return ALC_ERROR_NONE;
}

// class SivAead Functions

namespace aesni {

    SivAead128::SivAead128(alc_cipher_data_t* ctx)
        : Ctr128(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead128::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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

        // Do the CTR
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr128::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead128::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr128::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead192::SivAead192(alc_cipher_data_t* ctx)
        : Ctr192(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead192::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr192::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead192::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr192::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead256::SivAead256(alc_cipher_data_t* ctx)
        : Ctr256(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead256::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr256::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead256::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr256::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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
} // namespace aesni

namespace vaes {
    SivAead128::SivAead128(alc_cipher_data_t* ctx)
        : Ctr128(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead128::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr128::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead128::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr128::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead192::SivAead192(alc_cipher_data_t* ctx)
        : Ctr192(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead192::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr192::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead192::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr192::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead256::SivAead256(alc_cipher_data_t* ctx)
        : Ctr256(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead256::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr256::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead256::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr256::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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
} // namespace vaes

namespace vaes512 {
    SivAead128::SivAead128(alc_cipher_data_t* ctx)
        : Ctr128(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead128::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr128::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead128::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr128::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr128::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead192::SivAead192(alc_cipher_data_t* ctx)
        : Ctr192(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead192::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr192::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead192::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr192::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr192::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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

    SivAead256::SivAead256(alc_cipher_data_t* ctx)
        : Ctr256(ctx)
        , SivHash(ctx)
    {
        // Set current mode to AES-SIV
        Aes::setMode(ALC_AES_MODE_SIV);
    }

    alc_error_t SivAead256::encryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pPlainText,
                                          Uint8*             pCipherText,
                                          Uint64             len)
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
        // s = ctrWrapper(ctx, pPlainText, pCipherText, len + m_padLen, q,
        // true);

        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);

        alc_error_t err =
            Ctr256::encrypt(ctx, pPlainText, pCipherText, len + m_padLen);
        if (alcp_is_error(err)) {
            auto cer = status::EncryptFailed("Encryption Kernel Failed!");
            s.update(cer);
            return s.code();
        }

        return s.code();
    }

    alc_error_t SivAead256::decryptUpdate(alc_cipher_data_t* ctx,
                                          const Uint8*       pCipherText,
                                          Uint8*             pPlainText,
                                          Uint64             len)

    {
        Status      s   = StatusOk();
        alc_error_t err = ALC_ERROR_NONE;

        // Mask Vector for disabling 2 bits in the counter
        Uint8 q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

        // Apply the mask and make q the IV
        for (Uint64 i = 0; i < SIZE_CMAC; i++) {
            q[i] = m_iv[i] & q[i];
        }

        // Do the CTR
        // s = ctrWrapper(ctx, pCipherText, pPlainText, len + m_padLen, q,
        // false);
        Ctr256::init(ctx, m_key2, Aes::m_keyLen_in_bytes_aes * 8, q, 16);
        err = Ctr256::decrypt(ctx, pCipherText, pPlainText, len); //, mac);
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
        if (memcmp(&(m_cmacTemp[0]), m_iv, SIZE_CMAC) != 0) {
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
} // namespace vaes512

} // namespace alcp::cipher