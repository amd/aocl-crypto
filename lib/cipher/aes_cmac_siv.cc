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

#include "cipher/aes_cmac_siv.hh"

namespace alcp::cipher {

using alcp::base::status::InternalError;

inline std::string
parseBytesToHexStr(const Uint8* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    // return "something";
    return ss.str();
}

inline std::string
parseBytesToHexStr(std::vector<Uint8> bytes)
{
    return parseBytesToHexStr(&(bytes.at(0)), bytes.size());
}

inline Uint8
parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

inline std::vector<Uint8>
parseHexStrToBin(const std::string in)
{
    std::vector<Uint8> vector;
    int                len = in.size();
    int                ind = 0;

    for (int i = 0; i < len; i += 2) {
        Uint8 val =
            parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
        vector.push_back(val);
        ind += 2;
    }
    return vector;
}

/**
    @brief Does an XOR operation on two array of Uint8 a and b store it to c
    @param a Input a (first input)
    @param b Input b (second input)
    @param c Output c (output of xor operation)
    @param len Entities to XOR
*/
template<typename T>
inline void
xor_a_b(const T a[], const T b[], T c[], size_t len)
{
    for (size_t j = 0; j < len; j++) {
        c[j] = b[j] ^ a[j];
    }
}
inline void
left_shift(const Uint8 in[], Uint8 out[])
{
    int i = 0;
    for (i = 0; i < 15; i++) {
        out[i] = in[i] << 1;
        out[i] |= (in[i + 1] >> 7);
    }
    out[i] = in[i] << 1;
}
void
dbl(const Uint8 in[], const Uint8 rb[], Uint8 out[])
{

    Uint8 in_leftshift[16]{};
    left_shift(in, in_leftshift);
    // Uint8 rb[16]{};
    // rb[15] = 0x87;
    if (in[0] & 0x80) {
        out[15] = in_leftshift[15] ^ rb[15];
        utils::CopyBytes(out, in_leftshift, 15);
    } else {
        utils::CopyBytes(out, in_leftshift, 16);
    }
}

Status
CmacSiv::Impl::cmacWrapper(const Uint8 key[],
                           Uint64      keySize,
                           const Uint8 data[],
                           Uint64      size,
                           Uint8       mac[],
                           Uint64      macSize)
{
    Status s{ StatusOk() };
    s = m_cmac.setKey(key, keySize);
    if (!s.ok()) {
        return s;
    }
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

Status
CmacSiv::Impl::cmacWrapperMultiData(const Uint8 key[],
                                    Uint64      keySize,
                                    const Uint8 data1[],
                                    Uint64      size1,
                                    const Uint8 data2[],
                                    Uint64      size2,
                                    Uint8       mac[],
                                    Uint64      macSize)
{
    Status s{ StatusOk() };
    s = m_cmac.setKey(key, keySize);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.update(data1, size1);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.finalize(data2, size2);
    if (!s.ok()) {
        return s;
    }
    s = m_cmac.copy(mac, macSize);
    return s;
}

Status
CmacSiv::Impl::ctrWrapper(const Uint8 key[],
                          Uint64      keySize,
                          const Uint8 in[],
                          Uint8       out[],
                          Uint64      size,
                          Uint8       iv[],
                          bool        enc)
{
    Status s = StatusOk();
    m_ctr.setKey(key, keySize);

    // FIXME: To be removed once we move everything to Status
    alc_error_t err = ALC_ERROR_NONE;
    if (enc)
        err = m_ctr.encrypt(in, out, size, iv);
    else
        err = m_ctr.decrypt(in, out, size, iv);
    if (alcp_is_error(err)) {
        s.update(InternalError("An error occured"));
    }
    return s;
}

Status
CmacSiv::Impl::setPaddingLen(Uint64 len)
{
    Status s = StatusOk();
    m_padLen = len;
    return s;
}

Status
CmacSiv::Impl::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    Status             s         = StatusOk();
    std::vector<Uint8> zero      = std::vector<Uint8>(m_sizeCmac, 0);
    const Uint64* p_cPlainText64 = reinterpret_cast<const Uint64*>(plainText);
    Uint64*       p_cmacTemp64 = reinterpret_cast<Uint64*>(&(m_cmacTemp.at(0)));

    s = cmacWrapper(m_key1,
                    m_keyLength,
                    &(zero.at(0)),
                    zero.size(),
                    &(m_cmacTemp.at(0)),
                    m_sizeCmac);

    if (!s.ok()) {
        return s;
    }

    std::cout << "ZERO_VECT:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

    // Erase the contents of the memory
    // memset(p_cmacTemp64, 0, m_sizeCmac);

    Uint8 rb[16] = {};
    rb[15]       = 0x87;
    for (Uint64 i = 0; i < m_additionalDataProcessedSize; i++) {
        Uint64* add_temp_uint64 =
            reinterpret_cast<Uint64*>(&(m_additionalDataProcessed.at(i).at(0)));
        // TODO: Remove TODO // TODO: Implement dbl function.
        alcp::cipher::dbl(&(m_cmacTemp[0]), rb, &(m_cmacTemp[0]));

        std::cout << "dbl:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        // xor_a_b(p_cmacTemp64, add_temp_uint64, p_cmacTemp64, m_sizeCmac /
        // 8);
        xor_a_b(&m_cmacTemp[0],
                &m_additionalDataProcessed.at(i).at(0),
                &m_cmacTemp[0],
                m_sizeCmac);
    }
    // alcp::cipher::dbl(&(m_cmacTemp[0]), rb, &(m_cmacTemp[0]));
    // std::cout << "dbl:" << parseBytesToHexStr(m_cmacTemp) << std::endl;
    // xor_a_b(&m_cmacTemp[0], plainText, &m_cmacTemp[0], m_sizeCmac);

    // TODO: Implement CMAC function.
    if (size >= m_sizeCmac) {
        // Take out last block
        xor_a_b((plainText + size - m_sizeCmac),
                &(m_cmacTemp.at(0)),
                &(m_cmacTemp.at(0)),
                m_sizeCmac);

        s = cmacWrapperMultiData(m_key1,
                                 m_keyLength,
                                 plainText,
                                 (size - m_sizeCmac),
                                 &(m_cmacTemp.at(0)),
                                 m_sizeCmac,
                                 &(m_cmacTemp.at(0)),
                                 m_sizeCmac);
    } else {
        Uint8 temp_bytes[16] = {};
        temp_bytes[0]        = 0x80;
        alcp::cipher::dbl(&(m_cmacTemp[0]), rb, &(m_cmacTemp[0]));
        std::cout << "dbl:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        xor_a_b(plainText, &(m_cmacTemp.at(0)), &(m_cmacTemp.at(0)), size);
        xor_a_b(temp_bytes,
                &(m_cmacTemp.at(0)) + size,
                &(m_cmacTemp.at(0)) + size,
                (m_sizeCmac)-size);
        std::cout << "xor:" << parseBytesToHexStr(m_cmacTemp) << std::endl;

        s = cmacWrapper(m_key1,
                        m_keyLength,
                        &(m_cmacTemp.at(0)),
                        m_sizeCmac,
                        &(m_cmacTemp.at(0)),
                        m_sizeCmac);
    }
    if (!s.ok()) {
        return s;
    }
    std::cout << "V:  " << parseBytesToHexStr(m_cmacTemp) << std::endl;
    return s;
}

Status
CmacSiv::Impl::setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length)
{
    Status s    = StatusOk();
    m_keyLength = length;
    switch (length) {
        case 128:
        case 192:
        case 256:
            break;
        default:
            // FIXME: Implement CMAC-SIV Error class.
            s = InternalError("Length is unsupported!");
            return s;
    }
    m_key1 = key1;
    m_key2 = key2;
    return s;
}
// Section 2.4 in RFC
Status
CmacSiv::Impl::addAdditionalInput(const Uint8 memory[], Uint64 length)
{
    // Check if there is an overflow
    Status s = StatusOk();

    if ((m_additionalDataProcessedSize + 1)
        == m_additionalDataProcessed.size()) {
        m_additionalDataProcessed.resize(m_additionalDataProcessed.size() + 10);
    }
    if (m_key1 == nullptr || m_key2 == nullptr) {
        // FIXME: Implement Error class for CMAC SIV
        s = InternalError("Key Not Found");
        return s;
    }

    m_additionalDataProcessed.at(m_additionalDataProcessedSize) =
        std::vector<Uint8>(m_sizeCmac);

    // TODO: Implement CMAC function.
    s = cmacWrapper(
        m_key1,
        m_keyLength,
        memory,
        length,
        &((m_additionalDataProcessed.at(m_additionalDataProcessedSize)).at(0)),
        m_sizeCmac);

    if (!s.ok()) {
        return s;
    }

    m_additionalDataProcessedSize += 1;
    return s;
}

Status
CmacSiv::Impl::encrypt(const Uint8 plainText[], Uint8 cipherText[], Uint64 len)
{
    Status s     = StatusOk();
    Uint8  q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    s = s2v(plainText, len);

    if (!s.ok()) {
        return s;
    }

    for (int i = 0; i < m_sizeCmac; i++) {
        q[i] = m_cmacTemp[i] & q[i];
    }

    s = ctrWrapper(
        m_key2, m_keyLength, plainText, cipherText, len + m_padLen, q, true);

    if (!s.ok()) {
        return s;
    }
    return s;
}

Status
CmacSiv::Impl::decrypt(const Uint8  cipherText[],
                       Uint8        plainText[],
                       Uint64       len,
                       const Uint8* iv)
{
    Status s     = StatusOk();
    Uint8  q[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };

    for (int i = 0; i < m_sizeCmac; i++) {
        q[i] = iv[i] & q[i];
    }

    // TODO: Implement CtrDec function.
    //              CT      L       PT        IV     key      keyL
    // s = CtrDec(cipherText, len, plainText, iv, m_key2, m_keyLength);
    s = ctrWrapper(
        m_key2, m_keyLength, cipherText, plainText, len + m_padLen, q, false);

    if (!s.ok()) {
        return s;
    }

    // Create the tag from generated plain text
    s = s2v(plainText, len);

    // Verify tag, which just got generated
    if (memcmp(&(m_cmacTemp[0]), iv, m_sizeCmac) != 0) {
        // FIXME: Initiate Wipedown!
        s = InternalError("Verification Failure!");
        return s;
    }
    return s;
}

CmacSiv::CmacSiv()
    : pImpl{ std::make_unique<Impl>() }
{
}

CmacSiv::CmacSiv(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
    : pImpl{ std::make_unique<Impl>() }
{
    assert(aesInfo.ai_siv.xi_ctr_key->len == keyInfo.len);
    setKeys(keyInfo.key, aesInfo.ai_siv.xi_ctr_key->key, keyInfo.len);
}

Status
CmacSiv::Impl::getTag(Uint8 out[])
{
    Status s = StatusOk();
    utils::CopyBytes(out, &m_cmacTemp[0], m_sizeCmac);
    memset(&m_cmacTemp[0], 0, 16);
    return s;
}

Status
CmacSiv::s2v(const Uint8 plainText[], Uint64 size)
{
    return pImpl->s2v(plainText, size);
}

Status
CmacSiv::getTag(Uint8 out[])
{
    return pImpl->getTag(out);
}

alc_error_t
CmacSiv::getTag(Uint8 out[], Uint64 len)
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

Status
CmacSiv::setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length)
{
    return pImpl->setKeys(key1, key2, length);
}

Status
CmacSiv::addAdditionalInput(const Uint8 memory[], Uint64 length)
{
    return pImpl->addAdditionalInput(memory, length);
}

Status
CmacSiv::setPaddingLen(Uint64 len)
{
    return pImpl->setPaddingLen(len);
}

alc_error_t
CmacSiv::encrypt(const Uint8* pPlainText,
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

alc_error_t
CmacSiv::decrypt(const Uint8* pCipherText,
                 Uint8*       pPlainText,
                 Uint64       len,
                 const Uint8* pIv) const

{
    alc_error_t err = ALC_ERROR_NONE;
    Status      s   = pImpl->decrypt(pCipherText, pPlainText, len, pIv);
    if (!s.ok()) {
        err = ALC_ERROR_GENERIC;
        std::cout << "IV Verify Failed!" << std::endl;
    }
    return err;
}

bool
CmacSiv::isSupported(const alc_cipher_info_t& cipherInfo)
{
    // Northing much to do here, need to be removed.
    return true;
}

} // namespace alcp::cipher