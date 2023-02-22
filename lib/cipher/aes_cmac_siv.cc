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

Status
CmacSiv::dbl(std::vector<Uint8>& in)
{
    Status s = StatusOk();
    // Double the in vector
    return s;
}

Status
CmacSiv::s2v(const Uint8 plainText[], Uint64 size)
{
    // Assume plaintest to be 128 bit multiples.
    Status             s    = StatusOk();
    std::vector<Uint8> zero = std::vector<Uint8>(m_sizeCmac, 0);

    Uint64* cmac_temp_uint64 = reinterpret_cast<Uint64*>(&(m_cmacTemp.at(0)));

    // Erase the contents of the memory
    memset(cmac_temp_uint64, 0, m_sizeCmac);

    // TODO: Implement CMAC function.
    s = Cmac(
        m_key1, m_keyLength, zero, m_sizeCmac, &(m_cmacTemp[0]), m_sizeCmac);

    if (!s.ok()) {
        return s;
    }

    for (int i = 0; i < m_additionalDataProcessedSize; i++) {
        Uint64* add_temp_uint64 =
            reinterpret_cast<Uint64*>(&(m_additionalDataProcessed.at(i).at(0)));
        // TODO: Implement dbl function.
        dbl(m_cmacTemp);
        for (int j = 0; j < m_sizeCmac / 8; j++) {
            cmac_temp_uint64[j] ^= add_temp_uint64[j];
        }
    }
    return s;
}

Status
CmacSiv::setKeys(Uint8 key1[], Uint8 key2[], Uint64 length)
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
CmacSiv::addAdditionalInput(const Uint8 memory[], Uint64 length)
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
    s = Cmac(m_key1,
             m_keyLength,
             memory,
             length,
             &(m_additionalDataProcessed.at(m_additionalDataProcessedSize)[0]),
             m_sizeCmac);

    if (!s.ok()) {
        return s;
    }

    m_additionalDataProcessedSize += 1;
    return s;
}

alc_error_t
CmacSiv::encrypt(const Uint8* pPlainText,
                 Uint8*       pCipherText,
                 Uint64       len,
                 const Uint8* pIv) const
{
}

Status
CmacSiv::encrypt(const Uint8 plainText[], Uint8 cipherText[], Uint64 len)
{
    Status s = StatusOk();

    s = s2v(plainText, len);

    if (!s.ok()) {
        return s;
    }

    // TODO: Implement CtrEnc function.
    //         PT      L       CT          IV         key      keyL
    s = CtrEnc(
        plainText, len, cipherText, &(m_cmacTemp[0]), m_key2, m_keyLength);

    if (!s.ok()) {
        return s;
    }
}

alc_error_t
CmacSiv::decrypt(const Uint8* pCipherText,
                 Uint8*       pPlainText,
                 Uint64       len,
                 const Uint8* pIv) const
{
}

Status
CmacSiv::decrypt(const Uint8  cipherText[],
                 Uint8        plainText[],
                 Uint64       len,
                 const Uint8* iv)
{
    Status s = StatusOk();

    // TODO: Implement CtrDec function.
    //              CT      L       PT        IV     key      keyL
    s = CtrDec(cipherText, len, plainText, iv, m_key2, m_keyLength);

    if (!s.ok()) {
        return s;
    }

    // Create the tag from generated plain text
    s = s2v(plainText, len);

    // Verify tag, which just got generated
    if (memcmp(&(m_cmacTemp[0]), iv, m_sizeCmac) != 0) {
        s = InternalError("Verification Failure!");
        return s;
    }
    return s;
}

Status
CmacSiv::getTag(Uint8 out[])
{
    Status s = StatusOk();
    utils::CopyBytes(out, &m_cmacTemp, m_sizeCmac);
    return s;
}
} // namespace alcp::cipher