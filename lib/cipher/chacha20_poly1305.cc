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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/base.hh"
#include <openssl/bio.h>

// #define DEBUG

namespace alcp::cipher::chacha20 {

using mac::poly1305::Poly1305;

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::setNonce(const Uint8* nonce,
                                               Uint64       noncelen)
{

    if (noncelen != 12) {
        return ALC_ERROR_INVALID_SIZE;
    }
    memset(ChaCha20Poly1305<cpu_cipher_feature>::m_iv, 0, 4);
    memcpy(ChaCha20Poly1305<cpu_cipher_feature>::m_iv + 4, nonce, noncelen);

    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::encryptupdate(const Uint8 plaintext[],
                                                    Uint64      plaintextLength,
                                                    Uint8       ciphertext[])
{
    return ChaCha20Poly1305::processInput<true>(
        plaintext, plaintextLength, ciphertext);
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::decryptupdate(const Uint8 ciphertext[],
                                                    Uint64 ciphertextLength,
                                                    Uint8  plaintext[])
{
    return ChaCha20Poly1305::processInput<false>(
        ciphertext, ciphertextLength, plaintext);
}

template<CpuArchFeature cpu_cipher_feature>
template<bool is_encrypt>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::processInput(const Uint8 inputBuffer[],
                                                   Uint64      bufferLength,
                                                   Uint8       outputBuffer[])
{

    alcp::base::Status s{ alcp::base::StatusOk() };
    // set  Counter to 1
    (*(reinterpret_cast<Uint32*>(ChaCha20<cpu_cipher_feature>::m_iv))) += 1;
    alc_error_t err = ChaCha20<cpu_cipher_feature>::processInput(
        inputBuffer, bufferLength, outputBuffer);

    if (err != ALC_ERROR_NONE) {
        return err;
    }

    m_len_input_processed.u64 += bufferLength;

    Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                ? 0
                                : (16 - (m_len_aad_processed.u64 % 16));
    if (padding_length != 0) {
        s = Poly1305::update(m_zero_padding, padding_length);
        if (!s.ok()) {
            return ALC_ERROR_EXISTS;
        }
    }
    if constexpr (is_encrypt) {

        s = Poly1305::update(outputBuffer, bufferLength);
    } else {
        //  In case of decryption one should change the order of updation i.e
        //  input (which is the ciphertext) should be updated
        s = Poly1305::update(inputBuffer, bufferLength);
    }
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    padding_length = ((m_len_input_processed.u64 % 16) == 0)
                         ? 0
                         : (16 - (m_len_input_processed.u64 % 16));
    if (padding_length != 0) {
        s = Poly1305::update(m_zero_padding, padding_length);
        if (!s.ok()) {
            return ALC_ERROR_EXISTS;
        }
    }

    constexpr Uint64 cSizeLength = sizeof(Uint64);
    s = Poly1305::update(m_len_aad_processed.u8, cSizeLength);
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    s = Poly1305::update(m_len_input_processed.u8, cSizeLength);
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::setAad(const Uint8* pInput, Uint64 len)
{
    alcp::base::Status s = Poly1305::update(pInput, len);
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    m_len_aad_processed.u64 += len;
    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::getTag(Uint8* pOutput, Uint64 len)
{
    alcp::base::Status s = Poly1305::finalize(nullptr, 0);
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    s = Poly1305::copy(pOutput, len);
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::setTagLength(Uint64 tagLength)
{
    if (tagLength != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchFeature cpu_cipher_feature>
alc_error_t
ChaCha20Poly1305<cpu_cipher_feature>::setKey(const Uint8 key[], Uint64 keylen)
{

    alc_error_t err = ChaCha20<cpu_cipher_feature>::setKey(key, keylen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = ChaCha20<cpu_cipher_feature>::getKeyStream(m_poly1305_key, 32);
#ifdef DEBUG
    std::cout << "Key Stream generated for Poly" << std::endl;
    BIO_dump_fp(stdout, m_poly1305_key, 32);
#endif
    alcp::base::Status s      = Poly1305::setKey(m_poly1305_key, 256);
    m_len_input_processed.u64 = 0;
    m_len_aad_processed.u64   = 0;
    if (!s.ok()) {
        return ALC_ERROR_EXISTS;
    }

    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return ALC_ERROR_NONE;
}

template class ChaCha20Poly1305<CpuArchFeature::eAvx512>;
template class ChaCha20Poly1305<CpuArchFeature::eReference>;
template class ChaCha20Poly1305<CpuArchFeature::eDynamic>;

} // namespace alcp::cipher::chacha20
