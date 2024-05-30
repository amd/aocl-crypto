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

namespace alcp::cipher {

using mac::poly1305::Poly1305;

// FIXME: to be moved to zen4 arch
namespace vaes512 {
    alc_error_t ChaChaPlusPoly::setIv(const Uint8* iv, Uint64 ivLen)
    {
        if (ivLen != 12) {
            return ALC_ERROR_INVALID_SIZE;
        }
        memset(m_iv, 0, 4);
        memcpy(m_iv + 4, iv, ivLen);

        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPlusPoly::setKey(const Uint8* key, Uint64 keylen)
    {
        alc_error_t err = ChaCha256::setKey(key, keylen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        std::fill(m_poly1305_key, m_poly1305_key + 32, 0);
        err = ChaCha256::encrypt(nullptr, m_poly1305_key, m_poly1305_key, 32);

        alcp::base::Status s      = Poly1305::init(m_poly1305_key, 32);
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

    alc_error_t ChaChaPoly::init(alc_cipher_data_t* cipher_data,
                                 const Uint8*       pKey,
                                 Uint64             keyLen,
                                 const Uint8*       pIv,
                                 Uint64             ivLen)
    {
        alc_error_t err = ALC_ERROR_NONE;
        // FIXME: add ptr check and len checks
        err = setIv(pIv, ivLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = setKey(pKey, keyLen);
        return err;
    }

    /* chacha256::encrypt and poly::update to be fused */
    alc_error_t ChaChaPoly256::encrypt(alc_cipher_data_t* cipher_data,
                                       const Uint8*       inputBuffer,
                                       Uint8*             outputBuffer,
                                       Uint64             bufferLength)
    {

        alcp::base::Status s{ alcp::base::StatusOk() };
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        alc_error_t err = ChaCha256::encrypt(
            nullptr, inputBuffer, outputBuffer, bufferLength);

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

        s = Poly1305::update(outputBuffer, bufferLength);
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

    alc_error_t ChaChaPoly256::decrypt(alc_cipher_data_t* cipher_data,
                                       const Uint8*       inputBuffer,
                                       Uint8*             outputBuffer,
                                       Uint64             bufferLength)
    {

        alcp::base::Status s{ alcp::base::StatusOk() };
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        alc_error_t err = ChaCha256::encrypt(
            nullptr, inputBuffer, outputBuffer, bufferLength);

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

        //  In case of decryption one should change the order of updation i.e
        //  input (which is the ciphertext) should be updated
        s = Poly1305::update(inputBuffer, bufferLength);

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

    alc_error_t ChaChaPolyAuth::setAad(alc_cipher_data_t* cipher_data,
                                       const Uint8*       pInput,
                                       Uint64             len)
    {
        alcp::base::Status s = Poly1305::update(pInput, len);
        if (!s.ok()) {
            return ALC_ERROR_EXISTS;
        }
        m_len_aad_processed.u64 += len;
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPolyAuth::getTag(alc_cipher_data_t* cipher_data,
                                       Uint8*             pOutput,
                                       Uint64             len)
    {
        alcp::base::Status s = Poly1305::finalize(pOutput, len);
        if (!s.ok()) {
            return ALC_ERROR_EXISTS;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPolyAuth::setTagLength(alc_cipher_data_t* cipher_data,
                                             Uint64             tagLength)
    {
        if (tagLength != 16) {
            return ALC_ERROR_INVALID_SIZE;
        }
        return ALC_ERROR_NONE;
    }

} // namespace vaes512

#if 0
namespace ref {
#include "chacha20_poly1305.cc.inc"

} // namespace ref
#endif

} // namespace alcp::cipher
