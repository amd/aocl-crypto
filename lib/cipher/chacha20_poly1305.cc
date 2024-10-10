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
        err = ChaCha256::encrypt(m_poly1305_key, m_poly1305_key, 32);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 = 0;
        m_len_aad_processed.u64   = 0;
        err                       = Poly1305::init(m_poly1305_key, 32);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPoly::init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen)
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
    alc_error_t ChaChaPoly256::encrypt(const Uint8* inputBuffer,
                                       Uint8*       outputBuffer,
                                       Uint64       bufferLength)
    {

        alc_error_t err = ALC_ERROR_NONE;
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        err = ChaCha256::encrypt(inputBuffer, outputBuffer, bufferLength);

        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 += bufferLength;

        Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                    ? 0
                                    : (16 - (m_len_aad_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        /*FIXME: Workaround to use the 1x kernel in poly1305 due to known issue
           in 8x kernel. Remove the while loop and update in a single call once
           the issue is resolved.
        */
        // err = Poly1305::update(outputBuffer, bufferLength); // loop
        while (bufferLength) {
            if (bufferLength >= 256) {
                err = Poly1305::update(outputBuffer, 256); // loop
                outputBuffer += 256;
                bufferLength -= 256;
            } else {
                err = Poly1305::update(outputBuffer, bufferLength); // loop
                bufferLength = 0;
            }
        }

        if (err != ALC_ERROR_NONE) {
            return err;
        }
        padding_length = ((m_len_input_processed.u64 % 16) == 0)
                             ? 0
                             : (16 - (m_len_input_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        constexpr Uint64 cSizeLength = sizeof(Uint64);
        err = Poly1305::update(m_len_aad_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = Poly1305::update(m_len_input_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPoly256::decrypt(const Uint8* inputBuffer,
                                       Uint8*       outputBuffer,
                                       Uint64       bufferLength)
    {

        alc_error_t err = ALC_ERROR_NONE;
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        err = ChaCha256::encrypt(inputBuffer, outputBuffer, bufferLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 += bufferLength;

        Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                    ? 0
                                    : (16 - (m_len_aad_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        /*FIXME: Workaround to use the 1x kernel in poly1305 due to known issue
            in 8x kernel. Remove the while loop and update in a single call once
            the issue is resolved.
        */
        //  In case of decryption one should change the order of updation i.e
        //  input (which is the ciphertext) should be updated
        // err = Poly1305::update(inputBuffer, bufferLength);

        while (bufferLength) {
            if (bufferLength >= 256) {
                err = Poly1305::update(inputBuffer, 256); // loop
                inputBuffer += 256;
                bufferLength -= 256;
            } else {
                err = Poly1305::update(inputBuffer, bufferLength); // loop
                bufferLength = 0;
            }
        }

        if (err != ALC_ERROR_NONE) {
            return err;
        }
        padding_length = ((m_len_input_processed.u64 % 16) == 0)
                             ? 0
                             : (16 - (m_len_input_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        constexpr Uint64 cSizeLength = sizeof(Uint64);
        err = Poly1305::update(m_len_aad_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = Poly1305::update(m_len_input_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPolyAuth::setAad(const Uint8* pInput, Uint64 len)
    {
        alc_error_t err = Poly1305::update(pInput, len);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_len_aad_processed.u64 += len;
        return err;
    }

    alc_error_t ChaChaPolyAuth::getTag(Uint8* pOutput, Uint64 len)
    {
        alc_error_t err = Poly1305::finalize(pOutput, len);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return err;
    }

    alc_error_t ChaChaPolyAuth::setTagLength(Uint64 tagLength)
    {
        if (tagLength != 16) {
            return ALC_ERROR_INVALID_SIZE;
        }
        return ALC_ERROR_NONE;
    }

} // namespace vaes512

#if 1 // duplicate of code under vaes512 to be refined.
namespace ref {
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
        err = ChaCha256::encrypt(m_poly1305_key, m_poly1305_key, 32);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        err = Poly1305::init(m_poly1305_key, 32);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 = 0;
        m_len_aad_processed.u64   = 0;

        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPoly::init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen)
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
    alc_error_t ChaChaPoly256::encrypt(const Uint8* inputBuffer,
                                       Uint8*       outputBuffer,
                                       Uint64       bufferLength)
    {
        alc_error_t err = ALC_ERROR_NONE;
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        err = ChaCha256::encrypt(inputBuffer, outputBuffer, bufferLength);

        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 += bufferLength;

        Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                    ? 0
                                    : (16 - (m_len_aad_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        err = Poly1305::update(outputBuffer, bufferLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        padding_length = ((m_len_input_processed.u64 % 16) == 0)
                             ? 0
                             : (16 - (m_len_input_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        constexpr Uint64 cSizeLength = sizeof(Uint64);
        err = Poly1305::update(m_len_aad_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = Poly1305::update(m_len_input_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPoly256::decrypt(const Uint8* inputBuffer,
                                       Uint8*       outputBuffer,
                                       Uint64       bufferLength)
    {

        alc_error_t err = ALC_ERROR_NONE;
        // set  Counter to 1
        (*(reinterpret_cast<Uint32*>(ChaCha256::m_iv))) += 1;
        err = ChaCha256::encrypt(inputBuffer, outputBuffer, bufferLength);

        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_len_input_processed.u64 += bufferLength;

        Uint64 padding_length = ((m_len_aad_processed.u64 % 16) == 0)
                                    ? 0
                                    : (16 - (m_len_aad_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        //  In case of decryption one should change the order of updation i.e
        //  input (which is the ciphertext) should be updated
        err = Poly1305::update(inputBuffer, bufferLength);

        if (err != ALC_ERROR_NONE) {
            return err;
        }
        padding_length = ((m_len_input_processed.u64 % 16) == 0)
                             ? 0
                             : (16 - (m_len_input_processed.u64 % 16));
        if (padding_length != 0) {
            err = Poly1305::update(m_zero_padding, padding_length);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }

        constexpr Uint64 cSizeLength = sizeof(Uint64);
        err = Poly1305::update(m_len_aad_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        err = Poly1305::update(m_len_input_processed.u8, cSizeLength);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t ChaChaPolyAuth::setAad(const Uint8* pInput, Uint64 len)
    {
        alc_error_t err = Poly1305::update(pInput, len);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_len_aad_processed.u64 += len;
        return err;
    }

    alc_error_t ChaChaPolyAuth::getTag(Uint8* pOutput, Uint64 len)
    {
        alc_error_t err = Poly1305::finalize(pOutput, len);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return err;
    }

    alc_error_t ChaChaPolyAuth::setTagLength(Uint64 tagLength)
    {
        if (tagLength != 16) {
            return ALC_ERROR_INVALID_SIZE;
        }
        return ALC_ERROR_NONE;
    }
} // namespace ref
#endif

} // namespace alcp::cipher
