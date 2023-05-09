/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes.hh"
//
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

namespace vaes512 {
    alc_error_t Ctr128::encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_128(
            pPlainText, pCipherText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

    alc_error_t Ctr128::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_128(
            pCipherText, pPlainText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

    alc_error_t Ctr192::encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_192(
            pPlainText, pCipherText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

    alc_error_t Ctr192::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_192(
            pCipherText, pPlainText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

    alc_error_t Ctr256::encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_256(
            pPlainText, pCipherText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

    alc_error_t Ctr256::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(m_enc_key);

        blocks = ctrProcessAvx512_256(
            pCipherText, pPlainText, blocks, pkey128, pIv, m_nrounds);
        return err;
    }

} // namespace vaes512

// FIXME: separate ctr implementation (ctrProcessAvx256) needs to be done
// for different key size
namespace vaes {
    alc_error_t cryptCtr128(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv)
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx256(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);
        return err;
    }

    alc_error_t cryptCtr192(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv         // ptr to Initialization Vector
    )
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx256(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);

        return err;
    }

    alc_error_t cryptCtr256(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv         // ptr to Initialization Vector
    )
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx256(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);

        return err;
    }
} // namespace vaes

// FIXME: separate ctr implementation (ctrProcessAvx2) needs to be done
// for different key size
namespace aesni {
    alc_error_t cryptCtr128(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv)
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx2(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);
        return err;
    }

    alc_error_t cryptCtr192(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv         // ptr to Initialization Vector
    )
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx2(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);

        return err;
    }

    alc_error_t cryptCtr256(
        const Uint8* pInputText, // ptr to plaintext for encrypt
                                 // and ciphertext for decrypt
        Uint8* pOutputText,      // ptr to ciphertext for encrypt and
                                 // plaintext for decrypt
        Uint64       len,        // message length in bytes
        const Uint8* pKey,       // ptr to Key
        int          nRounds,    // No. of rounds
        const Uint8* pIv         // ptr to Initialization Vector
    )
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx2(
            pInputText, pOutputText, blocks, pkey128, pIv, nRounds);

        return err;
    }
} // namespace aesni

namespace vaes {
    alc_error_t Ctr128::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr128(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr128::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr128(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr192::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr192(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr192::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr192(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr256::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr256(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr256::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr256(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

} // namespace vaes

namespace aesni {
    alc_error_t Ctr128::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr128(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr128::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr128(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr192::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr192(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr192::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr192(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr256::decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr256(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

    alc_error_t Ctr256::encrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        err             = cryptCtr256(
            pCipherText, pPlainText, len, m_enc_key, m_nrounds, pIv);

        return err;
    }

} // namespace aesni

} // namespace alcp::cipher