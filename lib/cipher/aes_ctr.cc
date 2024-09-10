/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

// FIXME: separate ctr implementation (ctrProcessAvx256) needs to be done
// for different key size
namespace vaes {
    alc_error_t CryptCtr(const Uint8* pInputText,
                         Uint8*       pOutputText,
                         Uint64       len,
                         const Uint8* pKey,
                         int          nRounds,
                         Uint8*       pIv)
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        Uint64      res     = len % 16;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx256(
            pInputText, pOutputText, blocks, res, pkey128, pIv, nRounds);
        return err;
    }
} // namespace vaes

// FIXME: separate ctr implementation (ctrProcessAvx2) needs to be done
// for different key size
namespace aesni {
    alc_error_t CryptCtr(const Uint8* pInputText,
                         Uint8*       pOutputText,
                         Uint64       len,
                         const Uint8* pKey,
                         int          nRounds,
                         Uint8*       pIv)
    {
        alc_error_t err     = ALC_ERROR_NONE;
        Uint64      blocks  = len >> 4; // / Rijndael::cBlockSize;
        Uint64      res     = len % 16;
        auto        pkey128 = reinterpret_cast<const __m128i*>(pKey);

        blocks = ctrProcessAvx2(
            pInputText, pOutputText, blocks, res, pkey128, pIv, nRounds);
        return err;
    }
} // namespace aesni

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tCtr<keyLenBits, arch>::encrypt(const Uint8* pinput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = 1;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = CryptCtr<keyLenBits, arch>(pinput,
                                         pOutput,
                                         len,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         m_pIv_aes);
    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::CryptCtr(pinput,
                             pOutput,
                             len,
                             m_cipher_key_data.m_enc_key,
                             getRounds(),
                             m_pIv_aes);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::CryptCtr(pinput,
                              pOutput,
                              len,
                              m_cipher_key_data.m_enc_key,
                              getRounds(),
                              m_pIv_aes);
    }

    return err;
}

template<alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
tCtr<keyLenBits, arch>::decrypt(const Uint8* pinput, Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = 0;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    if constexpr (arch == CpuCipherFeatures::eVaes512) {
        err = CryptCtr<keyLenBits, arch>(pinput,
                                         pOutput,
                                         len,
                                         m_cipher_key_data.m_enc_key,
                                         getRounds(),
                                         m_pIv_aes);
    } else if constexpr (arch == CpuCipherFeatures::eVaes256) {
        err = vaes::CryptCtr(pinput,
                             pOutput,
                             len,
                             m_cipher_key_data.m_enc_key,
                             getRounds(),
                             m_pIv_aes);
    } else if constexpr (arch == CpuCipherFeatures::eAesni) {
        err = aesni::CryptCtr(pinput,
                              pOutput,
                              len,
                              m_cipher_key_data.m_enc_key,
                              getRounds(),
                              m_pIv_aes);
    }
    return err;
}

template class tCtr<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes512>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes512>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes512>;

template class tCtr<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eVaes256>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eVaes256>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eVaes256>;

template class tCtr<alcp::cipher::CipherKeyLen::eKey128Bit,
                    CpuCipherFeatures::eAesni>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey192Bit,
                    CpuCipherFeatures::eAesni>;
template class tCtr<alcp::cipher::CipherKeyLen::eKey256Bit,
                    CpuCipherFeatures::eAesni>;

} // namespace alcp::cipher