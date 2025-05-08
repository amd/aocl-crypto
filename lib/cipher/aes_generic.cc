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

#include "alcp/cipher/aes.hh"
//
#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuId;

namespace alcp::cipher {

// WIP
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::encrypt(const Uint8* pinput,
                                                    Uint8*       pOutput,
                                                    Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_ENC;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    /*
        eAesCBC,
        eAesOFB,
        eAesCTR,
        eAesCFB,*/

    if constexpr (arch < CpuCipherFeatures::eAesni) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    constexpr alcp::cipher::CipherMode cMode = mode;

    switch (cMode) {
        case CipherMode::eAesCBC:
            err = aesni::EncryptCbc(pinput,
                                    pOutput,
                                    len,
                                    m_cipher_key_data.m_enc_key,
                                    getRounds(),
                                    m_pIv_aes);
            break;
        case CipherMode::eAesOFB:
            err = aesni::EncryptOfb(pinput,
                                    pOutput,
                                    len,
                                    m_cipher_key_data.m_enc_key,
                                    getRounds(),
                                    m_pIv_aes);
            break;
        case CipherMode::eAesCTR:
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
            break;
        case CipherMode::eAesCFB:
            err = aesni::EncryptCfb(pinput,
                                    pOutput,
                                    len,
                                    m_cipher_key_data.m_enc_key,
                                    getRounds(),
                                    m_pIv_aes);
            break;
        default:
            break;
    }
    // WIP, other generic modes to be added.
    return err;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuCipherFeatures arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::decrypt(const Uint8* pinput,
                                                    Uint8*       pOutput,
                                                    Uint64       len)
{
    alc_error_t err = ALC_ERROR_NONE;
    m_isEnc_aes     = ALCP_DEC;
    if (!(m_isKeySet_aes)) {
        printf("\nError: Key or Iv not set \n");
        return ALC_ERROR_BAD_STATE;
    }
    if (m_ivLen_aes != 16) {
        m_ivLen_aes = 16;
    }

    if constexpr (arch < CpuCipherFeatures::eAesni) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    constexpr alcp::cipher::CipherMode cMode = mode;

    switch (cMode) {
        case CipherMode::eAesCBC:
            err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
                pinput, pOutput, len, m_cipher_key_data.m_dec_key, m_pIv_aes);
            break;

        case CipherMode::eAesOFB:
            err = aesni::DecryptOfb(pinput,
                                    pOutput,
                                    len,
                                    m_cipher_key_data.m_enc_key,
                                    getRounds(),
                                    m_pIv_aes);
            break;

        case CipherMode::eAesCTR:
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
            break;

        case CipherMode::eAesCFB:
            err = DecryptCfb<keyLenBits, arch>(
                pinput,
                pOutput,
                len,
                m_cipher_key_data.m_enc_key,
                getRounds(), // getCipherRounds(keyLenBits),
                m_pIv_aes);
            break;

        default:
            break;
    }
    return err;
}

#if 1

/*
    eAesCBC,
    eAesOFB,
    eAesCTR,
    eAesCFB,*/
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesOFB */
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesCTR */
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

/* eAesCFB */
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes512>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes512>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eVaes256>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eVaes256>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuCipherFeatures::eAesni>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuCipherFeatures::eAesni>;

// other generic modes to be added.
#endif

} // namespace alcp::cipher