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

#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cfb.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aes_ofb.hh"
#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_poly1305.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {

using alcp::utils::CpuCipherFeatures;

template<typename INTERFACE, class CLASS_128, class CLASS_192, class CLASS_256>
INTERFACE*
pickKeyLen(CipherKeyLen keyLen)
{
    switch (keyLen) {
        case CipherKeyLen::eKey128Bit:
            return new CLASS_128();
        case CipherKeyLen::eKey192Bit:
            return new CLASS_192();
        case CipherKeyLen::eKey256Bit:
            return new CLASS_256();
        default:
            printf("\n Error: key length not supported ");
            return nullptr;
    }
}

template<typename INTERFACE, class CLASS_128, class CLASS_256>
INTERFACE*
pickKeyLen(CipherKeyLen keyLen)
{
    switch (keyLen) {
        case CipherKeyLen::eKey128Bit:
            return new CLASS_128();
        case CipherKeyLen::eKey256Bit:
            return new CLASS_256();
        default:
            printf("\n Error: key length not supported ");
            return nullptr;
    }
}

template<typename INTERFACE,
         class CLASS_128_VAES512,
         class CLASS_192_VAES512,
         class CLASS_256_VAES512,
         class CLASS_128_VAES,
         class CLASS_192_VAES,
         class CLASS_256_VAES,
         class CLASS_128_AESNI,
         class CLASS_192_AESNI,
         class CLASS_256_AESNI>
INTERFACE*
getMode(CipherKeyLen keyLen, CpuCipherFeatures arch)
{
    switch (arch) {
        case CpuCipherFeatures::eVaes512:
            return pickKeyLen<INTERFACE,
                              CLASS_128_VAES512,
                              CLASS_192_VAES512,
                              CLASS_256_VAES512>(keyLen);
        case CpuCipherFeatures::eVaes256:
            return pickKeyLen<INTERFACE,
                              CLASS_128_VAES,
                              CLASS_192_VAES,
                              CLASS_256_VAES>(keyLen);
        case CpuCipherFeatures::eAesni:
            return pickKeyLen<INTERFACE,
                              CLASS_128_AESNI,
                              CLASS_192_AESNI,
                              CLASS_256_AESNI>(keyLen);
        case CpuCipherFeatures::eReference:
            printf("\n Error: Reference kernel not supported ");
            return nullptr;
        default:
            return nullptr;
    }
}

template<typename INTERFACE,
         class CLASS_128_VAES512,
         class CLASS_256_VAES512,
         class CLASS_128_VAES,
         class CLASS_256_VAES,
         class CLASS_128_AESNI,
         class CLASS_256_AESNI>
INTERFACE*
getMode(CipherKeyLen keyLen, CpuCipherFeatures arch)
{
    switch (arch) {
        case CpuCipherFeatures::eVaes512:
            return pickKeyLen<INTERFACE, CLASS_128_VAES512, CLASS_256_VAES512>(
                keyLen);
        case CpuCipherFeatures::eVaes256:
            return pickKeyLen<INTERFACE, CLASS_128_VAES, CLASS_256_VAES>(
                keyLen);
        case CpuCipherFeatures::eAesni:
            return pickKeyLen<INTERFACE, CLASS_128_AESNI, CLASS_256_AESNI>(
                keyLen);
        case CpuCipherFeatures::eReference:
            printf("\n Error: Reference kernel not supported ");
            return nullptr;
        default:
            return nullptr;
    }
}

template<>
void
CipherFactory<iCipher>::getCipher()
{
    // Non-AEAD ciphers
    switch (m_cipher_mode) {
        case CipherMode::eAesCBC:
            m_iCipher = getMode<iCipher,
                                Cbc128_vaes512,
                                Cbc192_vaes512,
                                Cbc256_vaes512,
                                Cbc128_vaes,
                                Cbc192_vaes,
                                Cbc256_vaes,
                                Cbc128_aesni,
                                Cbc192_aesni,
                                Cbc256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesOFB:
            m_iCipher = getMode<iCipher,
                                Ofb128_aesni,
                                Ofb192_aesni,
                                Ofb256_aesni,
                                Ofb128_aesni,
                                Ofb192_aesni,
                                Ofb256_aesni,
                                Ofb128_aesni,
                                Ofb192_aesni,
                                Ofb256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesCTR:
            m_iCipher = getMode<iCipher,
                                Ctr128_vaes512,
                                Ctr192_vaes512,
                                Ctr256_vaes512,
                                Ctr128_vaes,
                                Ctr192_vaes,
                                Ctr256_vaes,
                                Ctr128_aesni,
                                Ctr192_aesni,
                                Ctr256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesCFB:
            m_iCipher = getMode<iCipher,
                                Cfb128_vaes512,
                                Cfb192_vaes512,
                                Cfb256_vaes512,
                                Cfb128_vaes,
                                Cfb192_vaes,
                                Cfb256_vaes,
                                Cfb128_aesni,
                                Cfb192_aesni,
                                Cfb256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesXTS:
            m_iCipher = getMode<iCipher,
                                Xts128_vaes512,
                                Xts256_vaes512,
                                Xts128_vaes,
                                Xts256_vaes,
                                Xts128_aesni,
                                Xts256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eCHACHA20:
            if (m_arch == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                m_iCipher = new ChaCha256();
            } else {
                using namespace ref;
                m_iCipher = new ChaCha256();
            }
            break;
        default:
            m_iCipher = nullptr;
            break;
    }
}

template<>
void
CipherFactory<iCipherAead>::getCipher()
{
    // AEAD ciphers
    switch (m_cipher_mode) {
        case CipherMode::eAesGCM:
            m_iCipher = getMode<iCipherAead,
                                Gcm128_vaes512,
                                Gcm192_vaes512,
                                Gcm256_vaes512,
                                Gcm128_vaes,
                                Gcm192_vaes,
                                Gcm256_vaes,
                                Gcm128_aesni,
                                Gcm192_aesni,
                                Gcm256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesCCM:
            m_iCipher = getMode<iCipherAead,
                                Ccm128_aesni,
                                Ccm192_aesni,
                                Ccm256_aesni,
                                Ccm128_aesni,
                                Ccm192_aesni,
                                Ccm256_aesni,
                                Ccm128_aesni,
                                Ccm192_aesni,
                                Ccm256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesSIV:
            m_iCipher = getMode<iCipherAead,
                                Siv128_vaes512,
                                Siv192_vaes512,
                                Siv256_vaes512,
                                Siv128_vaes,
                                Siv192_vaes,
                                Siv256_vaes,
                                Siv128_aesni,
                                Siv192_aesni,
                                Siv256_aesni>(m_keyLen, m_arch);
            break;
        case CipherMode::eCHACHA20_POLY1305:
            if (m_arch == CpuCipherFeatures::eVaes512) {
                using namespace vaes512;
                m_iCipher = new ChaChaPoly256();
            } else {
                using namespace ref;
                m_iCipher = new ChaChaPoly256();
            }
            break;
        default:
            m_iCipher = nullptr;
            break;
    }
}

static void
listModes(cipherAlgoMapT map)
{
    std::cout << "List of supported cipher modes in the selected CipherFactory "
              << std::endl;
    for (auto it1 = map.begin(); it1 != map.end(); ++it1) {
        std::cout << it1->first.c_str() << std::endl;
    }
}

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(const string& name)
{
    auto it = m_cipherMap.find(name);
    if (it == m_cipherMap.end()) {
        std::cout << "\n error " << name << " cipher mode not supported "
                  << std::endl;
        listModes(m_cipherMap);
        return nullptr;
    }
    cipherKeyLenTupleT t = it->second;
    return create(std::get<0>(t), std::get<1>(t));
}

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(const string& name, CpuCipherFeatures arch)
{
    auto it = m_cipherMap.find(name);
    if (it == m_cipherMap.end()) {
        std::cout << "\n error " << name << " cipher mode not supported "
                  << std::endl;
        listModes(m_cipherMap);
        return nullptr;
    }
    cipherKeyLenTupleT t = it->second;
    return create(std::get<0>(t), std::get<1>(t), arch);
}

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(CipherMode mode, CipherKeyLen keyLen)
{
    m_cipher_mode = mode;
    m_keyLen      = keyLen;
    m_arch        = m_currentArch;
    getCipher();
    return m_iCipher;
};

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(CipherMode        mode,
                                 CipherKeyLen      keyLen,
                                 CpuCipherFeatures arch)
{
    m_cipher_mode = mode;
    m_keyLen      = keyLen;
    // limit based on arch available in the cpu.
    if (arch > m_currentArch) {
#if 0 /* when default feature set to highest level, avoid multiple warnings */
        std::cout << "\n warning! requested ISA is not supported by platform, "
                     "lowering to ISA supported "
                  << std::endl;
#endif
        arch = m_currentArch;
    }
    m_arch = arch;
    getCipher();
    return m_iCipher;
}

template<class INTERFACE>
CpuCipherFeatures
CipherFactory<INTERFACE>::getCpuCipherFeature()
{
    CpuCipherFeatures cpu_feature =
        CpuCipherFeatures::eReference; // If no arch features present,means
                                       // no acceleration, Fall back to
                                       // reference

    if (CpuId::cpuHasAesni()) {
        cpu_feature = CpuCipherFeatures::eAesni;

        if (CpuId::cpuHasVaes()) {
            cpu_feature = CpuCipherFeatures::eVaes256;

            if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
                cpu_feature = CpuCipherFeatures::eVaes512;
            }
        }
    }
    return cpu_feature;
}

template<>
void
CipherFactory<iCipher>::initCipherMap()
{
    m_cipherMap = {
        { "aes-cbc-128", { CipherMode::eAesCBC, CipherKeyLen::eKey128Bit } },
        { "aes-cbc-192", { CipherMode::eAesCBC, CipherKeyLen::eKey192Bit } },
        { "aes-cbc-256", { CipherMode::eAesCBC, CipherKeyLen::eKey256Bit } },

        { "aes-ofb-128", { CipherMode::eAesOFB, CipherKeyLen::eKey128Bit } },
        { "aes-ofb-192", { CipherMode::eAesOFB, CipherKeyLen::eKey192Bit } },
        { "aes-ofb-256", { CipherMode::eAesOFB, CipherKeyLen::eKey256Bit } },

        { "aes-ctr-128", { CipherMode::eAesCTR, CipherKeyLen::eKey128Bit } },
        { "aes-ctr-192", { CipherMode::eAesCTR, CipherKeyLen::eKey192Bit } },
        { "aes-ctr-256", { CipherMode::eAesCTR, CipherKeyLen::eKey256Bit } },

        { "aes-cfb-128", { CipherMode::eAesCFB, CipherKeyLen::eKey128Bit } },
        { "aes-cfb-192", { CipherMode::eAesCFB, CipherKeyLen::eKey192Bit } },
        { "aes-cfb-256", { CipherMode::eAesCFB, CipherKeyLen::eKey256Bit } },

        { "aes-xts-128", { CipherMode::eAesCBC, CipherKeyLen::eKey128Bit } },
        { "aes-xts-256", { CipherMode::eAesCBC, CipherKeyLen::eKey256Bit } },

        { "chacha20", { CipherMode::eCHACHA20, CipherKeyLen::eKey256Bit } },
    };
}

template<>
void
CipherFactory<iCipherAead>::initCipherMap()
{
    m_cipherMap = {
        { "aes-gcm-128", { CipherMode::eAesGCM, CipherKeyLen::eKey128Bit } },
        { "aes-gcm-192", { CipherMode::eAesGCM, CipherKeyLen::eKey192Bit } },
        { "aes-gcm-256", { CipherMode::eAesGCM, CipherKeyLen::eKey256Bit } },

        { "aes-ccm-128", { CipherMode::eAesCCM, CipherKeyLen::eKey128Bit } },
        { "aes-ccm-192", { CipherMode::eAesCCM, CipherKeyLen::eKey192Bit } },
        { "aes-ccm-256", { CipherMode::eAesCCM, CipherKeyLen::eKey256Bit } },

        { "aes-siv-128", { CipherMode::eAesSIV, CipherKeyLen::eKey128Bit } },
        { "aes-siv-192", { CipherMode::eAesSIV, CipherKeyLen::eKey192Bit } },
        { "aes-siv-256", { CipherMode::eAesSIV, CipherKeyLen::eKey256Bit } },

        { "chachapoly",
          { CipherMode::eCHACHA20_POLY1305, CipherKeyLen::eKey256Bit } },
    };
}

template<class INTERFACE>
void
CipherFactory<INTERFACE>::clearCipherMap()
{
    m_cipherMap.clear();
}

template<class INTERFACE>
CipherFactory<INTERFACE>::CipherFactory()
{
    initCipherMap();
};

template<class INTERFACE>
CipherFactory<INTERFACE>::~CipherFactory()
{
    clearCipherMap();
    if (m_iCipher != nullptr) {
        delete m_iCipher;
    }
};

template class CipherFactory<iCipherAead>;
template class CipherFactory<iCipher>;

} // namespace alcp::cipher