/*
 * Copyright (C) 2021-2025, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/aes_cmac_siv.hh"
#include "alcp/cipher/aes_gcm.hh"
#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/aes_xts.hh"
#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_poly1305.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {

using alcp::utils::CpuCipherFeatures;

template<CipherMode MODE>
iCipher*
getGenericCiphers(const CipherKeyLen keyLen, const CpuCipherFeatures arch)
{

    if (arch < alcp::utils::CpuCipherFeatures::eAesni) {
        printf("\n Error: Reference kernel not supported ");
        return nullptr;
    }

    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey128Bit,
                                              CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey192Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey192Bit,
                                              CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey256Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey256Bit,
                                              CpuCipherFeatures::eVaes512>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey128Bit,
                                              CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey192Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey192Bit,
                                              CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey256Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey256Bit,
                                              CpuCipherFeatures::eVaes256>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey128Bit,
                                              CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey192Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey192Bit,
                                              CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new AesGenericCiphersT<MODE,
                                              CipherKeyLen::eKey256Bit,
                                              CpuCipherFeatures::eAesni>();
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

iCipherAead*
getSiv(const CipherKeyLen keyLen, const CpuCipherFeatures arch)
{
    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new SivT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey192Bit:
                return new SivT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey256Bit:
                return new SivT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes512>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new SivT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey192Bit:
                return new SivT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey256Bit:
                return new SivT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes256>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new SivT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey192Bit:
                return new SivT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new SivT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>();
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

// copy-paste of siv, can be avoided
iCipherAead*
getGcm(const CipherKeyLen      keyLen,
       const CpuCipherFeatures arch,
       alc_cipher_state_t*     pCipherState)
{
    if (pCipherState == nullptr) {
        printf("\n State invalid ");
        return nullptr;
    }

    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes512>(pCipherState);
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes512>(pCipherState);
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes512>(pCipherState);
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes256>(pCipherState);
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes256>(pCipherState);
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes256>(pCipherState);
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>(pCipherState);
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eAesni>(pCipherState);
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>(pCipherState);
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

iCipherAead*
getGcm(const CipherKeyLen keyLen, const CpuCipherFeatures arch)
{
    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes512>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes256>();
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new GcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey192Bit:
                return new GcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new GcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>();
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

iCipherAead*
getCcm(const CipherKeyLen keyLen, const CpuCipherFeatures arch)
{
    if (arch >= alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLen) {
            case CipherKeyLen::eKey128Bit:
                return new CcmT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey192Bit:
                return new CcmT<CipherKeyLen::eKey192Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new CcmT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>();
            default:
                printf("\n Error: key length not supported ");
                return nullptr;
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

iCipher*
getXts(const CipherKeyLen keyLenBits, const CpuCipherFeatures arch)
{
    if ((keyLenBits != CipherKeyLen::eKey128Bit)
        && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        printf("\n Error: key length not supported ");
        return nullptr;
    }

    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey256Bit:
                return new XtsT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes512>();
            default:
                return nullptr;
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey256Bit:
                return new XtsT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eVaes256>();
            default:
                return nullptr;
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsT<CipherKeyLen::eKey128Bit,
                                CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new XtsT<CipherKeyLen::eKey256Bit,
                                CpuCipherFeatures::eAesni>();
            default:
                return nullptr;
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

iCipherSeg*
getXtsBlock(const CipherKeyLen keyLenBits, const CpuCipherFeatures arch)
{
    if ((keyLenBits != CipherKeyLen::eKey128Bit)
        && (keyLenBits != CipherKeyLen::eKey256Bit)) {
        printf("\n Error: key length not supported ");
        return nullptr;
    }

    if (arch == alcp::utils::CpuCipherFeatures::eVaes512) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                     CpuCipherFeatures::eVaes512>();
            case CipherKeyLen::eKey256Bit:
                return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                     CpuCipherFeatures::eVaes512>();
            default:
                return nullptr;
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eVaes256) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                     CpuCipherFeatures::eVaes256>();
            case CipherKeyLen::eKey256Bit:
                return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                     CpuCipherFeatures::eVaes256>();
            default:
                return nullptr;
        }
    } else if (arch == alcp::utils::CpuCipherFeatures::eAesni) {
        switch (keyLenBits) {
            case CipherKeyLen::eKey128Bit:
                return new XtsBlockT<CipherKeyLen::eKey128Bit,
                                     CpuCipherFeatures::eAesni>();
            case CipherKeyLen::eKey256Bit:
                return new XtsBlockT<CipherKeyLen::eKey256Bit,
                                     CpuCipherFeatures::eAesni>();
            default:
                return nullptr;
        }
    }
    printf("\n Error: Reference kernel not supported ");
    return nullptr;
}

static bool
isKeyLenSupported(CipherKeyLen keyLen)
{
    if ((keyLen != CipherKeyLen::eKey128Bit)
        && (keyLen != CipherKeyLen::eKey192Bit)
        && (keyLen != CipherKeyLen::eKey256Bit)) {
        printf("\n Error: key length not supported ");
        return false;
    }
    return true;
}

template<>
void
CipherFactory<iCipher>::getCipher()
{

    if (!isKeyLenSupported(m_keyLen)) {
        printf("\n Error: key length not supported ");
        m_iCipher = nullptr;
        return;
    }

    // Non-AEAD ciphers
    switch (m_cipher_mode) {
        case CipherMode::eAesCBC:
            m_iCipher =
                getGenericCiphers<CipherMode::eAesCBC>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesOFB:
            m_iCipher =
                getGenericCiphers<CipherMode::eAesOFB>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesCTR:
            m_iCipher =
                getGenericCiphers<CipherMode::eAesCTR>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesCFB:
            m_iCipher =
                getGenericCiphers<CipherMode::eAesCFB>(m_keyLen, m_arch);
            break;
        case CipherMode::eAesXTS:
            m_iCipher = getXts(m_keyLen, m_arch);
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
            printf("\n Error: Cipher mode not supported ");
            m_iCipher = nullptr;
            break;
    }
}

template<>
void
CipherFactory<iCipherSeg>::getCipher()
{
    if (m_arch < alcp::utils::CpuCipherFeatures::eAesni) {
        printf("\n Error: Reference kernel not supported ");
        m_iCipher = nullptr;
        return;
    }

    // Non-AEAD ciphers
    switch (m_cipher_mode) {
        case CipherMode::eAesXTS:
            m_iCipher = getXtsBlock(m_keyLen, m_arch);
            break;
        default:
            printf("\n Error: Cipher mode not supported in iCipherSeg ");
            m_iCipher = nullptr;
            break;
    }
}

template<>
void
CipherFactory<iCipherAead>::getCipher()
{
    if (!isKeyLenSupported(m_keyLen)) {
        printf("\n Error: key length not supported ");
        m_iCipher = nullptr;
        return;
    }

    // AEAD ciphers
    switch (m_cipher_mode) {
        case CipherMode::eAesGCM:
            if (m_cipher_state != nullptr) {
                m_iCipher = getGcm(m_keyLen, m_arch, m_cipher_state);
            } else {
                m_iCipher = getGcm(m_keyLen, m_arch);
            }
            break;
        case CipherMode::eAesCCM:
            m_iCipher = getCcm(m_keyLen, m_arch);
            break;
        case CipherMode::eAesSIV:
            m_iCipher = getSiv(m_keyLen, m_arch);
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
            printf("\n Error: Cipher mode not supported ");
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
CipherFactory<INTERFACE>::create(const CipherMode   mode,
                                 const CipherKeyLen keyLen)
{
    m_cipher_mode = mode;
    m_keyLen      = keyLen;
    m_arch        = m_currentArch;
    getCipher();
    return m_iCipher;
};

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(const CipherMode    mode,
                                 const CipherKeyLen  keyLen,
                                 alc_cipher_state_t* pCipherState)
{
    m_cipher_mode  = mode;
    m_keyLen       = keyLen;
    m_arch         = m_currentArch;
    m_cipher_state = pCipherState;
    getCipher();
    return m_iCipher;
};

template<class INTERFACE>
INTERFACE*
CipherFactory<INTERFACE>::create(const CipherMode        mode,
                                 const CipherKeyLen      keyLen,
                                 const CpuCipherFeatures arch)
{
    m_cipher_mode = mode;
    m_keyLen      = keyLen;
    m_arch        = arch;

    // limit based on arch available in the cpu.
    if (m_arch > m_currentArch) {
#if 0 /* when default feature set to highest level, avoid multiple warnings */
        std::cout << "\n warning! requested ISA is not supported by platform, "
                     "lowering to ISA supported "
                  << std::endl;
#endif
        m_arch = m_currentArch;
    }

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

    if (CpuId::cpuHasAesni() && CpuId::cpuHasAvx2()) {
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

        { "aes-xts-128", { CipherMode::eAesXTS, CipherKeyLen::eKey128Bit } },
        { "aes-xts-256", { CipherMode::eAesXTS, CipherKeyLen::eKey256Bit } },

        { "chacha20", { CipherMode::eCHACHA20, CipherKeyLen::eKey256Bit } },
    };
}

template<>
void
CipherFactory<iCipherSeg>::initCipherMap()
{
    m_cipherMap = {
        { "aes-xts-128", { CipherMode::eAesXTS, CipherKeyLen::eKey128Bit } },
        { "aes-xts-256", { CipherMode::eAesXTS, CipherKeyLen::eKey256Bit } },
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
template class CipherFactory<iCipherSeg>;
} // namespace alcp::cipher