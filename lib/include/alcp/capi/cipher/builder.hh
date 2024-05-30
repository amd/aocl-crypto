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

#pragma once
#include <map>
#include <tuple>

#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/error.h"

#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuCipherFeatures;
using alcp::utils::CpuId;

namespace alcp::cipher {

enum CipherKeyLen
{
    KEY_128_BIT,
    KEY_192_BIT,
    KEY_256_BIT
};

typedef std::tuple<const alc_cipher_mode_t, const CipherKeyLen>
                                                        cipherKeyLenTuple;
typedef std::map<const string, const cipherKeyLenTuple> cipherAlgoMap;

template<class INTERFACE>
class CipherFactory
{
  private:
    // user arch request
    CpuCipherFeatures m_arch = CpuCipherFeatures::eVaes512; // default zen arch
    CipherKeyLen      m_keyLen = KEY_128_BIT;               // default keyLen
    alc_cipher_mode_t m_mode   = ALC_AES_MODE_CTR;          // default mode
    // current arch detected by CPUID
    CpuCipherFeatures m_currentArch = getCpuCipher();

    INTERFACE* m_iCipher = nullptr;

    cipherAlgoMap m_cipherAeadMap = {
        { "aes-gcm-128", { ALC_AES_MODE_GCM, KEY_128_BIT } },
        { "aes-gcm-192", { ALC_AES_MODE_GCM, KEY_192_BIT } },
        { "aes-gcm-256", { ALC_AES_MODE_GCM, KEY_256_BIT } },

        { "aes-ccm-128", { ALC_AES_MODE_CCM, KEY_128_BIT } },
        { "aes-ccm-192", { ALC_AES_MODE_CCM, KEY_192_BIT } },
        { "aes-ccm-256", { ALC_AES_MODE_CCM, KEY_256_BIT } },

        { "aes-siv-128", { ALC_AES_MODE_SIV, KEY_128_BIT } },
        { "aes-siv-192", { ALC_AES_MODE_SIV, KEY_192_BIT } },
        { "aes-siv-256", { ALC_AES_MODE_SIV, KEY_256_BIT } },

        { "aes-polychacha", { ALC_AES_MODE_SIV, KEY_256_BIT } },
    };

    cipherAlgoMap m_cipherMap = {
        { "aes-cbc-128", { ALC_AES_MODE_CBC, KEY_128_BIT } },
        { "aes-cbc-192", { ALC_AES_MODE_CBC, KEY_192_BIT } },
        { "aes-cbc-256", { ALC_AES_MODE_CBC, KEY_256_BIT } },

        { "aes-ofb-128", { ALC_AES_MODE_OFB, KEY_128_BIT } },
        { "aes-ofb-192", { ALC_AES_MODE_OFB, KEY_192_BIT } },
        { "aes-ofb-256", { ALC_AES_MODE_OFB, KEY_256_BIT } },

        { "aes-ctr-128", { ALC_AES_MODE_CTR, KEY_128_BIT } },
        { "aes-ctr-192", { ALC_AES_MODE_CTR, KEY_192_BIT } },
        { "aes-ctr-256", { ALC_AES_MODE_CTR, KEY_256_BIT } },

        { "aes-cfb-128", { ALC_AES_MODE_CFB, KEY_128_BIT } },
        { "aes-cfb-192", { ALC_AES_MODE_CFB, KEY_192_BIT } },
        { "aes-cfb-256", { ALC_AES_MODE_CFB, KEY_256_BIT } },

        { "aes-xts-128", { ALC_AES_MODE_CBC, KEY_128_BIT } },
        { "aes-xts-256", { ALC_AES_MODE_CBC, KEY_256_BIT } },

        { "aes-chacha20", { ALC_CHACHA20, KEY_256_BIT } },

    };

  public:
    CipherFactory() = default;
    ~CipherFactory()
    {
        m_cipherMap.clear();

        if (m_iCipher != nullptr) {
            delete m_iCipher;
        }
    };

    // cipher creators
    INTERFACE* create(const string& name);
    INTERFACE* create(const string& name, CpuCipherFeatures arch);
    INTERFACE* create(alc_cipher_mode_t mode, CipherKeyLen keyLen);
    INTERFACE* create(alc_cipher_mode_t mode,
                      CipherKeyLen      keyLen,
                      CpuCipherFeatures arch);

  private:
    void              getCipher();
    CpuCipherFeatures getCpuCipher();
};

} // namespace alcp::cipher
