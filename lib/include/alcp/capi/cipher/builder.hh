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

#include "alcp/cipher.hh"
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
    CpuCipherFeatures m_arch = CpuCipherFeatures::eVaes512; // default zen4 arch
    CpuCipherFeatures m_currentArch = getCpuCipherFeature();
    CipherKeyLen      m_keyLen      = KEY_128_BIT;
    alc_cipher_mode_t m_mode        = ALC_AES_MODE_NONE;
    INTERFACE*        m_iCipher     = nullptr;
    cipherAlgoMap     m_cipherMap   = {};

  public:
    CipherFactory();
    ~CipherFactory();

    // cipher creators
    INTERFACE* create(const string& name);
    INTERFACE* create(const string& name, CpuCipherFeatures arch);
    INTERFACE* create(alc_cipher_mode_t mode, CipherKeyLen keyLen);
    INTERFACE* create(alc_cipher_mode_t mode,
                      CipherKeyLen      keyLen,
                      CpuCipherFeatures arch);

  private:
    void              initCipherMap();
    void              clearCipherMap();
    void              getCipher();
    CpuCipherFeatures getCpuCipherFeature();
};

} // namespace alcp::cipher
