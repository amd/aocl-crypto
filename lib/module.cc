/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

#include "alcp/cipher.h"

#include "alcp/module.hh"
#include "cipher.hh"

namespace alcp {

alc_module_type_t
Module::getType()
{
    // FIXME: Horror ahead
    return ALC_MODULE_TYPE_CIPHER;
}

const std::map<alc_module_type_t, std::string> Module::typeNameMap =
    std::map<alc_module_type_t, std::string>{
        { ALC_MODULE_TYPE_CIPHER, "CIPHER" },
        { ALC_MODULE_TYPE_DIGEST, "DIGEST" },
        { ALC_MODULE_TYPE_RNG, "RNG" },
        { ALC_MODULE_TYPE_MAC, "MAC" },
        { ALC_MODULE_TYPE_EC, "EC" },
    };

// Disabled because Prem asked.
#if 0
class Module::Impl
{
  public:
    using CipherModuleList = std::list<Cipher*>;
    using CipherMap = std::unordered_map<alc_cipher_type_t, CipherModuleList>;
#if 0
    typedef std::unordered_map<const alc_rng_type_t, module_list_t> RngMap;
    typedef std::unordered_map<const alc_digest_type_t, module_list_t>
    DigestMap;
#endif
    bool isType(alc_module_type_t t) const { return t == m_type; }

  private:
    std::string       m_name;
    alc_module_type_t m_type;
    CipherMap         m_cipher_map;
    // DigestMap   m_digest_map
    std::vector<Algorithm> m_algo;
};
#endif

} // namespace alcp
