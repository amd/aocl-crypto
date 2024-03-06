/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/cipher/rijndael.hh"
#include "alcp/utils/bits.hh"
#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;

namespace alcp::cipher {

/*
 * @brief        AES Encryption in CBC(Cipher block chaining)
 */
class ALCP_API_EXPORT Cbc : public Aes
{
  public:
    Cbc() { Aes::setMode(ALC_AES_MODE_CBC); };
    ~Cbc() {}
};

namespace vaes512 {
    AES_CLASS_GEN(Cbc128, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc192, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc256, public Cbc, public ICipher)
} // namespace vaes512

namespace vaes {
    AES_CLASS_GEN(Cbc128, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc192, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc256, public Cbc, public ICipher)
} // namespace vaes

namespace aesni {
    AES_CLASS_GEN(Cbc128, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc192, public Cbc, public ICipher)
    AES_CLASS_GEN(Cbc256, public Cbc, public ICipher)
} // namespace aesni
} // namespace alcp::cipher