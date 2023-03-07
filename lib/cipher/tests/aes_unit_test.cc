/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/base.hh"
#include "cipher/aes.hh"
#include "types.hh"
#include "gtest/gtest.h"
using namespace alcp::cipher;
using namespace alcp::base;

class TestCipherMode : public Aes
{
    bool isSupported(const alc_cipher_info_t& cipherInfo) { return true; }

  public:
    using Aes::Aes;

    Status setKey(const Uint8* pUserKey, Uint64 len)
    {
        return Aes::setKey(pUserKey, len);
    };
    Status setMode(alc_cipher_mode_t mode) { return Aes::setMode(mode); };

    const Uint8* getEncryptKeys() { return Aes::getEncryptKeys(); }
    const Uint8* getDecryptKeys() { return Aes::getDecryptKeys(); }
};

TEST(AES, setKeyEquivalencyTest)
{
    /**
     * Testcase to check whether EncryptKeys obtained after aes setKey and
     * setMode is same as that obtained from compelx Aes constructor with
     * alc_key_info_t and alc_cipher_algo_info_t
     */
    TestCipherMode aes;

    std::vector<Uint8> key = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                               0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                               0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    aes.setKey(&key[0], key.size() * 8);
    aes.setMode(ALC_AES_MODE_NONE);

    const alc_key_info_t   kinfo   = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                   .fmt  = ALC_KEY_FMT_RAW,
                                   .algo = ALC_KEY_ALG_MAC,
                                   .len  = sizeof(key) * 8,
                                   .key  = &key[0] };
    alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_NONE,
                                       .ai_iv   = NULL };
    auto                   aes2    = TestCipherMode(aesInfo, kinfo);

    ASSERT_FALSE(
        memcmp(aes2.getEncryptKeys(), aes.getEncryptKeys(), aes.getRounds()));
}
