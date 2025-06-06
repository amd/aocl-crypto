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

#include "cipher/alc_cipher.hh"
#include "cipher/cipher.hh"
#include "cipher/gtest_base_cipher.hh"

using namespace alcp::testing;

#define ALC_MODE ALC_AES_MODE_SIV

/* Testing Starts Here! */
TEST(AES_ENC_128, KAT_128)
{
    CipherAeadKatTest(128, ENCRYPT, ALC_MODE);
}

TEST(AES_ENC_192, KAT_192)
{
    CipherAeadKatTest(192, ENCRYPT, ALC_MODE);
}

TEST(AES_ENC_256, KAT_256)
{
    CipherAeadKatTest(256, ENCRYPT, ALC_MODE);
}

TEST(AES_DEC_128, KAT_128)
{
    CipherAeadKatTest(128, DECRYPT, ALC_MODE);
}

TEST(AES_DEC_192, KAT_192)
{
    CipherAeadKatTest(192, DECRYPT, ALC_MODE);
}

TEST(AES_DEC_256, KAT_256)
{
    CipherAeadKatTest(256, DECRYPT, ALC_MODE);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parseArgs(argc, argv);
    return RUN_ALL_TESTS();
}