/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "../../rng/include/hardware_rng.hh"
#include "openssl/bio.h"
#include "rng/drbg_hmac.hh"
#include "gtest/gtest.h"
#include <iostream>

// #include "types.h"
using namespace alcp::random_number::drbg;
using namespace alcp::random_number;

TEST(DRBGFrameWork, Concat)
{
    const std::vector<Uint8> a = { static_cast<const Uint8>('H'),
                                   static_cast<const Uint8>('E'),
                                   static_cast<const Uint8>('L'),
                                   static_cast<const Uint8>('L'),
                                   static_cast<const Uint8>('O') };
    const std::vector<Uint8> b = {
        static_cast<const Uint8>(' '), static_cast<const Uint8>('W'),
        static_cast<const Uint8>('O'), static_cast<const Uint8>('R'),
        static_cast<const Uint8>('L'), static_cast<const Uint8>('D')
    };
    const std::vector<Uint8> c = { static_cast<Uint8>('!'),
                                   static_cast<Uint8>('\n') };
    concat_type_t<Uint8>     concatVect(3);
    std::vector<Uint8>       output(13);
    const std::vector<Uint8> expOutput = {
        static_cast<const Uint8>('H'), static_cast<const Uint8>('E'),
        static_cast<const Uint8>('L'), static_cast<const Uint8>('L'),
        static_cast<const Uint8>('O'), static_cast<const Uint8>(' '),
        static_cast<const Uint8>('W'), static_cast<const Uint8>('O'),
        static_cast<const Uint8>('R'), static_cast<const Uint8>('L'),
        static_cast<const Uint8>('D'), static_cast<const Uint8>('!'),
        static_cast<const Uint8>('\n')
    };
    concatVect[0] = &a;
    concatVect[1] = &b;
    concatVect[2] = &c;

    HmacDrbg::concat(concatVect, output);

    EXPECT_EQ(output, expOutput);
}

TEST(DRBGFrameWork, ConcatRand)
{
    alc_rng_info_t rng_info = {};
    HardwareRng    hrng     = HardwareRng(rng_info);
    Uint8          randVal[4]; // Fixme 4 Due to stride
    hrng.randomize(reinterpret_cast<Uint8*>(&randVal), 4);
    const std::vector<Uint8> a(randVal[0]);
    const std::vector<Uint8> b(randVal[1]);
    const std::vector<Uint8> c(randVal[2]);
    concat_type_t<Uint8>     concatVect(3);
    std::vector<Uint8>       output(a.size() + b.size() + c.size());
    std::vector<Uint8>       expOutput;

    // Costly but reliable insertion method
    expOutput.insert(expOutput.end(), a.begin(), a.end());
    expOutput.insert(expOutput.end(), b.begin(), b.end());
    expOutput.insert(expOutput.end(), c.begin(), c.end());

    concatVect[0] = &a;
    concatVect[1] = &b;
    concatVect[2] = &c;

    HmacDrbg::concat(concatVect, output);

    EXPECT_EQ(output, expOutput);
}

TEST(DRBGFrameWork, Wrapper_Test)
{
    std::vector<Uint8> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                               0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                               0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                               0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                               0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
    std::vector<Uint8> in  = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
                              0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
                              0x20, 0x66, 0x6f, 0x72, 0x20, 0x6b, 0x65,
                              0x79, 0x6c, 0x65, 0x6e, 0x3d, 0x62, 0x6c,
                              0x6f, 0x63, 0x6b, 0x6c, 0x65, 0x6e };
    std::vector<Uint8> expMac = { 0x8b, 0xb9, 0xa1, 0xdb, 0x98, 0x06, 0xf2,
                                  0x0d, 0xf7, 0xf7, 0x7b, 0x82, 0x13, 0x8c,
                                  0x79, 0x14, 0xd1, 0x74, 0xd5, 0x9e, 0x13,
                                  0xdc, 0x4d, 0x01, 0x69, 0xc9, 0x05, 0x7b,
                                  0x13, 0x3e, 0x1d, 0x62 };
    std::vector<Uint8> out(expMac.size());
    HmacDrbg::HMAC_Wrapper(key, in, out);

    std::vector<Uint8> p_K(32, 0);
    std::vector<Uint8> p_V(32, 1);
    std::vector<Uint8> provided_data(0);
    HmacDrbg::Update(provided_data, p_K, p_V);
    BIO_dump_fp(stdout, &p_K[0], 32);
    BIO_dump_fp(stdout, &p_V[0], 32);

    EXPECT_EQ(out, expMac);
}

// From complete example code. Passing
TEST(DRBGGeneration, SHA256_1)
{
    const std::vector<Uint8> EntropyInput = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
    };

    const std::vector<Uint8> nonce = { 0x20, 0x21, 0x22, 0x23,
                                       0x24, 0x25, 0x26, 0x27 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> expReturnedBits = {
        0xD6, 0x7B, 0x8C, 0x17, 0x34, 0xF4, 0x6F, 0xA3, 0xF7, 0x63, 0xCF,
        0x57, 0xC6, 0xF9, 0xF4, 0xF2, 0xDC, 0x10, 0x89, 0xBD, 0x8B, 0xC1,
        0xF6, 0xF0, 0x23, 0x95, 0x0B, 0xFC, 0x56, 0x17, 0x63, 0x52, 0x08,
        0xC8, 0x50, 0x12, 0x38, 0xAD, 0x7A, 0x44, 0x00, 0xDE, 0xFE, 0xE4,
        0x6C, 0x64, 0x0B, 0x61, 0xAF, 0x77, 0xC2, 0xD1, 0xA3, 0xBF, 0xAA,
        0x90, 0xED, 0xE5, 0xD2, 0x07, 0x40, 0x6E, 0x54, 0x03
    };

    std::vector<Uint8> key(32);
    std::vector<Uint8> v(32);

    HmacDrbg::Instantiate(EntropyInput, nonce, PersonalizationString, key, v);

    std::vector<Uint8> output(expReturnedBits.size());
    HmacDrbg::Generate(AdditionalInput, output, key, v);

    EXPECT_EQ(expReturnedBits, output);
}

TEST(DRBGGeneration, SHA256_FAIL)
{
    const std::vector<Uint8> EntropyInput = {
        0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde,
        0x1c, 0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb,
        0x93, 0x5e, 0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88
    };

    const std::vector<Uint8> nonce = { 0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d,
                                       0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08,
                                       0x05, 0xec, 0x0c, 0xa8 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> expReturnedBits = {
        0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e, 0x75,
        0xe5, 0xfe, 0x30, 0x21, 0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4, 0xbe, 0xe6,
        0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89, 0xd5, 0x4f, 0xbb, 0x97,
        0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21, 0x03, 0x6d, 0x24, 0x60,
        0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a, 0xba, 0x6e, 0x62, 0x4a, 0xbf,
        0x07, 0x74, 0x5b, 0xc1, 0x07, 0x69, 0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99,
        0x5f, 0x70, 0xde, 0x25, 0xd6, 0xb2, 0x9e, 0x2d, 0x30, 0x11, 0xbb, 0x19,
        0xd2, 0x76, 0x76, 0xc0, 0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68,
        0x96, 0x1d, 0xf8, 0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0,
        0xbb, 0x8d, 0x50, 0xcf, 0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd,
        0xab, 0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8
    };

    std::vector<Uint8> key(32);
    std::vector<Uint8> v(32);

    HmacDrbg::Instantiate(EntropyInput, nonce, PersonalizationString, key, v);

    std::cout << "Test Instantiate : key=" << std::endl;
    BIO_dump_fp(stdout, &key[0], key.size());
    std::cout << std::endl;

    std::cout << "Test Instantiate : v=" << std::endl;
    BIO_dump_fp(stdout, &v[0], v.size());
    std::cout << std::endl;

    std::vector<Uint8> output(expReturnedBits.size(), 0x01);
    HmacDrbg::Generate(AdditionalInput, output, key, v);
    HmacDrbg::Generate(AdditionalInput, output, key, v);

    std::cout << "Test Generate : key=" << std::endl;
    BIO_dump_fp(stdout, &key[0], key.size());
    std::cout << std::endl;

    std::cout << "Test Generate : v=" << std::endl;
    BIO_dump_fp(stdout, &v[0], v.size());
    std::cout << std::endl;

    EXPECT_EQ(expReturnedBits, output);
    std::cout << "FINALLY! THERE THE STANDS!" << std::endl;
    BIO_dump_fp(stdout, &expReturnedBits[0], expReturnedBits.size());
    BIO_dump_fp(stdout, &output[0], output.size());
}

TEST(DRBGGeneration, SHA256_FAIL_1)
{
    const std::vector<Uint8> EntropyInput = {
        0x79, 0x73, 0x74, 0x79, 0xba, 0x4e, 0x76, 0x42, 0xa2, 0x21, 0xfc,
        0xfd, 0x1b, 0x82, 0x0b, 0x13, 0x4e, 0x9e, 0x35, 0x40, 0xa3, 0x5b,
        0xb4, 0x8f, 0xfa, 0xe2, 0x9c, 0x20, 0xf5, 0x41, 0x8e, 0xa3
    };

    const std::vector<Uint8> nonce = { 0x35, 0x93, 0x25, 0x9c, 0x09, 0x2b,
                                       0xef, 0x41, 0x29, 0xbc, 0x2c, 0x6c,
                                       0x9e, 0x19, 0xf3, 0x43 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    const std::vector<Uint8> expReturnedBits = {
        0xcf, 0x5a, 0xd5, 0x98, 0x4f, 0x9e, 0x43, 0x91, 0x7a, 0xa9, 0x08, 0x73,
        0x80, 0xda, 0xc4, 0x6e, 0x41, 0x0d, 0xdc, 0x8a, 0x77, 0x31, 0x85, 0x9c,
        0x84, 0xe9, 0xd0, 0xf3, 0x1b, 0xd4, 0x36, 0x55, 0xb9, 0x24, 0x15, 0x94,
        0x13, 0xe2, 0x29, 0x3b, 0x17, 0x61, 0x0f, 0x21, 0x1e, 0x09, 0xf7, 0x70,
        0xf1, 0x72, 0xb8, 0xfb, 0x69, 0x3a, 0x35, 0xb8, 0x5d, 0x3b, 0x9e, 0x5e,
        0x63, 0xb1, 0xdc, 0x25, 0x2a, 0xc0, 0xe1, 0x15, 0x00, 0x2e, 0x9b, 0xed,
        0xfb, 0x4b, 0x5b, 0x6f, 0xd4, 0x3f, 0x33, 0xb8, 0xe0, 0xea, 0xfb, 0x2d,
        0x07, 0x2e, 0x1a, 0x6f, 0xee, 0x1f, 0x15, 0x9d, 0xf9, 0xb5, 0x1e, 0x6c,
        0x8d, 0xa7, 0x37, 0xe6, 0x0d, 0x50, 0x32, 0xdd, 0x30, 0x54, 0x4e, 0xc5,
        0x15, 0x58, 0xc6, 0xf0, 0x80, 0xbd, 0xbd, 0xab, 0x1d, 0xe8, 0xa9, 0x39,
        0xe9, 0x61, 0xe0, 0x6b, 0x5f, 0x1a, 0xca, 0x37
    };

    std::vector<Uint8> key(32);
    std::vector<Uint8> v(32);

    HmacDrbg::Instantiate(EntropyInput, nonce, PersonalizationString, key, v);

    std::cout << "Test Instantiate : key=" << std::endl;
    BIO_dump_fp(stdout, &key[0], key.size());
    std::cout << std::endl;

    std::cout << "Test Instantiate : v=" << std::endl;
    BIO_dump_fp(stdout, &v[0], v.size());
    std::cout << std::endl;

    std::vector<Uint8> output(expReturnedBits.size(), 0x01);
    HmacDrbg::Generate(AdditionalInput, output, key, v);
    HmacDrbg::Generate(AdditionalInput, output, key, v);

    std::cout << "Test Generate : key=" << std::endl;
    BIO_dump_fp(stdout, &key[0], key.size());
    std::cout << std::endl;

    std::cout << "Test Generate : v=" << std::endl;
    BIO_dump_fp(stdout, &v[0], v.size());
    std::cout << std::endl;

    EXPECT_EQ(expReturnedBits, output);
    std::cout << "FINALLY! THERE THE STANDS!" << std::endl;
    BIO_dump_fp(stdout, &expReturnedBits[0], expReturnedBits.size());
    BIO_dump_fp(stdout, &output[0], output.size());
}

TEST(Instantiate, SHA256)
{
    const std::vector<Uint8> EntropyInput = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
    };

    const std::vector<Uint8> nonce = { 0x20, 0x21, 0x22, 0x23,
                                       0x24, 0x25, 0x26, 0x27 };

    const std::vector<Uint8> PersonalizationString(0);

    const std::vector<Uint8> AdditionalInput(0);

    std::vector<Uint8> key(32);
    std::vector<Uint8> v(32);

    std::vector<Uint8> key_exp = { 0x3D, 0xDA, 0x54, 0x3E, 0x7E, 0xEF, 0x14,
                                   0xF9, 0x36, 0x23, 0x7B, 0xE6, 0x5D, 0x09,
                                   0x4B, 0x4D, 0xDC, 0x96, 0x9C, 0x0B, 0x2B,
                                   0x5E, 0xAF, 0xB5, 0xD8, 0x05, 0xE8, 0x6C,
                                   0xFA, 0x64, 0xD7, 0x41 };
    std::vector<Uint8> v_exp   = {
        0x2D, 0x02, 0xC2, 0xF8, 0x22, 0x51, 0x7D, 0x54, 0xB8, 0x17, 0x27,
        0x9A, 0x59, 0x49, 0x1C, 0x41, 0xA1, 0x98, 0x9B, 0x3E, 0x38, 0x2D,
        0xEB, 0xE8, 0x0D, 0x2C, 0x7F, 0x66, 0x0F, 0x44, 0x76, 0xC4
    };

    HmacDrbg::Instantiate(EntropyInput, nonce, PersonalizationString, key, v);

    EXPECT_EQ(key_exp, key);
    EXPECT_EQ(v_exp, v);
}

#if 0
int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
#endif
