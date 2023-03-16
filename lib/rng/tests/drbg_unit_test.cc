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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "../../rng/include/hardware_rng.hh"
#include "../../rng/include/system_rng.hh"
#include "alcp/base.hh"
#include "alcp/interface/Irng.hh"
#include "alcp/rng/drbg_hmac.hh"
#include "digest.hh"
#include "digest/sha2.hh"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

// #include "types.h"
using namespace alcp::rng::drbg;
using namespace alcp::rng;
using namespace alcp::digest;
using namespace alcp;

// #define DEBUG

#ifdef DEBUG
void
DebugPrintPretty(std::vector<Uint8>& output)
{
    std::cout << "{";
    for (size_t i = 0; i < output.size(); i++) {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<Uint32>(output.at(i));
        if (i < (output.size() - 1)) {
            std::cout << ",\t";
        }
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << "}" << std::endl;
}
#else
void
DebugPrintPretty(std::vector<Uint8>& output)
{
}
#endif

class NullGenerator : public IRng
{
  public:
    NullGenerator() = default;

    Status readRandom(Uint8* pBuf, Uint64 size) override { return StatusOk(); }

    Status randomize(Uint8 output[], size_t length) override
    {
        Status s = StatusOk();
        memset(output, 0, length);
        return s;
    }

    std::string name() const { return "Dummy DRBG"; }

    bool isSeeded() const { return true; }

    size_t reseed() { return 0; }

    Status setPredictionResistance(bool value)
    {
        Status s = StatusOk();
        return s;
    }
};

/**
 * @brief Example of implementing a class using Google Mock for testing
 *
 */
class MockGenerator : public IRng
{
  public:
    MockGenerator() = default;

    Status readRandom(Uint8* pBuf, Uint64 size) override { return StatusOk(); }

    MOCK_METHOD(Status, randomize, (Uint8 output[], size_t length), (override));

    std::string name() const { return "Mock DRBG"; }

    bool isSeeded() const { return true; }

    size_t reseed() { return 0; }

    Status setPredictionResistance(bool value)
    {
        Status s = StatusOk();
        return s;
    }
};

TEST(DRBG_HMAC, Instantiation)
{
    auto     sha_obj = std::make_shared<alcp::digest::Sha224>();
    auto     sys_rng = std::make_shared<alcp::rng::SystemRng>();
    HmacDrbg hmac_drbg;
    hmac_drbg.setRng(sys_rng);
    hmac_drbg.setDigest(sha_obj);
}

TEST(DRBG_HMAC, Generate)
{
    auto     sha_obj = std::make_shared<alcp::digest::Sha224>();
    auto     sys_rng = std::make_shared<alcp::rng::SystemRng>();
    HmacDrbg hmac_drbg;
    hmac_drbg.setRng(sys_rng);
    hmac_drbg.setDigest(sha_obj);
    std::vector<Uint8> output(200, 0);
    std::vector<Uint8> untouched_output(200, 0);
    std::vector<Uint8> personalization_string(0);

    hmac_drbg.initialize(128, personalization_string);
    hmac_drbg.randomize(&output[0], output.size());

    DebugPrintPretty(output);

    EXPECT_NE(output, untouched_output);
}

TEST(DRBG_HMAC, GenerateNull)
{
    auto     sha_obj = std::make_shared<alcp::digest::Sha224>();
    auto     sys_rng = std::make_shared<NullGenerator>();
    HmacDrbg hmac_drbg;
    hmac_drbg.setRng(sys_rng);
    hmac_drbg.setDigest(sha_obj);
    std::vector<Uint8> output(200, 0);
    std::vector<Uint8> untouched_output = {
        0x3a, 0x01, 0x46, 0xa7, 0xa8, 0x99, 0x3b, 0x7e, 0xd6, 0xb2, 0x87, 0x77,
        0xb3, 0xcf, 0xee, 0x18, 0x17, 0x13, 0x21, 0xc3, 0x61, 0x85, 0x43, 0x90,
        0x77, 0xf7, 0xf0, 0x59, 0x04, 0x15, 0x37, 0x58, 0x18, 0x33, 0xb5, 0x71,
        0x22, 0x06, 0x18, 0x66, 0x50, 0x42, 0x19, 0x8c, 0x9f, 0x76, 0x55, 0x3e,
        0x7c, 0x80, 0xd7, 0x27, 0xf5, 0xb6, 0x06, 0xdc, 0xa6, 0xd7, 0xec, 0xef,
        0x62, 0x53, 0xbf, 0xd7, 0x97, 0x76, 0x5f, 0x64, 0x1a, 0xab, 0xdb, 0xa2,
        0xa5, 0x5b, 0x07, 0x48, 0xaf, 0xb7, 0x33, 0xc1, 0x50, 0xac, 0xdb, 0x06,
        0x95, 0x69, 0x5f, 0xa0, 0x49, 0xac, 0x49, 0x59, 0xd9, 0x45, 0x72, 0x78,
        0xc8, 0xb3, 0x5e, 0xc8, 0x2e, 0x11, 0x0f, 0x66, 0x32, 0x91, 0x26, 0x2f,
        0x26, 0xb3, 0xa2, 0x37, 0xc6, 0x7f, 0xe8, 0x64, 0x43, 0xfd, 0x19, 0x8c,
        0x27, 0xe4, 0x75, 0x69, 0x0e, 0xca, 0xad, 0xe8, 0xb2, 0xca, 0x9b, 0x7c,
        0x3d, 0xda, 0x8a, 0x83, 0x7b, 0x7a, 0x5f, 0xe8, 0xca, 0x4d, 0x2e, 0xa3,
        0x64, 0xbd, 0xdb, 0x7d, 0x68, 0xda, 0xdf, 0x52, 0xd5, 0x76, 0x22, 0xab,
        0x8a, 0xe9, 0x90, 0x71, 0x16, 0x69, 0x22, 0xd2, 0x2f, 0xa6, 0xbf, 0x0b,
        0xfe, 0x69, 0x7e, 0x8f, 0x0b, 0x50, 0xb9, 0x48, 0x7f, 0xf2, 0x63, 0x72,
        0x0c, 0xf9, 0x6b, 0xca, 0x7c, 0x1f, 0x64, 0x9f, 0x78, 0xf7, 0x02, 0xe0,
        0xec, 0xbc, 0x18, 0x2b, 0x91, 0x84, 0x3a, 0x7a
    };
    std::vector<Uint8> personalization_string(0);

    hmac_drbg.initialize(128, personalization_string);
    hmac_drbg.randomize(&output[0], output.size());

    DebugPrintPretty(output);

    EXPECT_EQ(output, untouched_output);
}

TEST(DRBG_HMAC, MutiGenerate)
{
    auto     sha_obj = std::make_shared<alcp::digest::Sha224>();
    auto     sys_rng = std::make_shared<alcp::rng::SystemRng>();
    HmacDrbg hmac_drbg;
    hmac_drbg.setRng(sys_rng);
    hmac_drbg.setDigest(sha_obj);
    std::vector<Uint8> output_1(10, 0);
    std::vector<Uint8> output_2(10, 0);
    std::vector<Uint8> personalization_string(0);

    hmac_drbg.initialize(128, personalization_string);
    hmac_drbg.randomize(&output_1[0], output_1.size());
    hmac_drbg.randomize(&output_2[0], output_1.size());

    DebugPrintPretty(output_1);

    EXPECT_NE(output_1, output_2);

    for (int i = 0; i < 10; i++) {
        output_2 = output_1;
        hmac_drbg.randomize(&output_1[0], output_1.size());
        hmac_drbg.randomize(&output_2[0], output_1.size());
        EXPECT_NE(output_1, output_2);
    }
}

/**
 * @brief Example of how to use google mock in testing
 *
 */
TEST(DRBG_HMAC, GenerateMock)
{
    auto     sha_obj = std::make_shared<alcp::digest::Sha224>();
    auto     sys_rng = std::make_shared<MockGenerator>();
    HmacDrbg hmac_drbg;
    hmac_drbg.setRng(sys_rng);
    hmac_drbg.setDigest(sha_obj);
    std::vector<Uint8> output(200, 0);
    std::vector<Uint8> untouched_output = {
        0x3a, 0x01, 0x46, 0xa7, 0xa8, 0x99, 0x3b, 0x7e, 0xd6, 0xb2, 0x87, 0x77,
        0xb3, 0xcf, 0xee, 0x18, 0x17, 0x13, 0x21, 0xc3, 0x61, 0x85, 0x43, 0x90,
        0x77, 0xf7, 0xf0, 0x59, 0x04, 0x15, 0x37, 0x58, 0x18, 0x33, 0xb5, 0x71,
        0x22, 0x06, 0x18, 0x66, 0x50, 0x42, 0x19, 0x8c, 0x9f, 0x76, 0x55, 0x3e,
        0x7c, 0x80, 0xd7, 0x27, 0xf5, 0xb6, 0x06, 0xdc, 0xa6, 0xd7, 0xec, 0xef,
        0x62, 0x53, 0xbf, 0xd7, 0x97, 0x76, 0x5f, 0x64, 0x1a, 0xab, 0xdb, 0xa2,
        0xa5, 0x5b, 0x07, 0x48, 0xaf, 0xb7, 0x33, 0xc1, 0x50, 0xac, 0xdb, 0x06,
        0x95, 0x69, 0x5f, 0xa0, 0x49, 0xac, 0x49, 0x59, 0xd9, 0x45, 0x72, 0x78,
        0xc8, 0xb3, 0x5e, 0xc8, 0x2e, 0x11, 0x0f, 0x66, 0x32, 0x91, 0x26, 0x2f,
        0x26, 0xb3, 0xa2, 0x37, 0xc6, 0x7f, 0xe8, 0x64, 0x43, 0xfd, 0x19, 0x8c,
        0x27, 0xe4, 0x75, 0x69, 0x0e, 0xca, 0xad, 0xe8, 0xb2, 0xca, 0x9b, 0x7c,
        0x3d, 0xda, 0x8a, 0x83, 0x7b, 0x7a, 0x5f, 0xe8, 0xca, 0x4d, 0x2e, 0xa3,
        0x64, 0xbd, 0xdb, 0x7d, 0x68, 0xda, 0xdf, 0x52, 0xd5, 0x76, 0x22, 0xab,
        0x8a, 0xe9, 0x90, 0x71, 0x16, 0x69, 0x22, 0xd2, 0x2f, 0xa6, 0xbf, 0x0b,
        0xfe, 0x69, 0x7e, 0x8f, 0x0b, 0x50, 0xb9, 0x48, 0x7f, 0xf2, 0x63, 0x72,
        0x0c, 0xf9, 0x6b, 0xca, 0x7c, 0x1f, 0x64, 0x9f, 0x78, 0xf7, 0x02, 0xe0,
        0xec, 0xbc, 0x18, 0x2b, 0x91, 0x84, 0x3a, 0x7a
    };

    std::vector<Uint8> personalization_string(0);
    // const auto         s = testing::Action<Status>(StatusOk());
    EXPECT_CALL(*(sys_rng.get()), randomize(::testing::_, ::testing::_))
        .Times(2)
        .WillRepeatedly([](Uint8 output[], size_t length) {
            memset(output, 0, length);
            return StatusOk();
        });

    hmac_drbg.initialize(128, personalization_string);
    hmac_drbg.randomize(&output[0], output.size());

    DebugPrintPretty(output);

    EXPECT_EQ(output, untouched_output);
}