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

#include "alcp/digest/sha2.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 28;
// Input Block Size in bytes
static constexpr Uint8 InputBlockSize = 64;

typedef std::tuple<std::vector<Uint8>, // message
                   std::vector<Uint8>  // expected_digest
                   >
                                                 ParamTuple2;
typedef std::map<const std::string, ParamTuple2> KnownAnswerMap2;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"} },
    { "Symbols", 
            { "!@#$",
                "065059bd65226ad9b78a59d6726064fdc101fda1b8baa695d42f55b1"} },
    { "All_Char",
            { "abc",
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"} },
    { "All_Num",
            { "123", 
                "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"}}
};

// clang-format off
KnownAnswerMap2 KATDataset2 = {
    { "FAILURE_CASE",
      { { 0xb5, 0x03, 0xb9, 0xce, 0x4a, 0x9a, 0x04, 0xa3, 0xf5, 0xb1, 0x36,
          0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
          0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
          0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
          0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
          0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xa3, 0xbb,
          0x06, 0x7d, 0x77, 0x20, 0xca, 0x44, 0x0e, 0x40, 0xba, 0x2a, 0x09,
          0xf9, 0xf3, 0xd8, 0x6c, 0x50, 0x23, 0x4e, 0x8a, 0xe0, 0x5f, 0x84,
          0x1e, 0x9b, 0x83, 0xb4, 0x48, 0xfe, 0xb3, 0x47, 0xed, 0x35, 0x54,
          0x25, 0xc9, 0x8e, 0xc3, 0xdc, 0xf2, 0x10, 0x66, 0x75, 0x1a, 0x55,
          0x6b, 0x0e, 0x99, 0x76, 0x65, 0x51, 0x32, 0x41, 0x00 },
        { 0x56, 0x65, 0x99, 0xd7, 0xc7, 0x95, 0x56, 0xf8, 0x9c, 0x2a,
          0xb1, 0x1a, 0x34, 0x0f, 0x8e, 0x44, 0x5c, 0x1d, 0xb6, 0x91,
          0x37, 0xe9, 0x80, 0xc6, 0xb0, 0x5e, 0xd3, 0x67 } 
        } 
    },{
        "PASSING_TEST_CASE",
        {
            {
            0xbd,0xe2,0xfe,0x06,0x61,0xe8,0x44,0x6e,0xa4,0x82
            },
            {
            0xb4,0xb6,0xe9,0x29,0x4e,0xed,0xab,0x83,0xf7,0x7f,0x5a,0x73,0x44,0xae,0xe1,0x5a,0xbe,0xaa,0x25,0x32,0xb6,0x15,0xaa,0xd2,0xbe,0x92,0x01,0xd4
            }
        }

    }
};
// clang-format on
class Sha224Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

class Sha224Kat
    : public testing::TestWithParam<std::pair<const string, ParamTuple2>>
{
  public:
    std::unique_ptr<Sha224> sha224{};
    std::vector<Uint8>      m_message, m_digest;
    void                    SetUp() override
    {
        const auto& params            = GetParam();
        const auto& [message, digest] = params.second;
        // const auto& test_name         = params.first; // Unused variable
        m_message = message;
        m_digest  = digest;
        sha224    = std::make_unique<Sha224>();
        sha224->init();
    }

    void TearDown() override { sha224.reset(); }
};

TEST_P(Sha224Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    Uint8                   hash[DigestSize];
    std::stringstream       ss;

    sha224->init();
    ASSERT_EQ(sha224->update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(sha224->finalize(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha224Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha224Test::ParamType>& info)
        -> const std::string { return info.param.first; });

TEST(Sha224Test, invalid_input_update_test)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224->update(nullptr, 0));
}

TEST(Sha224Test, zero_size_update_test)
{
    std::unique_ptr<Sha224> sha224          = std::make_unique<Sha224>();
    const Uint8             src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha224->update(src, 0));
}

TEST(Sha224Test, invalid_output_copy_hash_test)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224->finalize(nullptr, DigestSize));
}

TEST(Sha224Test, zero_size_hash_copy_test)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    Uint8                   hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224->finalize(hash, 0));
}

TEST(Sha224Test, over_size_hash_copy_test)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    Uint8                   hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224->finalize(hash, DigestSize + 1));
}

TEST(Sha224Test, call_finalize_twice_test)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    // calling finalize multiple times shoud not result in error
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_NONE, sha224->finalize(hash, DigestSize));
    EXPECT_EQ(ALC_ERROR_NONE, sha224->finalize(hash, DigestSize));
}

TEST(Sha224Test, getInputBlockSizeTest)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    EXPECT_EQ(sha224->getInputBlockSize(), InputBlockSize);
}
TEST(Sha224Test, getHashSizeTest)
{
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    EXPECT_EQ(sha224->getHashSize(), DigestSize);
}

TEST(Sha224Test, object_copy_test)
{
    string                  plaintext("1111");
    std::unique_ptr<Sha224> sha224 = std::make_unique<Sha224>();
    Uint8                   hash[DigestSize], hash_dup[DigestSize];
    std::stringstream       ss, ss_dup;

    sha224->init();
    ASSERT_EQ(sha224->update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);

    std::unique_ptr<Sha224> sha224_dup = std::make_unique<Sha224>(*sha224);

    ASSERT_EQ(sha224->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha224_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    ss_dup << std::hex << std::setfill('0');
    ;
    for (Uint16 i = 0; i < DigestSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
        ss_dup << std::setw(2) << static_cast<unsigned>(hash_dup[i]);
    }
    std::string hash_string = ss.str(), hash_string_dup = ss_dup.str();
    EXPECT_TRUE(hash_string == hash_string_dup);
}

TEST_P(Sha224Kat, KnownAnswerTest2)
{

    sha224->update(&m_message[0], m_message.size());
    std::vector<Uint8> expected_mac(sha224->getHashSize());
    sha224->finalize(&expected_mac[0], expected_mac.size());

    EXPECT_EQ(expected_mac, m_digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    Sha224Kat,
    testing::ValuesIn(KATDataset2),
    [](const testing::TestParamInfo<Sha224Kat::ParamType>& info)
        -> const std::string { return info.param.first; });

} // namespace
