/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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

#include <memory>

#include "alcp/digest/sha3.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 48;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 104;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",
      { "",
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004" } },
    { "Symbols",
      { "!@#$",
        "f63cc72e3698bc5146b51ed2b819ddbf2461b560c2b492765890b816d66f2b0ef"
        "09e5e5ec2ba33293c0bcc18aae969ac" } },
    { "All_Char",
      { "abc",
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b29"
        "8d88cea927ac7f539f1edf228376d25" } },
    { "All_Num",
      { "123",
        "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988"
        "b1c12803d4a8c9ba38fdc873e5f007" } },
    { "Long_Input",
      { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c7"
        "09b98b43b3852b337216179aa7fc7" } }
};

// clang-format on
class Sha3_384_Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_384_Test, digest_generation_test)
{
    const auto [plaintext, digest]     = GetParam().second;
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    Uint8                     hash[DigestSize];
    std::stringstream         ss;

    sha3_384->init();
    ASSERT_EQ(
        sha3_384->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);
    ASSERT_EQ(sha3_384->finalize(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_384_Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_384_Test::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST(Sha3_384_Test, invalid_input_update_test)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384->update(nullptr, 0));
}

TEST(Sha3_384_Test, zero_size_update_test)
{
    std::unique_ptr<Sha3_384> sha3_384        = std::make_unique<Sha3_384>();
    const Uint8               src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha3_384->update(src, 0));
}

TEST(Sha3_384_Test, invalid_output_copy_hash_test)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384->finalize(nullptr, DigestSize));
}

TEST(Sha3_384_Test, zero_size_hash_copy_test)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    Uint8                     hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384->finalize(hash, 0));
}

TEST(Sha3_384_Test, over_size_hash_copy_test)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    Uint8                     hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384->finalize(hash, DigestSize + 1));
}

TEST(Sha3_384_Test, getInputBlockSizeTest)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    EXPECT_EQ(sha3_384->getInputBlockSize(), InputBlockSize);
}

TEST(Sha3_384_Test, getHashSizeTest)
{
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    EXPECT_EQ(sha3_384->getHashSize(), DigestSize);
}

TEST(Sha3_384_Test, object_copy_test)
{
    string                    plaintext("1111");
    std::unique_ptr<Sha3_384> sha3_384 = std::make_unique<Sha3_384>();
    Uint8                     hash[DigestSize], hash_dup[DigestSize];
    std::stringstream         ss, ss_dup;

    sha3_384->init();
    ASSERT_EQ(
        sha3_384->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);

    std::unique_ptr<Sha3_384> sha3_384_dup =
        std::make_unique<Sha3_384>(*sha3_384);

    ASSERT_EQ(sha3_384->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_384_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    ss_dup << std::hex << std::setfill('0');

    for (Uint16 i = 0; i < DigestSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
        ss_dup << std::setw(2) << static_cast<unsigned>(hash_dup[i]);
    }
    std::string hash_string = ss.str(), hash_string_dup = ss_dup.str();
    EXPECT_TRUE(hash_string == hash_string_dup);
}

} // namespace
