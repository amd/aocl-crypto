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

#include "alcp/digest/sha3.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 28;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 144;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",
      { "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" } },
    { "Symbols",
      { "!@#$", "e22e7553367578d29912464418c37de0e24c34522d237408eb0d158e" } },
    { "All_Char",
      { "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" } },
    { "All_Num",
      { "123", "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097" } },
    { "Long_Input",
      { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc" } }
};

// clang-format on
class Sha3_224_Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_224_Test, digest_generation_test)
{

    const auto [plaintext, digest] = GetParam().second;
    Sha3_224          sha3_224;
    Uint8             hash[DigestSize];
    std::stringstream ss;

    sha3_224.init();
    ASSERT_EQ(
        sha3_224.update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);
    ASSERT_EQ(sha3_224.finalize(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_224_Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_224_Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha3_224_Test, invalid_input_update_test)
{
    Sha3_224 sha3_224;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_224.update(nullptr, 0));
}

TEST(Sha3_224_Test, zero_size_update_test)
{
    Sha3_224    sha3_224;
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha3_224.update(src, 0));
}

TEST(Sha3_224_Test, invalid_output_copy_hash_test)
{
    Sha3_224 sha3_224;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_224.finalize(nullptr, DigestSize));
}

TEST(Sha3_224_Test, zero_size_hash_copy_test)
{
    Sha3_224 sha3_224;
    Uint8    hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_224.finalize(hash, 0));
}

TEST(Sha3_224_Test, over_size_hash_copy_test)
{
    Sha3_224 sha3_224;
    Uint8    hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_224.finalize(hash, DigestSize + 1));
}

TEST(Sha3_224_Test, getInputBlockSizeTest)
{
    Sha3_224 sha3_224;
    EXPECT_EQ(sha3_224.getInputBlockSize(), InputBlockSize);
}

TEST(Sha3_224_Test, getHashSizeTest)
{
    Sha3_224 sha3_224;
    EXPECT_EQ(sha3_224.getHashSize(), DigestSize);
}

TEST(Sha3_224_Test, setShakeLengthTest)
{
    Sha3_224    sha3_224;
    alc_error_t err = ALC_ERROR_NONE;

    constexpr unsigned short cShakeLength = 100;

    err = sha3_224.setShakeLength(cShakeLength);
    EXPECT_EQ(err, ALC_ERROR_NOT_PERMITTED);
    EXPECT_EQ(sha3_224.getHashSize(), DigestSize);
    EXPECT_NE(sha3_224.getHashSize(), cShakeLength);
}

} // namespace
