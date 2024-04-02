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
static const Uint8 DigestSize = 32;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 64;
// IV array size where every element is 4 bytes
static const Uint8 IvArraySize   = 8;
static const Uint8 IvElementSize = 4;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} },
    { "Symbols", 
            { "!@#$",
                "1296bfb42b244aa5811e4098497329f3845ca6a3715c1da844d1999acc5cdfdd"} },
    { "All_Char",
            { "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"} },
    { "All_Num",
            { "123", 
                "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"}}
};

// clang-format on
class Sha256Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha256Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha256            sha256;
    Uint8             hash[DigestSize];
    std::stringstream ss;

    sha256.init();
    ASSERT_EQ(sha256.update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(sha256.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha256.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha256Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha256Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha256Test, invalid_input_update_test)
{
    Sha256 sha256;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256.update(nullptr, 0));
}

TEST(Sha256Test, zero_size_update_test)
{
    Sha256      sha256;
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha256.update(src, 0));
}

TEST(Sha256Test, invalid_output_copy_hash_test)
{
    Sha256 sha256;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha256.copyHash(nullptr, DigestSize));
}

TEST(Sha256Test, zero_size_hash_copy_test)
{
    Sha256 sha256;
    Uint8  hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha256.copyHash(hash, 0));
}

TEST(Sha256Test, over_size_hash_copy_test)
{
    Sha256 sha256;
    Uint8  hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha256.copyHash(hash, DigestSize + 1));
}

TEST(Sha256Test, invalid_iv_test)
{
    Sha256 sha256;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG,
              sha256.setIv(nullptr, IvArraySize * IvElementSize));
}

TEST(Sha256Test, zero_size_iv_test)
{
    Sha256 sha256;
    Uint32 iv[IvArraySize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha256.setIv(iv, 0));
}

TEST(Sha256Test, over_size_iv_test)
{
    Sha256 sha256;
    Uint32 iv[IvArraySize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha256.setIv(iv, sizeof(iv)));
}

TEST(Sha256Test, call_finalize_twice_test)
{
    Sha256 sha256;
    // calling finalize multiple times shoud not result in error
    EXPECT_EQ(ALC_ERROR_NONE, sha256.finalize(nullptr, 0));
    EXPECT_EQ(ALC_ERROR_NONE, sha256.finalize(nullptr, 0));
}

TEST(Sha256Test, getInputBlockSizeTest)
{
    Sha256 sha256;
    EXPECT_EQ(sha256.getInputBlockSize(), InputBlockSize);
}
TEST(Sha256Test, getHashSizeTest)
{
    Sha256 sha256;
    EXPECT_EQ(sha256.getHashSize(), DigestSize);
}

} // namespace
