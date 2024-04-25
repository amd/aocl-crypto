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

#include "alcp/digest/sha512.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 48;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 128;
// IV array size where every element is 8 bytes

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                "274edebfe76f65fbd51ad2f14898b95b"} },
    { "Symbols", 
            { "!@#$",
                "213fd3930d3aec8cc96477170ee3264acb3e2234d7f36b425d519f99e62265374"
                "dd08cd4729bfa8349c16de6e07df771"} },
    { "All_Char",
            { "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed80"
                "86072ba1e7cc2358baeca134c825a7"} },
    { "All_Num",
            { "123", 
                "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b"
                "5cd8aaf9cec4919d76255b6bfb00f"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7"
                "c71a557e2db966c3e9fa91746039"}}
};

// clang-format on
class Sha384Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha384Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha384            sha384;
    Uint8             hash[DigestSize];
    std::stringstream ss;
    sha384.init();
    ASSERT_EQ(sha384.update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(sha384.finalize(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha384Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha384Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha384Test, invalid_input_update_test)
{
    Sha384 sha384;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha384.update(nullptr, 0));
}

TEST(Sha384Test, zero_size_update_test)
{
    Sha384      sha384;
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha384.update(src, 0));
}

TEST(Sha384Test, invalid_output_copy_hash_test)
{
    Sha384 sha384;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha384.finalize(nullptr, DigestSize));
}

TEST(Sha384Test, zero_size_hash_copy_test)
{
    Sha384 sha384;
    Uint8  hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha384.finalize(hash, 0));
}

TEST(Sha384Test, over_size_hash_copy_test)
{
    Sha384 sha384;
    Uint8  hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha384.finalize(hash, DigestSize + 1));
}

TEST(Sha384Test, getInputBlockSizeTest)
{
    Sha384 sha384;
    EXPECT_EQ(sha384.getInputBlockSize(), InputBlockSize);
}
TEST(Sha384Test, getHashSizeTest)
{
    Sha384 sha384;
    EXPECT_EQ(sha384.getHashSize(), DigestSize);
}
TEST(Sha384Test, object_copy_test)
{
    string            plaintext("1111");
    Sha384            sha384;
    Uint8             hash[DigestSize], hash_dup[DigestSize];
    std::stringstream ss, ss_dup;

    sha384.init();
    ASSERT_EQ(sha384.update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);

    Sha384 sha384_dup = sha384;

    ASSERT_EQ(sha384.finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha384_dup.finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

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

} // namespace
