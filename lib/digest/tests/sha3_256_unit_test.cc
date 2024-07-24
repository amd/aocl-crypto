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

#include <memory>

#include "alcp/digest/sha3.hh"
#include "gtest/gtest.h"

#include <fstream>

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 32;
// Input Block size in bytes
static constexpr Uint8 InputBlockSize = 136;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",
      { "",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" } },
    { "Symbols",
      { "!@#$",
        "91ca6ff7194aefa2ba367d458e87f7912dbb6c514b7d6ee1345f7b8eca699f92" } },
    { "All_Char",
      { "abc",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" } },
    { "All_Num",
      { "123",
        "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67" } },
    { "Long_Input",
      { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d1"
        "8" } }
};

// clang-format on
class Sha3_256_Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_256_Test, digest_generation_test)
{
    const auto [plaintext, digest]     = GetParam().second;
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    std::unique_ptr<Uint8[]>  hash     = std::make_unique<Uint8[]>(DigestSize);
    Uint8*                    hash_p   = hash.get();
    std::stringstream         ss;

    sha3_256->init();
    ASSERT_EQ(
        sha3_256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);
    ASSERT_EQ(sha3_256->finalize(hash_p, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash_p[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_256_Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_256_Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha3_256_Test, invalid_input_update_test)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256->update(nullptr, 0));
}

TEST(Sha3_256_Test, zero_size_update_test)
{
    std::unique_ptr<Sha3_256> sha3_256        = std::make_unique<Sha3_256>();
    const Uint8               src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha3_256->update(src, 0));
}

TEST(Sha3_256_Test, invalid_output_copy_hash_test)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256->finalize(nullptr, DigestSize));
}

TEST(Sha3_256_Test, zero_size_hash_copy_test)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    Uint8*                    hash     = new Uint8[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256->finalize(hash, 0));
    delete[] hash;
}

TEST(Sha3_256_Test, over_size_hash_copy_test)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    Uint8*                    hash     = new Uint8[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256->finalize(hash, DigestSize + 1));
    delete[] hash;
}

TEST(Sha3_256_Test, getInputBlockSizeTest)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    EXPECT_EQ(sha3_256->getInputBlockSize(), InputBlockSize);
}

TEST(Sha3_256_Test, getHashSizeTest)
{
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    EXPECT_EQ(sha3_256->getHashSize(), DigestSize);
}

TEST(Sha3_256_Test, object_copy_test)
{
    string                    plaintext("1111");
    std::unique_ptr<Sha3_256> sha3_256 = std::make_unique<Sha3_256>();
    Uint8                     hash[DigestSize], hash_dup[DigestSize];
    std::stringstream         ss, ss_dup;

    sha3_256->init();
    ASSERT_EQ(
        sha3_256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);

    std::unique_ptr<Sha3_256> sha3_256_dup =
        std::make_unique<Sha3_256>(*sha3_256);

    ASSERT_EQ(sha3_256->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_256_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

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
