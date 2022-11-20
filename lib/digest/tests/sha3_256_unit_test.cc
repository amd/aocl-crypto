/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "digest/sha3.hh"
#include "gtest/gtest.h"

#include <fstream>

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

static const alc_digest_info_t DigestInfo = []() {
    alc_digest_info_t DigestInfo;
    DigestInfo.dt_type         = ALC_DIGEST_TYPE_SHA3;
    DigestInfo.dt_len          = ALC_DIGEST_LEN_256;
    DigestInfo.dt_mode.dm_sha3 = ALC_SHA3_256;
    return DigestInfo;
}();

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
class Sha3_256
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_256, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha3              sha3_256(DigestInfo);
    Uint8             hash[DigestSize];
    std::stringstream ss;

    ASSERT_EQ(
        sha3_256.update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);
    ASSERT_EQ(sha3_256.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_256.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_256,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_256::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha3_256, invalid_input_update_test)
{
    Sha3 sha3_256(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256.update(nullptr, 0));
}

TEST(Sha3_256, zero_size_update_test)
{
    Sha3        sha3_256(DigestInfo);
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha3_256.update(src, 0));
}

TEST(Sha3_256, invalid_output_copy_hash_test)
{
    Sha3 sha3_256(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_256.copyHash(nullptr, DigestSize));
}

TEST(Sha3_256, zero_size_hash_copy_test)
{
    Sha3  sha3_256(DigestInfo);
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_256.copyHash(hash, 0));
}

TEST(Sha3_256, over_size_hash_copy_test)
{
    Sha3  sha3_256(DigestInfo);
    Uint8 hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_256.copyHash(hash, DigestSize + 1));
}

TEST(Sha3_256, getInputBlockSizeTest)
{
    Sha3 sha3_256(DigestInfo);
    EXPECT_EQ(sha3_256.getInputBlockSize(), InputBlockSize);
}

TEST(Sha3_256, getHashSizeTest)
{
    Sha3 sha3_256(DigestInfo);
    EXPECT_EQ(sha3_256.getHashSize(), DigestSize);
}

} // namespace
