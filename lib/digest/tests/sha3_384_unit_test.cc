/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

static const alc_digest_info_t DigestInfo = []() {
    alc_digest_info_t DigestInfo;
    DigestInfo.dt_type         = ALC_DIGEST_TYPE_SHA3;
    DigestInfo.dt_len          = ALC_DIGEST_LEN_384;
    DigestInfo.dt_mode.dm_sha3 = ALC_SHA3_384;
    return DigestInfo;
}();

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
class Sha3_384
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_384, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha3              sha3_384(DigestInfo);
    Uint8             hash[DigestSize];
    std::stringstream ss;

    ASSERT_EQ(
        sha3_384.update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);
    ASSERT_EQ(sha3_384.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_384.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_384,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_384::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha3_384, invalid_input_update_test)
{
    Sha3 sha3_384(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384.update(nullptr, 0));
}

TEST(Sha3_384, zero_size_update_test)
{
    Sha3        sha3_384(DigestInfo);
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha3_384.update(src, 0));
}

TEST(Sha3_384, invalid_output_copy_hash_test)
{
    Sha3 sha3_384(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_384.copyHash(nullptr, DigestSize));
}

TEST(Sha3_384, zero_size_hash_copy_test)
{
    Sha3  sha3_384(DigestInfo);
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_384.copyHash(hash, 0));
}

TEST(Sha3_384, over_size_hash_copy_test)
{
    Sha3  sha3_384(DigestInfo);
    Uint8 hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_384.copyHash(hash, DigestSize + 1));
}

TEST(Sha3_384, getInputBlockSizeTest)
{
    Sha3 sha3_384(DigestInfo);
    EXPECT_EQ(sha3_384.getInputBlockSize(), InputBlockSize);
}

TEST(Sha3_384, getHashSizeTest)
{
    Sha3 sha3_384(DigestInfo);
    EXPECT_EQ(sha3_384.getHashSize(), DigestSize);
}

TEST(Sha3_384, setShakeLengthTest)
{
    Sha3        sha3_384(DigestInfo);
    alc_error_t err                       = ALC_ERROR_NONE;
    err                                   = sha3_384.setShakeLength(384);
    constexpr unsigned short cShakeLength = 100;

    err = sha3_384.setShakeLength(cShakeLength);
    EXPECT_EQ(err, ALC_ERROR_NOT_PERMITTED);
    EXPECT_EQ(sha3_384.getHashSize(), DigestSize);
    EXPECT_NE(sha3_384.getHashSize(), cShakeLength);
}

} // namespace
