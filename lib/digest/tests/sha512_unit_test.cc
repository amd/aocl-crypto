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

#include "alcp/digest/sha512.hh"
#include "gtest/gtest.h"
#include <unordered_map>

namespace {
using namespace std;
using namespace alcp::digest;

enum DigestSha512
{
    DIGEST_SHA_512_224 = 0,
    DIGEST_SHA_512_256 = 1,
    DIGEST_SHA_512_512 = 2
};

typedef tuple<const string, const vector<string>> ParamTuple;
typedef std::map<const string, ParamTuple>        KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 64;
// Input Block length in bytes
static const unsigned int InputBlockLen = 1024;

static const std::unordered_map<DigestSha512, tuple<alc_digest_len_t, Uint8>>
    DigestSizes = { { DIGEST_SHA_512_224, { ALC_DIGEST_LEN_224, 28 } },
                    { DIGEST_SHA_512_256, { ALC_DIGEST_LEN_256, 32 } },
                    { DIGEST_SHA_512_512, { ALC_DIGEST_LEN_512, 64 } } };

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                {"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"}} },
    { "Symbols", 
            { "!@#$",
                {"77ba6922593e7b089af4b662b59ada4ac52b6a9e3b63def5748061a7",
                "ca74ee9de71f434fa85198d84271d7582dc21cdc74aae127d886e9f54101600f",
                "8ce82d8a4ee4f12eb603a697b39237df0d58efaab5ae25a44bb01a29e3c8f10b"
                "340d411d6531ce7fadbfcdf4308e91314380e3fc76c45242422bcd488a05db8c"}} },
    { "All_Char",
            { "abc",
                {"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"}} },
    { "All_Num",
            { "123", 
                {"10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a",
                "f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10",
                "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1e"
                "b8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"}} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                {"23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
                "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"}} }
};

// clang-format on
class Sha512Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha512Test, digest_generation_test)
{
    const auto [plaintext, digests] = GetParam().second;

    for (const auto& enum_digest : { DigestSha512::DIGEST_SHA_512_224,
                                     DigestSha512::DIGEST_SHA_512_256,
                                     DigestSha512::DIGEST_SHA_512_512 }) {
        const auto& digest                    = digests[enum_digest];
        const auto [digest_type, digest_size] = DigestSizes.at(enum_digest);
        std::unique_ptr<IDigest> digest_obj; // Change to unique_ptr
        switch (digest_type) {
            case ALC_DIGEST_LEN_224:
                digest_obj =
                    std::make_unique<Sha512_224>(); // Change to unique_ptr
                break;
            case ALC_DIGEST_LEN_256:
                digest_obj =
                    std::make_unique<Sha512_256>(); // Change to unique_ptr
                break;
            case ALC_DIGEST_LEN_512:
                digest_obj = std::make_unique<Sha512>(); // Change to unique_ptr
                break;
            default:
                FAIL() << "Digest does not exist / is not implemented!";
                break;
        }
        ASSERT_NE(nullptr, digest_obj.get());
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        digest_obj->init();
        ASSERT_EQ(digest_obj->update((const Uint8*)plaintext.c_str(),
                                     plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(digest_obj->finalize(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        ss << std::hex << std::setfill('0');
        for (Uint16 i = 0; i < digest_size; ++i)
            ss << std::setw(2) << static_cast<unsigned>(hash[i]);

        std::string hash_string = ss.str();
        EXPECT_TRUE(hash_string == digest);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha512Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha512Test::ParamType>& info)
        -> const std::string { return info.param.first; });

TEST(Sha512Test, invalid_input_update_test)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512->update(nullptr, 0));
}

TEST(Sha512Test, zero_size_update_test)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha512->update(src, 0));
}

TEST(Sha512Test, invalid_output_copy_hash_test)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512->finalize(nullptr, DigestSize));
}

TEST(Sha512Test, zero_size_hash_copy_test)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512->finalize(hash, 0));
}

TEST(Sha512Test, over_size_hash_copy_test)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    Uint8 hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512->finalize(hash, DigestSize + 1));
}

TEST(Sha512Test, getInputBlockSizeTest)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getInputBlockSize() * 8, InputBlockLen);
}
TEST(Sha512Test, getHashSizeTest)
{
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getHashSize() * 8, 512U);
}

TEST(Sha512Test, Sha512_224_getInputBlockLenTest)
{
    std::unique_ptr<Sha512_224> sha512 =
        std::make_unique<Sha512_224>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getInputBlockSize() * 8, InputBlockLen);
}

TEST(Sha512Test, Sha512_224_getHashSizeTest)
{
    std::unique_ptr<Sha512_224> sha512 =
        std::make_unique<Sha512_224>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getHashSize() * 8, 224U);
}

TEST(Sha512Test, Sha512_256_getInputBlockLenTest)
{
    std::unique_ptr<Sha512_256> sha512 =
        std::make_unique<Sha512_256>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getInputBlockSize() * 8, InputBlockLen);
}

TEST(Sha512Test, Sha512_256_getHashSizeTest)
{
    std::unique_ptr<Sha512_256> sha512 =
        std::make_unique<Sha512_256>(); // Change to unique_ptr
    EXPECT_EQ(sha512->getHashSize() * 8, 256U);
}

TEST(Sha512Test, object_copy_test)
{
    string                  plaintext("1111");
    std::unique_ptr<Sha512> sha512 =
        std::make_unique<Sha512>(); // Change to unique_ptr
    Uint8             hash[DigestSize], hash_dup[DigestSize];
    std::stringstream ss, ss_dup;

    sha512->init();
    ASSERT_EQ(sha512->update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);

    std::unique_ptr<Sha512> sha512_dup =
        std::make_unique<Sha512>(*sha512); // Change to unique_ptr

    ASSERT_EQ(sha512->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(sha512_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

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
