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

#include "digest/sha2_512.hh"
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

static const std::unordered_map<DigestSha512, tuple<alc_digest_len_t, Uint8>>
    DigestSizes = { { DIGEST_SHA_512_224, { ALC_DIGEST_LEN_224, 28 } },
                    { DIGEST_SHA_512_256, { ALC_DIGEST_LEN_256, 32 } },
                    { DIGEST_SHA_512_512, { ALC_DIGEST_LEN_512, 64 } } };
// IV array size where every element is 8 bytes
static const Uint8 IvArraySize   = 8;
static const Uint8 IvElementSize = 8;

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

    for (const auto enum_digest : { DigestSha512::DIGEST_SHA_512_224,
                                    DigestSha512::DIGEST_SHA_512_256,
                                    DigestSha512::DIGEST_SHA_512_512 }) {
        auto digest                           = digests[enum_digest];
        const auto [digest_type, digest_size] = DigestSizes.at(enum_digest);
        Sha512            sha512(digest_type);
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        ASSERT_EQ(
            sha512.update((const Uint8*)plaintext.c_str(), plaintext.size()),
            ALC_ERROR_NONE);
        ASSERT_EQ(sha512.finalize(nullptr, 0), ALC_ERROR_NONE);
        ASSERT_EQ(sha512.copyHash(hash.data(), digest_size), ALC_ERROR_NONE);

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
    [](const testing::TestParamInfo<Sha512Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha512Test, invalid_input_update_test)
{
    Sha512 sha512;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512.update(nullptr, 0));
}

TEST(Sha512Test, zero_size_update_test)
{
    Sha512      sha512;
    const Uint8 src[DigestSize] = { 0 };
    EXPECT_EQ(ALC_ERROR_NONE, sha512.update(src, 0));
}

TEST(Sha512Test, invalid_output_copy_hash_test)
{
    Sha512 sha512;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha512.copyHash(nullptr, DigestSize));
}

TEST(Sha512Test, zero_size_hash_copy_test)
{
    Sha512 sha512;
    Uint8  hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha512.copyHash(hash, 0));
}

TEST(Sha512Test, over_size_hash_copy_test)
{
    Sha512 sha512;
    Uint8  hash[DigestSize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha512.copyHash(hash, DigestSize + 1));
}

TEST(Sha512Test, invalid_iv_test)
{
    Sha512 sha512;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG,
              sha512.setIv(nullptr, IvArraySize * IvElementSize));
}

TEST(Sha512Test, zero_size_iv_test)
{
    Sha512 sha512;
    Uint64 iv[IvArraySize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha512.setIv(iv, 0));
}

TEST(Sha512Test, over_size_iv_test)
{
    Sha512 sha512;
    Uint64 iv[IvArraySize + 1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha512.setIv(iv, sizeof(iv)));
}

TEST(Sha512Test, getInputBlockSizeTest)
{
    Sha512 sha512;
    EXPECT_EQ(sha512.getInputBlockSize() * 8, 1024);
}
TEST(Sha512Test, getHashSizeTest)
{
    Sha512 sha512;
    EXPECT_EQ(sha512.getHashSize() * 8, 512);
}

TEST(Sha512Test, Sha512_224_getInputBlockLenTest)
{
    Sha512 sha512(ALC_DIGEST_LEN_224);
    EXPECT_EQ(sha512.getInputBlockSize() * 8, 1024);
}

TEST(Sha512Test, Sha512_224_getHashSizeTest)
{
    Sha512 sha512(ALC_DIGEST_LEN_224);
    EXPECT_EQ(sha512.getHashSize() * 8, 224);
}

TEST(Sha512Test, Sha512_256_getInputBlockLenTest)
{
    Sha512 sha512(ALC_DIGEST_LEN_256);
    EXPECT_EQ(sha512.getInputBlockSize() * 8, 1024);
}

TEST(Sha512Test, Sha512_256_getHashSizeTest)
{
    Sha512 sha512(ALC_DIGEST_LEN_256);
    EXPECT_EQ(sha512.getHashSize() * 8, 256);
}

} // namespace
