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

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string>  ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 64;
// IV array size where every element is 8 bytes
static const Uint8 IvArraySize   = 8;
static const Uint8 IvElementSize = 8;

// clang-format off
static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"} },
    { "Symbols", 
            { "!@#$",
                "8ce82d8a4ee4f12eb603a697b39237df0d58efaab5ae25a44bb01a29e3c8f10b"
                "340d411d6531ce7fadbfcdf4308e91314380e3fc76c45242422bcd488a05db8c"} },
    { "All_Char",
            { "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"} },
    { "All_Num",
            { "123", 
                "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1e"
                "b8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"}}
};

// clang-format on
class Sha512Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha512Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha512            sha512;
    Uint8             hash[DigestSize];
    std::stringstream ss;

    ASSERT_EQ(sha512.update((const Uint8*)plaintext.c_str(), plaintext.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(sha512.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha512.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
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

} // namespace
