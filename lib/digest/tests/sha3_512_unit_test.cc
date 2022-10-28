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

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string> ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;


const alc_digest_info_t DigestInfo = {
    .dt_type = ALC_DIGEST_TYPE_SHA3,
    .dt_len = ALC_DIGEST_LEN_512,
    .dt_mode = {.dm_sha3 = ALC_SHA3_512,},
};

//Digest size in bytes
static const Uint8 DigestSize = 64;

static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"} },
    { "Symbols", 
            { "!@#$",
                "da20368346603040cf20725e385fa2891e802b2dd599707f32aa209f31228161"
                "8c8fe9f21cdab6df1ecaeba1a5662159f18caafd40689dd8c4eaa3b55c83eb8d"} },
    { "All_Char",
            { "abc",
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"} },
    { "All_Num",
            { "123", 
                "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801"
                "e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa"
                "73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"}}
};

class Sha3_512
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha3_512, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha3 sha3_512(DigestInfo);
    Uint8 hash[DigestSize];
    std::stringstream ss;

    ASSERT_EQ(sha3_512.update((const Uint8 *)plaintext.c_str(), plaintext.size()), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_512.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha3_512.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for(Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    
    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha3_512,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha3_512::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha3_512, invalid_input_update_test)
{
    Sha3 sha3_512(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_512.update(nullptr, 0));
}

TEST(Sha3_512, zero_size_update_test)
{
    Sha3 sha3_512(DigestInfo);
    const Uint8 src[DigestSize] = {0};
    EXPECT_EQ(ALC_ERROR_NONE, sha3_512.update(src, 0));
}

TEST(Sha3_512, invalid_output_copy_hash_test)
{
    Sha3 sha3_512(DigestInfo);
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_512.copyHash(nullptr, DigestSize));
}

TEST(Sha3_512, zero_size_hash_copy_test)
{
    Sha3 sha3_512(DigestInfo);
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_512.copyHash(hash, 0));
}

}
