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


#include "digest/sha2.hh"
#include "gtest/gtest.h"

namespace {
using namespace std;
using namespace alcp::digest;

typedef tuple<const string, const string> ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;

//Digest size in bytes
static const Uint8 DigestSize = 28;

static const KnownAnswerMap message_digest = {
    { "Empty",   
            { "", 
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"} },
    { "Symbols", 
            { "!@#$",
                "065059bd65226ad9b78a59d6726064fdc101fda1b8baa695d42f55b1"} },
    { "All_Char",
            { "abc",
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"} },
    { "All_Num",
            { "123", 
                "78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"} },
    { "Long_Input",
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"}}
};

class Sha224Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Sha224Test, digest_generation_test)
{
    const auto [plaintext, digest] = GetParam().second;
    Sha224 sha224;
    Uint8 hash[DigestSize];
    std::stringstream ss;

    ASSERT_EQ(sha224.update((const Uint8 *)plaintext.c_str(), plaintext.size()), ALC_ERROR_NONE);
    ASSERT_EQ(sha224.finalize(nullptr, 0), ALC_ERROR_NONE);
    ASSERT_EQ(sha224.copyHash(hash, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for(Uint16 i = 0; i < DigestSize; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    
    std::string hash_string = ss.str();
    EXPECT_TRUE(hash_string == digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    Sha224Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<Sha224Test::ParamType>& info) {
        return info.param.first;
    });

TEST(Sha224Test, invalid_input_update_test)
{
    Sha224 sha224;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224.update(nullptr, 0));
}

TEST(Sha224Test, zero_size_update_test)
{
    Sha224 sha224;
    const Uint8 src[DigestSize] = {0};
    EXPECT_EQ(ALC_ERROR_NONE, sha224.update(src, 0));
}

TEST(Sha224Test, invalid_output_copy_hash_test)
{
    Sha224 sha224;
    EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha224.copyHash(nullptr, DigestSize));
}

TEST(Sha224Test, zero_size_hash_copy_test)
{
    Sha224 sha224;
    Uint8 hash[DigestSize];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha224.copyHash(hash, 0));
}

TEST(Sha224Test, over_size_hash_copy_test)
{
    Sha224 sha224;
    Uint8 hash[DigestSize+1];
    EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha224.copyHash(hash, DigestSize+1));
}

TEST(Sha224Test, call_finalize_twice_test)
{
    Sha224 sha224;
    // calling finalize multiple times shoud not result in error
    EXPECT_EQ(ALC_ERROR_NONE, sha224.finalize(nullptr, 0));
    EXPECT_EQ(ALC_ERROR_NONE, sha224.finalize(nullptr, 0));
}

}
