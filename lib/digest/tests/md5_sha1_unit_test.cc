/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/digest/md5_sha1.hh"
#include "gtest/gtest.h"
#include <memory>
namespace {

/* Utilities */
Uint8
parseHexToNum(const unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

std::vector<Uint8>
parseHexStrToBin(const std::string in)
{
    std::vector<Uint8> vector;
    int                len = in.size();
    int                ind = 0;

    for (int i = 0; i < len; i += 2) {
        Uint8 val =

            parseHexToNum(in.at(ind)) << 4 | parseHexToNum(in.at(ind + 1));
        vector.push_back(val);
        ind += 2;
    }
    return vector;
}

using namespace std;
using namespace alcp::digest;

typedef tuple<const string, string>        ParamTuple;
typedef std::map<const string, ParamTuple> KnownAnswerMap;
static const KnownAnswerMap                message_digest = {
    { "Case1",
                     { "ffff",
                       "ab2a0d28de6b77ffdd6c72afead099aba19f987b885f5a96069f4bc7f12b9e84ceba7d"
                                      "fa" } }
};

class MD5_Sha1Test
    : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(MD5_Sha1Test, digest_generation_test)
{
    const auto [plaintext, digest]       = GetParam().second;
    auto                     digest_size = ALC_DIGEST_LEN_288 / 8;
    std::unique_ptr<IDigest> digest_obj  = std::make_unique<Md5_Sha1>();
    ASSERT_NE(nullptr, digest_obj);
    vector<Uint8>     hash(digest_size);
    std::stringstream ss;

    digest_obj->init();
    auto plaintext_hex = parseHexStrToBin(plaintext);
    ASSERT_EQ(digest_obj->update(&plaintext_hex[0], plaintext_hex.size()),
              ALC_ERROR_NONE);
    ASSERT_EQ(digest_obj->finalize(hash.data(), digest_size), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    for (Uint16 i = 0; i < digest_size; ++i)
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);

    std::string hash_string = ss.str();

    EXPECT_EQ(hash_string, digest);
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswer,
    MD5_Sha1Test,
    testing::ValuesIn(message_digest),
    [](const testing::TestParamInfo<MD5_Sha1Test::ParamType>& info)
        -> const std::string { return info.param.first; });

} // namespace