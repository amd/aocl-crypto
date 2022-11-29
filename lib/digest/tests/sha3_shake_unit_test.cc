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

enum DigestShake
{
    DIGEST_SHA3_SHAKE_128 = 0,
    DIGEST_SHA3_SHAKE_256 = 1,
};

// message, digest_size, array of digests
typedef tuple<const string, const Uint64, vector<string>> ParamTuple;
typedef std::map<const string, ParamTuple>                KnownAnswerMap;

alc_digest_info_t DigestInfoShake = {
    ALC_DIGEST_TYPE_SHA3,
    ALC_DIGEST_LEN_CUSTOM,
};

// Digest size in bytes
static const Uint8 DigestSize = 32;

static const KnownAnswerMap message_digest_array = {
    { "Empty", { "", 5, { "7f9c2ba4e8", "46b9dd2b0b" } } },
    { "Symbols",
      { "!@#$", 10, { "fcc24a4a66c42cafcfaa", "a480f72e1ae50f8f4e0e" } } },

    { "All_Char",
      { "abc",
        15,
        { "5881092dd818bf5cf8a3ddb793fbcb",
          "483366601360a8771c6863080cc411" } } },
    { "All_Num",
      { "123",
        20,
        { "d6b9bdbda14c3858c36d5af417fd083bfc8b19b0",
          "de46e887727353da377b63ed4e7b4725d1819442" } } },
    { "Long_Input",
      { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
        25,
        { "28e1d757fc91b7e055d01eabee20a50fda48c6bb12c8feab9a",
          "c1f5adb085c1c3dae1d1740b29c7140416b697c990f2b7aa4a" } } }
};

class Shake : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Shake, digest_generation_test)
{
    const auto [plaintext, digest_size, digests] = GetParam().second;

    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        auto digest                   = digests[enum_digest];
        DigestInfoShake.dt_custom_len = digest_size;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);

        Sha3              sha3_shake(DigestInfoShake);
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        ASSERT_EQ(sha3_shake.update((const Uint8*)plaintext.c_str(),
                                    plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.finalize(nullptr, 0), ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.copyHash(hash.data(), digest_size),
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
    Shake,
    testing::ValuesIn(message_digest_array),
    [](const testing::TestParamInfo<Shake::ParamType>& info) {
        return info.param.first;
    });

TEST(Shake, invalid_input_update_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        DigestInfoShake.dt_custom_len = DigestSize;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);
        Sha3 sha3_shake(DigestInfoShake);
        EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_shake.update(nullptr, 0));
    }
}

TEST(Shake, zero_size_update_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        DigestInfoShake.dt_custom_len = DigestSize;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);
        Sha3        sha3_shake(DigestInfoShake);
        const Uint8 src[DigestSize] = { 0 };
        EXPECT_EQ(ALC_ERROR_NONE, sha3_shake.update(src, 0));
    }
}

TEST(Shake, invalid_output_copy_hash_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        DigestInfoShake.dt_custom_len = DigestSize;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);
        Sha3 sha3_shake(DigestInfoShake);
        EXPECT_EQ(ALC_ERROR_INVALID_ARG,
                  sha3_shake.copyHash(nullptr, DigestSize));
    }
}

TEST(Shake, zero_size_hash_copy_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        DigestInfoShake.dt_custom_len = DigestSize;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);
        DigestInfoShake.dt_custom_len = DigestSize;
        Sha3  sha3_shake(DigestInfoShake);
        Uint8 hash[DigestSize];
        EXPECT_EQ(ALC_ERROR_INVALID_SIZE, sha3_shake.copyHash(hash, 0));
    }
}

TEST(Shake, over_size_hash_copy_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        DigestInfoShake.dt_custom_len = DigestSize;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);
        Sha3  sha3_shake(DigestInfoShake);
        Uint8 hash[DigestSize + 1];
        EXPECT_EQ(ALC_ERROR_INVALID_SIZE,
                  sha3_shake.copyHash(hash, DigestSize + 1));
    }
}

TEST(Shake, digest_correction_with_reset_test)
{
    // taking the last input message to check the digest generation after reset
    const auto [plaintext, digest_size, digests] =
        std::prev(message_digest_array.end())->second;

    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        auto digest                   = digests[enum_digest];
        DigestInfoShake.dt_custom_len = digest_size;
        DigestInfoShake.dt_mode.dm_sha3 =
            (enum_digest == DIGEST_SHA3_SHAKE_128 ? ALC_SHAKE_128
                                                  : ALC_SHAKE_256);

        Sha3              sha3_shake(DigestInfoShake);
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        ASSERT_EQ(sha3_shake.update((const Uint8*)plaintext.c_str(),
                                    plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.finalize(nullptr, 0), ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.copyHash(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        // Resetting the class. Now a new buffer will be used to test if the
        // digest is happening correctly
        sha3_shake.reset();

        ASSERT_EQ(sha3_shake.update((const Uint8*)plaintext.c_str(),
                                    plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.finalize(nullptr, 0), ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake.copyHash(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        ss << std::hex << std::setfill('0');
        for (Uint16 i = 0; i < digest_size; ++i)
            ss << std::setw(2) << static_cast<unsigned>(hash[i]);

        std::string hash_string = ss.str();
        EXPECT_TRUE(hash_string == digest);
    }
}

} // namespace
