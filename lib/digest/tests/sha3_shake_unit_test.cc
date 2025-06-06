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

enum DigestShake
{
    DIGEST_SHA3_SHAKE_128 = 0,
    DIGEST_SHA3_SHAKE_256 = 1,
};

// message, digest_size, array of digests
typedef tuple<const string, const Uint64, vector<string>> ParamTuple;
typedef std::map<const string, ParamTuple>                KnownAnswerMap;

// Digest size in bytes
static const Uint8 DigestSize = 32;
// Shake 128 Input Block size in bytes
static constexpr Uint8 Shake128_InputBlockSize = 168;
// Shake 256 Input Block size in bytes
static constexpr Uint8 Shake256_InputBlockSize = 136;

// clang-format off
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

// clang-format on
class Shake : public testing::TestWithParam<std::pair<const string, ParamTuple>>
{};

TEST_P(Shake, digest_generation_test)
{
    const auto [plaintext, digest_size, digests] = GetParam().second;

    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        const auto& digest = digests[enum_digest];

        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();

        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        ASSERT_EQ(sha3_shake->update((const Uint8*)plaintext.c_str(),
                                     plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake->finalize(hash.data(), digest_size),
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
    [](const testing::TestParamInfo<Shake::ParamType>& info)
        -> const std::string { return info.param.first; });

TEST(Shake, invalid_input_update_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_shake->update(nullptr, 0));
    }
}

TEST(Shake, zero_size_update_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        const Uint8 src[DigestSize] = { 0 };
        EXPECT_EQ(ALC_ERROR_NONE, sha3_shake->update(src, 0));
    }
}

TEST(Shake, invalid_output_copy_hash_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        EXPECT_EQ(ALC_ERROR_INVALID_ARG,
                  sha3_shake->finalize(nullptr, DigestSize));
    }
}

TEST(Shake, zero_size_hash_copy_test)
{
    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {

        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        Uint8 hash[DigestSize];
        EXPECT_EQ(ALC_ERROR_INVALID_ARG, sha3_shake->finalize(hash, 0));
    }
}

TEST(Shake, digest_correction_with_reset_test)
{
    // taking the last input message to check the digest generation after reset
    const auto [plaintext, digest_size, digests] =
        std::prev(message_digest_array.end())->second;

    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        const auto& digest = digests[enum_digest];

        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        ASSERT_EQ(sha3_shake->update((const Uint8*)plaintext.c_str(),
                                     plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake->finalize(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        // Resetting the class. Now a new buffer will be used to test if the
        // digest is happening correctly
        sha3_shake->init();

        ASSERT_EQ(sha3_shake->update((const Uint8*)plaintext.c_str(),
                                     plaintext.size()),
                  ALC_ERROR_NONE);
        ASSERT_EQ(sha3_shake->finalize(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        ss << std::hex << std::setfill('0');
        for (Uint16 i = 0; i < digest_size; ++i)
            ss << std::setw(2) << static_cast<unsigned>(hash[i]);

        std::string hash_string = ss.str();
        EXPECT_TRUE(hash_string == digest);
    }
}

TEST(Shake, Shake128_getInputBlockLenTest)
{
    std::unique_ptr<Shake128> sha3_shake_ptr(new Shake128);
    Shake128*                 sha3_shake = sha3_shake_ptr.get();
    sha3_shake->init();
    EXPECT_EQ(sha3_shake->getInputBlockSize(), Shake128_InputBlockSize);
}

TEST(Shake, Shake256_getInputBlockLenTest)
{
    std::unique_ptr<Shake256> sha3_shake_ptr(new Shake256);
    Shake256*                 sha3_shake = sha3_shake_ptr.get();
    sha3_shake->init();
    EXPECT_EQ(sha3_shake->getInputBlockSize(), Shake256_InputBlockSize);
}

TEST(Shake, Shake128_getHashSizeTest)
{
    std::unique_ptr<Shake128> sha3_shake_ptr(new Shake128);
    Shake128*                 sha3_shake = sha3_shake_ptr.get();
    sha3_shake->init();
    EXPECT_EQ(sha3_shake->getHashSize(), ALC_DIGEST_LEN_128 / 8);
}
TEST(Shake, Shake256_getHashSizeTest)
{
    std::unique_ptr<Shake256> sha3_shake_ptr(new Shake256);
    Shake256*                 sha3_shake = sha3_shake_ptr.get();
    sha3_shake->init();
    EXPECT_EQ(sha3_shake->getHashSize(), ALC_DIGEST_LEN_256 / 8);
}

TEST(Sha3_512_Test, object_copy_test)
{
    string                    plaintext("1111");
    std::unique_ptr<Shake256> shake256_ptr(new Shake256);
    Shake256*                 shake256 = shake256_ptr.get();
    Uint8                     hash[DigestSize], hash_dup[DigestSize];
    std::stringstream         ss, ss_dup;

    shake256->init();
    ASSERT_EQ(
        shake256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);

    std::unique_ptr<Shake256> shake256_dup_ptr(new Shake256(*shake256));
    Shake256*                 shake256_dup = shake256_dup_ptr.get();

    ASSERT_EQ(shake256->finalize(hash, DigestSize), ALC_ERROR_NONE);
    ASSERT_EQ(shake256_dup->finalize(hash_dup, DigestSize), ALC_ERROR_NONE);

    ss << std::hex << std::setfill('0');
    ss_dup << std::hex << std::setfill('0');
    ;
    for (Uint16 i = 0; i < DigestSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
        ss_dup << std::setw(2) << static_cast<unsigned>(hash_dup[i]);
    }
    std::string hash_string = ss.str(), hash_string_dup = ss_dup.str();
    EXPECT_TRUE(hash_string == hash_string_dup);
}

TEST(Sha3_512_Test, sqeeze_test)
{
    string                    plaintext("1111");
    std::unique_ptr<Shake256> shake256_ptr(new Shake256);
    Shake256*                 shake256 = shake256_ptr.get();
    Uint8                     hash[DigestSize], hash_dup[DigestSize];
    std::stringstream         ss, ss_dup;

    shake256->init();
    ASSERT_EQ(
        shake256->update((const Uint8*)plaintext.c_str(), plaintext.size()),
        ALC_ERROR_NONE);

    std::unique_ptr<Shake256> shake256_dup_ptr(new Shake256(*shake256));
    Shake256*                 shake256_dup = shake256_dup_ptr.get();

    ASSERT_EQ(shake256->finalize(hash, DigestSize), ALC_ERROR_NONE);
    Uint8* hash_dup_p = hash_dup;
    for (Uint16 i = 0; i < DigestSize; i++) {
        ASSERT_EQ(shake256_dup->shakeSqueeze(hash_dup_p, 1), ALC_ERROR_NONE);
        ++hash_dup_p;
    }
    ss << std::hex << std::setfill('0');
    ss_dup << std::hex << std::setfill('0');

    for (Uint16 i = 0; i < DigestSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
        ss_dup << std::setw(2) << static_cast<unsigned>(hash_dup[i]);
    }
    std::string hash_string = ss.str(), hash_string_dup = ss_dup.str();
    EXPECT_TRUE(hash_string == hash_string_dup);
}

TEST_P(Shake, setShakeLength_digest_generation_test)
{
    const auto [plaintext, digest_size, digests] = GetParam().second;

    for (const auto enum_digest : { DigestShake::DIGEST_SHA3_SHAKE_128,
                                    DigestShake::DIGEST_SHA3_SHAKE_256 }) {
        const auto& digest = digests[enum_digest];

        std::unique_ptr<IDigest> sha3_shake_ptr(
            (enum_digest == DIGEST_SHA3_SHAKE_128
                 ? static_cast<IDigest*>(new Shake128)
                 : static_cast<IDigest*>(new Shake256)));

        IDigest* sha3_shake = sha3_shake_ptr.get();
        sha3_shake->init();
        vector<Uint8>     hash(digest_size);
        std::stringstream ss;

        sha3_shake->init();
        ASSERT_EQ(sha3_shake->update((const Uint8*)plaintext.c_str(),
                                     plaintext.size()),
                  ALC_ERROR_NONE);

        ASSERT_EQ(sha3_shake->finalize(hash.data(), digest_size),
                  ALC_ERROR_NONE);

        ss << std::hex << std::setfill('0');
        for (Uint16 i = 0; i < digest_size; ++i)
            ss << std::setw(2) << static_cast<unsigned>(hash[i]);

        std::string hash_string = ss.str();
        EXPECT_TRUE(hash_string == digest);
    }
}

} // namespace
