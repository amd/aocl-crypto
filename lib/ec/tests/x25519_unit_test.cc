/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

#include <gtest/gtest.h>
#include <algorithm>
#include <iostream>
#include <string.h>

#include "alcp/base.hh"
#include "alcp/ec/ecdh.hh"
#include "alcp/types.hh"

#include "alcp/error.h"
#include "alcp/utils/benchmark.hh"

#define MAX_SIZE_KEY_DATA 32U

namespace {

using namespace std;
using namespace alcp;

// clang-format off
typedef std::tuple<std::vector<Uint8>, // peer1_private_key
                   std::vector<Uint8>, // peer2_private_key
                   std::vector<Uint8>> // expected_shared_key
            param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;


known_answer_map_t KATDataset{
    {
      "TEST_1",
      {
        {0x80, 0x5b, 0x30, 0x20, 0x25, 0x4a, 0x70, 0x2c, 0xad, 0xa9, 0x8d,
            0x7d, 0x47, 0xf8, 0x1b, 0x20, 0x89, 0xd2, 0xf9, 0x14, 0xac, 0x92,
            0x27, 0xf2, 0x10, 0x7e, 0xdb, 0x21, 0xbd, 0x73, 0x73, 0x5d},
        {0xf8, 0x84, 0x19, 0x69, 0x79, 0x13, 0x0d, 0xbd, 0xb1, 0x76, 0xd7,
            0x0e, 0x7e, 0x0f, 0xb6, 0xf4, 0x8c, 0x4a, 0x8c, 0x5f, 0xd8, 0x15,
            0x09, 0x0a, 0x71, 0x78, 0x74, 0x92, 0x0f, 0x85, 0xc8, 0x43},
        {0x19, 0x71, 0x26, 0x12, 0x74, 0xb5, 0xb1, 0xce, 0x77, 0xd0, 0x79,
            0x24, 0xb6, 0x0a, 0x5c, 0x72, 0x0c, 0xa6, 0x56, 0xc0, 0x11, 0xeb,
            0x43, 0x11, 0x94, 0x3b, 0x01, 0x45, 0xca, 0x19, 0xfe, 0x09},
      }
    }

};
// clang-format on

using namespace ec;
class x25519Test
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8> m_peer1_private_key, m_peer2_private_key,
        m_expected_shared_key;
    std::string m_test_name;
    alc_error_t m_err;

    X25519* m_px25519obj1        = nullptr;
    X25519* m_px25519obj2        = nullptr;
    Uint8   m_publicKeyData1[32] = {};
    Uint8   m_publicKeyData2[32] = {};

    void SetUp() override
    {
        // Tuple order
        // {peer1_private_key, peer2_private_key,expected_shared_key}
        const auto& params                = GetParam();
        const auto& [peer1_private_key,
                     peer2_private_key,
                     expected_shared_key] = params.second;
        const auto& test_name             = params.first;

        // Copy Values to class variables
        m_peer1_private_key   = peer1_private_key;
        m_peer2_private_key   = peer2_private_key;
        m_expected_shared_key = expected_shared_key;

        m_test_name = test_name;

        m_px25519obj1 = new X25519;
        m_px25519obj2 = new X25519;
    }

    void TearDown() override
    {
        delete m_px25519obj1;
        delete m_px25519obj2;
    }
};

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    x25519Test,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<x25519Test::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST_P(x25519Test, PublicAndSharedKeyTest)
{
    alc_error_t ret = ALC_ERROR_NONE;

    /* Peer 1 */
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));
    m_px25519obj1->generatePublicKey(m_publicKeyData1,
                                     sizeof(m_publicKeyData1),
                                     pPrivKey_input_data1,
                                     m_peer1_private_key.size());

    /* Peer 2 */
    const Uint8* pPrivKey_input_data2 = &(m_peer2_private_key.at(0));
    m_px25519obj2->generatePublicKey(m_publicKeyData2,
                                     sizeof(m_publicKeyData2),
                                     pPrivKey_input_data2,
                                     m_peer2_private_key.size());

    // compute shared secret key of both peers
    Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength1;
    m_px25519obj1->computeSecretKey(pSecret_key1,
                                    MAX_SIZE_KEY_DATA,
                                    m_publicKeyData2,
                                    sizeof(m_publicKeyData2),
                                    &keyLength1);

    Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength2;
    m_px25519obj2->computeSecretKey(pSecret_key2,
                                    MAX_SIZE_KEY_DATA,
                                    m_publicKeyData1,
                                    sizeof(m_publicKeyData1),
                                    &keyLength2);

    ret = memcmp(pSecret_key1, pSecret_key2, keyLength1);
    EXPECT_EQ(ret, 0U);
    ret = memcmp(&(m_expected_shared_key.at(0)), pSecret_key2, keyLength1);
    EXPECT_EQ(ret, 0U);

    delete[] pSecret_key1;
    delete[] pSecret_key2;
}

TEST_P(x25519Test, PerformanceTest)
{
    /* Peer 1 */
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START
        m_px25519obj1->generatePublicKey(m_publicKeyData1,
                                         sizeof(m_publicKeyData1),
                                         pPrivKey_input_data1,
                                         m_peer1_private_key.size());

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf("\n  %5d publickeys generated per second", k);
            break;
        }
    }

    Uint8* pSecret_key = new Uint8[MAX_SIZE_KEY_DATA];
    totalTimeElapsed   = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START

        Uint64 keyLength;
        m_px25519obj1->computeSecretKey(pSecret_key,
                                        MAX_SIZE_KEY_DATA,
                                        m_publicKeyData1,
                                        sizeof(m_publicKeyData1),
                                        &keyLength);
        ALCP_CRYPT_GET_TIME(0, "key generation time")

        if (totalTimeElapsed > 1) {
            printf("\n\n  %5d secretKey  generated per second", k);
            break;
        }
    }

    delete[] pSecret_key;
}

TEST_P(x25519Test, GetKeySizeTest)
{
    EXPECT_EQ(m_px25519obj1->getKeySize(), MAX_SIZE_KEY_DATA);
}

TEST_P(x25519Test, ValidatePublicKeyTest)
{
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));

    m_px25519obj1->generatePublicKey(m_publicKeyData1,
                                     sizeof(m_publicKeyData1),
                                     pPrivKey_input_data1,
                                     m_peer1_private_key.size());
    EXPECT_EQ(
        m_px25519obj1->validatePublicKey(m_publicKeyData1, MAX_SIZE_KEY_DATA),
        StatusOk());
}

// Negative length tests: buffers sized to claimed len so guard regression
// triggers ASan, not just a failed EXPECT.
TEST_P(x25519Test, SetPrivateKeyLengthTest)
{
    const Uint64 cKeySize = m_px25519obj1->getKeySize();

    std::vector<Uint8> key(cKeySize + 1, 0xab);

    EXPECT_NE(m_px25519obj1->setPrivateKey(&key[0], cKeySize - 1).code(),
              ErrorCode::eOk);
    EXPECT_NE(m_px25519obj1->setPrivateKey(&key[0], cKeySize + 1).code(),
              ErrorCode::eOk);
    EXPECT_NE(m_px25519obj1->setPrivateKey(&key[0], 0).code(), ErrorCode::eOk);

    EXPECT_EQ(m_px25519obj1->setPrivateKey(&key[0], cKeySize), StatusOk());
}

TEST_P(x25519Test, GeneratePublicKeyLengthTest)
{
    const Uint64 cKeySize = m_px25519obj1->getKeySize();

    std::vector<Uint8> priv_key(cKeySize + 1, 0xab);
    std::vector<Uint8> pub_key(cKeySize + 1);

    EXPECT_NE(m_px25519obj1
                  ->generatePublicKey(
                      &pub_key[0], cKeySize, &priv_key[0], cKeySize - 1)
                  .code(),
              ErrorCode::eOk);
    EXPECT_NE(m_px25519obj1
                  ->generatePublicKey(
                      &pub_key[0], cKeySize, &priv_key[0], cKeySize + 1)
                  .code(),
              ErrorCode::eOk);
    EXPECT_NE(
        m_px25519obj1->generatePublicKey(&pub_key[0], cKeySize, &priv_key[0], 0)
            .code(),
        ErrorCode::eOk);

    EXPECT_NE(m_px25519obj1
                  ->generatePublicKey(
                      &pub_key[0], cKeySize - 1, &priv_key[0], cKeySize)
                  .code(),
              ErrorCode::eOk);
    EXPECT_EQ(m_px25519obj1->generatePublicKey(
                  &pub_key[0], cKeySize, &priv_key[0], cKeySize),
              StatusOk());
    EXPECT_EQ(m_px25519obj1->generatePublicKey(
                  &pub_key[0], cKeySize + 1, &priv_key[0], cKeySize),
              StatusOk());
}

TEST_P(x25519Test, ComputeSecretKeyLengthTest)
{
    const Uint64 cKeySize    = m_px25519obj1->getKeySize();
    const Uint64 cPubKeySize = m_px25519obj1->getPublicKeySize();

    m_px25519obj1->generatePublicKey(m_publicKeyData1,
                                     sizeof(m_publicKeyData1),
                                     &(m_peer1_private_key.at(0)),
                                     m_peer1_private_key.size());
    m_px25519obj2->generatePublicKey(m_publicKeyData2,
                                     sizeof(m_publicKeyData2),
                                     &(m_peer2_private_key.at(0)),
                                     m_peer2_private_key.size());

    std::vector<Uint8> secret_key(cKeySize + 1);
    std::vector<Uint8> pub_key(m_publicKeyData2,
                               m_publicKeyData2 + sizeof(m_publicKeyData2));
    pub_key.reserve(sizeof(m_publicKeyData2) + 1);
    pub_key.push_back(0xab);

    Uint64 keyLength = 0;

    EXPECT_NE(m_px25519obj1
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize,
                                     &pub_key[0],
                                     cPubKeySize - 1,
                                     &keyLength)
                  .code(),
              ErrorCode::eOk);
    EXPECT_NE(m_px25519obj1
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize,
                                     &pub_key[0],
                                     cPubKeySize + 1,
                                     &keyLength)
                  .code(),
              ErrorCode::eOk);
    EXPECT_NE(m_px25519obj1
                  ->computeSecretKey(
                      &secret_key[0], cKeySize, &pub_key[0], 0, &keyLength)
                  .code(),
              ErrorCode::eOk);

    EXPECT_NE(m_px25519obj1
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize - 1,
                                     &pub_key[0],
                                     cPubKeySize,
                                     &keyLength)
                  .code(),
              ErrorCode::eOk);

    EXPECT_EQ(keyLength, 0U);

    EXPECT_EQ(
        m_px25519obj1->computeSecretKey(
            &secret_key[0], cKeySize + 1, &pub_key[0], cPubKeySize, &keyLength),
        StatusOk());
    EXPECT_EQ(keyLength, cKeySize);
}

TEST_P(x25519Test, SecretKeyRefusedWithoutPrivateKey)
{
    const std::vector<Uint8> cPeerPublicKey(MAX_SIZE_KEY_DATA, 0xab);

    std::vector<Uint8> secret_key(MAX_SIZE_KEY_DATA, 0xa5);
    const auto         untouched_secret = secret_key;
    Uint64             keyLength = 0;

    EXPECT_EQ(m_px25519obj1
                  ->computeSecretKey(&secret_key[0],
                                     secret_key.size(),
                                     &cPeerPublicKey[0],
                                     cPeerPublicKey.size(),
                                     &keyLength)
                  .code(),
              ErrorCode::eInvalidArgument);
    EXPECT_EQ(keyLength, 0U);
    EXPECT_EQ(secret_key, untouched_secret);
}

TEST_P(x25519Test, SecretKeyRefusedAfterReset)
{
    ASSERT_EQ(m_px25519obj1->setPrivateKey(&(m_peer1_private_key.at(0)),
                                           m_peer1_private_key.size()),
              StatusOk());
    ASSERT_EQ(m_px25519obj2->generatePublicKey(
                  m_publicKeyData2,
                  sizeof(m_publicKeyData2),
                  &(m_peer2_private_key.at(0)),
                  m_peer2_private_key.size()),
              StatusOk());

    const auto* object_begin = reinterpret_cast<const Uint8*>(m_px25519obj1);
    const auto* object_end   = object_begin + sizeof(*m_px25519obj1);
    const auto* key_pos      = std::search(object_begin,
                                      object_end,
                                      m_peer1_private_key.begin(),
                                      m_peer1_private_key.end());
    ASSERT_NE(key_pos, object_end);
    const size_t key_offset = static_cast<size_t>(key_pos - object_begin);

    m_px25519obj1->reset();

    EXPECT_TRUE(std::all_of(object_begin + key_offset,
                            object_begin + key_offset
                                + m_peer1_private_key.size(),
                            [](Uint8 byte) { return byte == 0; }));

    std::vector<Uint8> secret_key(MAX_SIZE_KEY_DATA, 0xa5);
    const auto         untouched_secret = secret_key;
    Uint64             keyLength = 0;

    EXPECT_EQ(m_px25519obj1
                  ->computeSecretKey(&secret_key[0],
                                     secret_key.size(),
                                     m_publicKeyData2,
                                     sizeof(m_publicKeyData2),
                                     &keyLength)
                  .code(),
              ErrorCode::eInvalidArgument);
    EXPECT_EQ(keyLength, 0U);
    EXPECT_EQ(secret_key, untouched_secret);
}

TEST_P(x25519Test, ResetAllowsDifferentPrivateKey)
{
    ASSERT_EQ(m_px25519obj1->setPrivateKey(&(m_peer1_private_key.at(0)),
                                           m_peer1_private_key.size()),
              StatusOk());
    ASSERT_EQ(m_px25519obj2->generatePublicKey(
                  m_publicKeyData2,
                  sizeof(m_publicKeyData2),
                  &(m_peer2_private_key.at(0)),
                  m_peer2_private_key.size()),
              StatusOk());

    std::vector<Uint8> first_secret(MAX_SIZE_KEY_DATA);
    Uint64             first_length = 0;
    ASSERT_EQ(m_px25519obj1->computeSecretKey(&first_secret[0],
                                              first_secret.size(),
                                              m_publicKeyData2,
                                              sizeof(m_publicKeyData2),
                                              &first_length),
              StatusOk());

    m_px25519obj1->reset();

    std::vector<Uint8> second_private_key = m_peer1_private_key;
    second_private_key.front() ^= 8;
    ASSERT_EQ(m_px25519obj1->setPrivateKey(&second_private_key[0],
                                           second_private_key.size()),
              StatusOk());

    std::vector<Uint8> second_secret(MAX_SIZE_KEY_DATA);
    Uint64             second_length = 0;
    ASSERT_EQ(m_px25519obj1->computeSecretKey(&second_secret[0],
                                              second_secret.size(),
                                              m_publicKeyData2,
                                              sizeof(m_publicKeyData2),
                                              &second_length),
              StatusOk());

    EXPECT_EQ(first_length, MAX_SIZE_KEY_DATA);
    EXPECT_EQ(second_length, MAX_SIZE_KEY_DATA);
    EXPECT_NE(second_secret, first_secret);
}

TEST_P(x25519Test, InvalidPublicKeyTest)
{
    Status status = m_px25519obj1->validatePublicKey(m_publicKeyData1,
                                                     MAX_SIZE_KEY_DATA - 1);
    EXPECT_NE(status.code(), ErrorCode::eOk);

    const Uint8 all_zero[MAX_SIZE_KEY_DATA] = { 0 };
    status = m_px25519obj1->validatePublicKey(all_zero, MAX_SIZE_KEY_DATA);
    EXPECT_NE(status.code(), ErrorCode::eOk);
}

} // namespace
