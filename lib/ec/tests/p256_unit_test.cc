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
#include "alcp/error.h"
#include "alcp/types.hh"

typedef std::tuple<std::vector<Uint8>, // peer1_private_key
                   std::vector<Uint8>, // peer2_public_key
                   std::vector<Uint8>> // expected_shared_key
                                                 param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

using alcp::ec::P256;

// clang-format off
known_answer_map_t KATDataset{ 
    { "TEST_1",
        {
            { // Peer 1 Private Key
              0x7d,0x7d,0xc5,0xf7,0x1e,0xb2,0x9d,0xda,
              0xf8,0x0d,0x62,0x14,0x63,0x2e,0xea,0xe0,
              0x3d,0x90,0x58,0xaf,0x1f,0xb6,0xd2,0x2e,
              0xd8,0x0b,0xad,0xb6,0x2b,0xc1,0xa5,0x34 }, 
            { // Peer 2 Public Key
              // affine(X,Y) 32 bytes each
              // X
              0x70,0x0c,0x48,0xf7,0x7f,0x56,0x58,0x4c,
              0x5c,0xc6,0x32,0xca,0x65,0x64,0x0d,0xb9,
              0x1b,0x6b,0xac,0xce,0x3a,0x4d,0xf6,0xb4,
              0x2c,0xe7,0xcc,0x83,0x88,0x33,0xd2,0x87,
              // Y
              0xdb,0x71,0xe5,0x09,0xe3,0xfd,0x9b,0x06,
              0x0d,0xdb,0x20,0xba,0x5c,0x51,0xdc,0xc5,
              0x94,0x8d,0x46,0xfb,0xf6,0x40,0xdf,0xe0,
              0x44,0x17,0x82,0xca,0xb8,0x5f,0xa4,0xac }, 
            { // Shared Secret Key
              0x46,0xfc,0x62,0x10,0x64,0x20,0xff,0x01,
              0x2e,0x54,0xa4,0x34,0xfb,0xdd,0x2d,0x25,
              0xcc,0xc5,0x85,0x20,0x60,0x56,0x1e,0x68,
              0x04,0x0d,0xd7,0x77,0x89,0x97,0xbd,0x7b }, 
        } 
    }
};
// clang-format on

class p256Test
    : public ::testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8> m_peer1_private_key;
    std::vector<Uint8> m_peer2_public_key;
    std::vector<Uint8> m_expected_shared_key;
    std::string        m_test_name;
    alc_error_t        m_err;

    P256* m_p256obj            = nullptr;
    Uint8 m_publicKeyData1[32] = {};

    void SetUp() override
    {
        // Tuple order
        // {peer1_private_key, peer2_private_key,expected_shared_key}
        const auto& params = GetParam();
        const auto& [peer1_private_key, peer2_public_key, expected_shared_key] =
            params.second;
        const auto& test_name = params.first;

        // Copy Values to class variables
        m_peer1_private_key   = peer1_private_key;
        m_peer2_public_key    = peer2_public_key;
        m_expected_shared_key = expected_shared_key;

        m_test_name = test_name;

        m_p256obj = new P256;
    }

    void TearDown() override { delete m_p256obj; }
};

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    p256Test,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<p256Test::ParamType>& tpInfo)
        -> const std::string { return tpInfo.param.first; });

TEST_P(p256Test, SecretKeyGen)
{
    m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                             m_peer1_private_key.size());

    std::vector<Uint8> pSecret_key(m_p256obj->getKeySize());
    Uint64             keyLength = 0;
    EXPECT_EQ(m_p256obj->computeSecretKey(&pSecret_key[0],
                                          pSecret_key.size(),
                                          &m_peer2_public_key[0],
                                          m_peer2_public_key.size(),
                                          &keyLength),
              alcp::StatusOk());

    EXPECT_EQ(keyLength, m_p256obj->getKeySize());
    EXPECT_EQ(m_expected_shared_key, pSecret_key);
}

// Negative length tests: buffers sized to claimed len so guard regression
// triggers ASan, not just a failed EXPECT.
TEST_P(p256Test, SetPrivateKeyLengthTest)
{
    const Uint64 cKeySize = m_p256obj->getKeySize();

    std::vector<Uint8> key(cKeySize + 1, 0xab);

    EXPECT_NE(m_p256obj->setPrivateKey(&key[0], cKeySize - 1).code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj->setPrivateKey(&key[0], cKeySize + 1).code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj->setPrivateKey(&key[0], 0).code(),
              alcp::ErrorCode::eOk);

    EXPECT_EQ(m_p256obj->setPrivateKey(&key[0], cKeySize), alcp::StatusOk());
}

TEST_P(p256Test, FailedKeyReplacementInvalidatesState)
{
    ASSERT_EQ(m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                                       m_peer1_private_key.size()),
              alcp::StatusOk());
    ASSERT_NE(m_p256obj
                  ->setPrivateKey(&m_peer1_private_key[0],
                                  m_peer1_private_key.size() - 1)
                  .code(),
              alcp::ErrorCode::eOk);

    std::vector<Uint8> secret(m_p256obj->getKeySize());
    Uint64             secret_len = 0;
    EXPECT_EQ(m_p256obj
                  ->computeSecretKey(&secret[0],
                                     secret.size(),
                                     &m_peer2_public_key[0],
                                     m_peer2_public_key.size(),
                                     &secret_len)
                  .code(),
              alcp::ErrorCode::eInvalidArgument);
}

TEST_P(p256Test, ValidatePublicKeyLengthTest)
{
    const Uint64 cPubKeySize = m_p256obj->getPublicKeySize();

    EXPECT_EQ(cPubKeySize, 2 * m_p256obj->getKeySize());

    std::vector<Uint8> pub_key(cPubKeySize + 1, 0xab);

    EXPECT_NE(m_p256obj->validatePublicKey(&pub_key[0], cPubKeySize - 1).code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj->validatePublicKey(&pub_key[0], cPubKeySize + 1).code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj->validatePublicKey(&pub_key[0], 0).code(),
              alcp::ErrorCode::eOk);

    EXPECT_EQ(m_p256obj->validatePublicKey(&pub_key[0], cPubKeySize),
              alcp::StatusOk());
}

TEST_P(p256Test, ComputeSecretKeyLengthTest)
{
    const Uint64 cKeySize    = m_p256obj->getKeySize();
    const Uint64 cPubKeySize = m_p256obj->getPublicKeySize();

    m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                             m_peer1_private_key.size());

    std::vector<Uint8> secret_key(cKeySize + 1);
    std::vector<Uint8> pub_key(m_peer2_public_key);
    pub_key.push_back(0xab);

    Uint64 keyLength = 0;

    EXPECT_NE(m_p256obj
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize,
                                     &pub_key[0],
                                     cPubKeySize - 1,
                                     &keyLength)
                  .code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize,
                                     &pub_key[0],
                                     cPubKeySize + 1,
                                     &keyLength)
                  .code(),
              alcp::ErrorCode::eOk);
    EXPECT_NE(m_p256obj
                  ->computeSecretKey(
                      &secret_key[0], cKeySize, &pub_key[0], 0, &keyLength)
                  .code(),
              alcp::ErrorCode::eOk);

    EXPECT_NE(m_p256obj
                  ->computeSecretKey(&secret_key[0],
                                     cKeySize - 1,
                                     &pub_key[0],
                                     cPubKeySize,
                                     &keyLength)
                  .code(),
              alcp::ErrorCode::eOk);

    EXPECT_EQ(keyLength, 0U);

    EXPECT_EQ(
        m_p256obj->computeSecretKey(
            &secret_key[0], cKeySize + 1, &pub_key[0], cPubKeySize, &keyLength),
        alcp::StatusOk());
    EXPECT_EQ(keyLength, cKeySize);
}

TEST_P(p256Test, SecretKeyRefusedWithoutPrivateKey)
{
    std::vector<Uint8> secret_key(m_p256obj->getKeySize(), 0xa5);
    const auto         untouched_secret = secret_key;
    Uint64             keyLength = 0;

    EXPECT_EQ(m_p256obj
                  ->computeSecretKey(&secret_key[0],
                                     secret_key.size(),
                                     &m_peer2_public_key[0],
                                     m_peer2_public_key.size(),
                                     &keyLength)
                  .code(),
              alcp::ErrorCode::eInvalidArgument);
    EXPECT_EQ(keyLength, 0U);
    EXPECT_EQ(secret_key, untouched_secret);
}

TEST_P(p256Test, SecretKeyRefusedAfterReset)
{
    ASSERT_EQ(m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                                       m_peer1_private_key.size()),
              alcp::StatusOk());

    const auto* object_begin = reinterpret_cast<const Uint8*>(m_p256obj);
    const auto* object_end   = object_begin + sizeof(*m_p256obj);
    const auto* key_pos      = std::search(object_begin,
                                      object_end,
                                      m_peer1_private_key.begin(),
                                      m_peer1_private_key.end());
    ASSERT_NE(key_pos, object_end);
    const size_t key_offset = static_cast<size_t>(key_pos - object_begin);

    m_p256obj->reset();

    EXPECT_TRUE(std::all_of(object_begin + key_offset,
                            object_begin + key_offset
                                + m_peer1_private_key.size(),
                            [](Uint8 byte) { return byte == 0; }));

    std::vector<Uint8> secret_key(m_p256obj->getKeySize(), 0xa5);
    const auto         untouched_secret = secret_key;
    Uint64             keyLength = 0;

    EXPECT_EQ(m_p256obj
                  ->computeSecretKey(&secret_key[0],
                                     secret_key.size(),
                                     &m_peer2_public_key[0],
                                     m_peer2_public_key.size(),
                                     &keyLength)
                  .code(),
              alcp::ErrorCode::eInvalidArgument);
    EXPECT_EQ(keyLength, 0U);
    EXPECT_EQ(secret_key, untouched_secret);
}

TEST_P(p256Test, ResetAllowsDifferentPrivateKey)
{
    ASSERT_EQ(m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                                       m_peer1_private_key.size()),
              alcp::StatusOk());

    std::vector<Uint8> first_secret(m_p256obj->getKeySize());
    Uint64             first_length = 0;
    ASSERT_EQ(m_p256obj->computeSecretKey(&first_secret[0],
                                          first_secret.size(),
                                          &m_peer2_public_key[0],
                                          m_peer2_public_key.size(),
                                          &first_length),
              alcp::StatusOk());

    m_p256obj->reset();

    std::vector<Uint8> second_private_key = m_peer1_private_key;
    second_private_key.back() ^= 1;
    ASSERT_EQ(m_p256obj->setPrivateKey(&second_private_key[0],
                                       second_private_key.size()),
              alcp::StatusOk());

    std::vector<Uint8> second_secret(m_p256obj->getKeySize());
    Uint64             second_length = 0;
    ASSERT_EQ(m_p256obj->computeSecretKey(&second_secret[0],
                                          second_secret.size(),
                                          &m_peer2_public_key[0],
                                          m_peer2_public_key.size(),
                                          &second_length),
              alcp::StatusOk());

    EXPECT_EQ(first_length, m_p256obj->getKeySize());
    EXPECT_EQ(second_length, m_p256obj->getKeySize());
    EXPECT_NE(second_secret, first_secret);
}

TEST_P(p256Test, RepeatedResetIsSafe)
{
    ASSERT_EQ(m_p256obj->setPrivateKey(&m_peer1_private_key[0],
                                       m_peer1_private_key.size()),
              alcp::StatusOk());

    std::vector<Uint8> secret_key(m_p256obj->getKeySize());
    Uint64             keyLength = 0;
    ASSERT_EQ(m_p256obj->computeSecretKey(&secret_key[0],
                                          secret_key.size(),
                                          &m_peer2_public_key[0],
                                          m_peer2_public_key.size(),
                                          &keyLength),
              alcp::StatusOk());

    /* both key handles are live at this point, and TearDown resets the object
     * once more, so releasing a handle twice would abort here */
    m_p256obj->reset();
    m_p256obj->reset();
    SUCCEED();
}
