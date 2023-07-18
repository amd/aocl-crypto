/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
        const auto params = GetParam();
        const auto [peer1_private_key, peer2_public_key, expected_shared_key] =
            params.second;
        const auto test_name = params.first;

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
    [](const testing::TestParamInfo<p256Test::ParamType>& info) {
        return info.param.first;
    });

TEST_P(p256Test, SecretKeyGen)
{
    alc_error_t ret = ALC_ERROR_NONE;

    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));
    m_p256obj->setPrivateKey(&m_peer1_private_key[0]);

    std::vector<Uint8> pSecret_key(m_p256obj->getKeySize());
    Uint64             keyLength;
    m_p256obj->computeSecretKey(
        &pSecret_key[0], &m_peer2_public_key[0], &keyLength);

    EXPECT_EQ(m_expected_shared_key, pSecret_key);
}
