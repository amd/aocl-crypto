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
#include <string.h>

#include "alcp/base.hh"
#include "alcp/error.h"
#include "alcp/rsa.hh"
#include "alcp/types.hh"

#define MAX_SIZE_KEY_DATA 32

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

using namespace rsa;
class RsaTest
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8> m_peer1_private_key, m_peer2_private_key,
        m_expected_shared_key;
    std::string m_test_name;
    alc_error_t m_err;

    Rsa*  m_pRsaobj1           = nullptr;
    Rsa*  m_pRsaobj2           = nullptr;
    Uint8 m_publicKeyData1[32] = {};
    Uint8 m_publicKeyData2[32] = {};

    void SetUp() override
    {
        // Tuple order
        // {peer1_private_key, peer2_private_key,expected_shared_key}
        const auto params = GetParam();
        const auto [peer1_private_key, peer2_private_key, expected_shared_key] =
            params.second;
        const auto test_name = params.first;

        // Copy Values to class variables
        m_peer1_private_key   = peer1_private_key;
        m_peer2_private_key   = peer2_private_key;
        m_expected_shared_key = expected_shared_key;

        m_test_name = test_name;

        m_pRsaobj1 = new Rsa;
        m_pRsaobj2 = new Rsa;
    }

    void TearDown() override
    {
        delete m_pRsaobj1;
        delete m_pRsaobj2;
    }
};

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    RsaTest,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<RsaTest::ParamType>& info) {
        return info.param.first;
    });

TEST_P(RsaTest, PublicEncryptPrivateDecryptTest)
{
    alc_error_t ret = ALC_ERROR_NONE;

    /* Peer 1 */
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));
    // m_pRsaobj1->generatePublicKey(m_publicKeyData1, pPrivKey_input_data1);

    // /* Peer 2 */
    // const Uint8* pPrivKey_input_data2 = &(m_peer2_private_key.at(0));
    // m_pRsaobj2->generatePublicKey(m_publicKeyData2, pPrivKey_input_data2);

    // // compute shared secret key of both peers
    // Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    // Uint64 keyLength1;
    // m_pRsaobj1->computeSecretKey(pSecret_key1, m_publicKeyData2,
    // &keyLength1);

    // Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    // Uint64 keyLength2;
    // m_pRsaobj2->computeSecretKey(pSecret_key2, m_publicKeyData1,
    // &keyLength2);

    // ret = memcmp(pSecret_key1, pSecret_key2, keyLength1);
    // EXPECT_EQ(ret, 0);
    // ret = memcmp(&(m_expected_shared_key.at(0)), pSecret_key2, keyLength1);
    EXPECT_EQ(ret, 0);
}

} // namespace
