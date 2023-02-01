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

#include <gtest/gtest.h>
#include <iostream>
#include <string.h>

#include "ec/ecdh.hh"

#include <sys/time.h>
#ifdef WIN32
#include <Windows.h>
#endif

#define MAX_SIZE_KEY_DATA 64

#define DEBUG_P /* Enable for debugging only */
/*
    debug prints to be print input, cipher, iv and decrypted output
*/
#ifdef DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)                                               \
    printf("\n %s ", S);                                                       \
    for (int x = 0; x < L; x++) {                                              \
        if ((x % (16 * 4) == 0)) {                                             \
            printf("\n");                                                      \
        }                                                                      \
        if (x % 16 == 0) {                                                     \
            printf("   ");                                                     \
        }                                                                      \
        printf(" %2x", *(I + x));                                              \
    }
#else // DEBUG_P
#define ALCP_PRINT_TEXT(I, L, S)
#endif // DEBUG_P

// to do: these macro is better to be moved to common header.
#define ALCP_CRYPT_TIMER_INIT struct timeval begin, end;
long   seconds;
long   microseconds;
double elapsed;
double totalTimeElapsed;

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

#define ALCP_CRYPT_GET_TIME(X, Y)                                              \
    gettimeofday(&end, 0);                                                     \
    seconds      = end.tv_sec - begin.tv_sec;                                  \
    microseconds = end.tv_usec - begin.tv_usec;                                \
    elapsed      = seconds + microseconds * 1e-6;                              \
    totalTimeElapsed += elapsed;                                               \
    if (X) {                                                                   \
        printf("\t" Y);                                                        \
        printf(" %2.2f ms ", elapsed * 1000);                                  \
    }

using namespace std;

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

#if ALCP_X25519_ADDED

class x25519Test
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    std::vector<Uint8> m_peer1_private_key, m_peer2_private_key,
        m_expected_shared_key;
    std::string m_test_name;
    alc_error_t m_err;

    EcX25519* m_px25519obj1 = nullptr;
    EcX25519* m_px25519obj2 = nullptr;
    Uint8     m_publicKeyData1[32];
    Uint8     m_publicKeyData2[32];

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

        m_px25519obj1 = new EcX25519;
        m_px25519obj2 = new EcX25519;
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
    [](const testing::TestParamInfo<x25519Test::ParamType>& info) {
        return info.param.first;
    });

TEST_P(x25519Test, PublicAndSharedKeyTest)
{
    alc_error_t ret = ALC_ERROR_NONE;

    /* Peer 1 */
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));
    m_px25519obj1->GeneratePublicKey(m_publicKeyData1, pPrivKey_input_data1);
    ALCP_PRINT_TEXT(pPrivKey_input_data1, 32, "PrivKey_input_peer1      ")
    ALCP_PRINT_TEXT(m_publicKeyData1, 32, "publicKeyData1      ")

    /* Peer 2 */
    const Uint8* pPrivKey_input_data2 = &(m_peer2_private_key.at(0));
    m_px25519obj2->GeneratePublicKey(m_publicKeyData2, pPrivKey_input_data2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);
    ALCP_PRINT_TEXT(pPrivKey_input_data2, 32, "PrivKey_input_peer2      ")
    ALCP_PRINT_TEXT(m_publicKeyData2, 32, "publicKeyData2      ")

    // compute shared secret key of both peers
    Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength1;
    ret = m_px25519obj1->ComputeSecretKey(
        pSecret_key1, m_publicKeyData2, &keyLength1);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength2;
    ret = m_px25519obj2->ComputeSecretKey(
        pSecret_key2, m_publicKeyData1, &keyLength2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    ALCP_PRINT_TEXT(pSecret_key1, 32, " shared Secret_key1      ")
    ALCP_PRINT_TEXT(pSecret_key2, 32, " shared Secret_key2      ")
    printf("\n");

    ret = memcmp(pSecret_key1, pSecret_key2, keyLength1);
    EXPECT_EQ(ret, 0);
    ret = memcmp(&(m_expected_shared_key.at(0)), pSecret_key2, keyLength1);
    EXPECT_EQ(ret, 0);

    // EXPECT_EQ(ALC_ERROR_NONE, ret);
}

TEST_P(x25519Test, performanceTest)
{
    alc_error_t ret = ALC_ERROR_NONE;

    /* Peer 1 */
    const Uint8* pPrivKey_input_data1 = &(m_peer1_private_key.at(0));

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) {
        ALCP_CRYPT_TIMER_START
        m_px25519obj1->GeneratePublicKey(m_publicKeyData1,
                                         pPrivKey_input_data1);

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf("\n  %5d publickeys generated per second", k);
            break;
        }
    }
    // ALCP_PRINT_TEXT(m_publicKeyData2, 32, "m_publicKeyData2      ")

    Uint8* pSecret_key = new Uint8[MAX_SIZE_KEY_DATA];
    totalTimeElapsed   = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START

        Uint64 keyLength;
        ret = m_px25519obj1->ComputeSecretKey(
            pSecret_key, m_publicKeyData1, &keyLength);
        ALCP_CRYPT_GET_TIME(0, "key generation time")

        if (totalTimeElapsed > 1) {
            printf("\n\n  %5d secretKey  generated per second", k);
            break;
        }
    }
    // ALCP_PRINT_TEXT(pSecret_key, 32, "pSecret_key      ")

    EXPECT_EQ(ALC_ERROR_NONE, ret);
}

#endif // ALCP_X25519_ADDED

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
