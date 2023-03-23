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

#include "ecdh/ecdh.hh"

#include "ecdh/alcp_ecdh.hh"

#ifdef USE_OSSL
#include "ecdh/openssl_ecdh.hh"
#endif

#ifdef USE_IPP
#include "ecdh/ippcp_ecdh.hh"
#endif

#ifdef WIN32
#include "alcp/utils/time.hh"
#else
#include <sys/time.h>
#endif

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

using namespace alcp::testing;
using namespace std;

static const Uint8 peer1_privk_data[32] = {
    0x80, 0x5b, 0x30, 0x20, 0x25, 0x4a, 0x70, 0x2c, 0xad, 0xa9, 0x8d,
    0x7d, 0x47, 0xf8, 0x1b, 0x20, 0x89, 0xd2, 0xf9, 0x14, 0xac, 0x92,
    0x27, 0xf2, 0x10, 0x7e, 0xdb, 0x21, 0xbd, 0x73, 0x73, 0x5d
};

static const Uint8 peer2_privk_data[32] = {
    0xf8, 0x84, 0x19, 0x69, 0x79, 0x13, 0x0d, 0xbd, 0xb1, 0x76, 0xd7,
    0x0e, 0x7e, 0x0f, 0xb6, 0xf4, 0x8c, 0x4a, 0x8c, 0x5f, 0xd8, 0x15,
    0x09, 0x0a, 0x71, 0x78, 0x74, 0x92, 0x0f, 0x85, 0xc8, 0x43
};

static const Uint8 expected_result[32] = {
    0x19, 0x71, 0x26, 0x12, 0x74, 0xb5, 0xb1, 0xce, 0x77, 0xd0, 0x79,
    0x24, 0xb6, 0x0a, 0x5c, 0x72, 0x0c, 0xa6, 0x56, 0xc0, 0x11, 0xeb,
    0x43, 0x11, 0x94, 0x3b, 0x01, 0x45, 0xca, 0x19, 0xfe, 0x09
};

#ifdef USE_OSSL
TEST(EC_X25519, opensslVerifySecretKey)
{
    alc_error_t ret = ALC_ERROR_NONE;

    alc_peer_id_t peerId;
    string        st       = "X25519"; //"prime256v1"; // P-256
    const char*   pKeytype = st.c_str();

    /* Peer 1 */
    Uint8 publicKeyData1[32];
    peerId              = ALC_PEER_ONE;
    OpenSSLEcdh* pEcdh1 = NULL;
    pEcdh1              = new OpenSSLEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data1 = peer1_privk_data;
    pEcdh1->generate_public_key(&publicKeyData1[0], pPrivKey_input_data1);
    ALCP_PRINT_TEXT(pPrivKey_input_data1, 32, "pPrivKey_input_peer1      ")
    ALCP_PRINT_TEXT(publicKeyData1, 32, "publicKeyData1      ")

    /* Peer 2 */
    Uint8 publicKeyData2[32];
    peerId              = ALC_PEER_TWO;
    OpenSSLEcdh* pEcdh2 = NULL;
    pEcdh2              = new OpenSSLEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data2 = peer2_privk_data;
    pEcdh2->generate_public_key(&publicKeyData2[0], pPrivKey_input_data2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);
    ALCP_PRINT_TEXT(pPrivKey_input_data2, 32, "pPrivKey_input_peer2      ")
    ALCP_PRINT_TEXT(publicKeyData2, 32, "publicKeyData2      ")
    printf("\n");

    // compute shared secret key of both peers
    Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength1;
    ret = pEcdh1->compute_secret_key(pSecret_key1, publicKeyData2, &keyLength1);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength2;
    ret = pEcdh2->compute_secret_key(pSecret_key2, publicKeyData1, &keyLength2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    if (memcmp(pSecret_key1, pSecret_key2, keyLength1) == 0) {
        ret = ALC_ERROR_NONE;
    }

    EXPECT_EQ(ALC_ERROR_NONE, ret);
}

TEST(EC_X25519, opensslSpeedCheck)
{
    alc_error_t ret = ALC_ERROR_NONE;

    alc_peer_id_t peerId;
    string        st       = "X25519"; //"prime256v1"; // P-256
    const char*   pKeytype = st.c_str();

    /* Peer 1 */
    Uint8 publicKeyData1[32];
    peerId              = ALC_PEER_ONE;
    OpenSSLEcdh* pEcdh1 = NULL;
    pEcdh1              = new OpenSSLEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data1 = peer1_privk_data;

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START
        pEcdh1->generate_public_key(&publicKeyData1[0], pPrivKey_input_data1);

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf(" %5d openSSL publickeys generated per second \n", k);
            break;
        }
    }

    /* Peer 2 */
    Uint8 publicKeyData2[32];
    peerId              = ALC_PEER_TWO;
    OpenSSLEcdh* pEcdh2 = NULL;
    pEcdh2              = new OpenSSLEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data2 = peer2_privk_data;
    pEcdh2->generate_public_key(&publicKeyData2[0], pPrivKey_input_data2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    // compute shared secret key of both peers
    Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength1;
    ret = pEcdh1->compute_secret_key(pSecret_key1, publicKeyData2, &keyLength1);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength2;
    // ret = pEcdh2->compute_secret_key(pSecret_key2, publicKeyData1,
    // &keyLength2); EXPECT_EQ(ALC_ERROR_NONE, ret);

    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START

        Uint64 keyLength;
        ret = pEcdh2->compute_secret_key(
            pSecret_key2, publicKeyData1, &keyLength2);
        ALCP_CRYPT_GET_TIME(0, "key generation time")

        if (totalTimeElapsed > 1) {
            printf(" %5d openSSL secretKey  generated per second \n", k);
            break;
        }
    }
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    if (memcmp(pSecret_key1, pSecret_key2, keyLength1) == 0) {
        ret = ALC_ERROR_NONE;
    }

    EXPECT_EQ(ALC_ERROR_NONE, ret);
}
#endif

#ifdef USE_IPP
TEST(EC_X25519, ippcpVerifySecretKey)
{
    alc_error_t   ret = ALC_ERROR_NONE;
    alc_peer_id_t peerId;
    string        st       = "X25519"; //"prime256v1"; // P-256
    const char*   pKeytype = st.c_str();

    /* Peer 1 */
    Uint8 publicKeyData1[32];
    peerId            = ALC_PEER_ONE;
    ippcpEcdh* pEcdh1 = NULL;
    pEcdh1            = new ippcpEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data1 = peer1_privk_data;
    pEcdh1->generate_public_key(&publicKeyData1[0], pPrivKey_input_data1);
    ALCP_PRINT_TEXT(pPrivKey_input_data1, 32, "pPrivKey_input_peer1      ")
    ALCP_PRINT_TEXT(publicKeyData1, 32, "publicKeyData1      ")

    /* Peer 2 */
    Uint8 publicKeyData2[32];
    peerId            = ALC_PEER_TWO;
    ippcpEcdh* pEcdh2 = NULL;
    pEcdh2            = new ippcpEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data2 = peer2_privk_data;
    pEcdh2->generate_public_key(&publicKeyData2[0], pPrivKey_input_data2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);
    ALCP_PRINT_TEXT(pPrivKey_input_data2, 32, "pPrivKey_input_peer2      ")
    ALCP_PRINT_TEXT(publicKeyData2, 32, "publicKeyData2      ")
    printf("\n");

    // compute shared secret key of both peers
    Uint8* pSecret_key1 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength1;
    ret = pEcdh1->compute_secret_key(pSecret_key1, publicKeyData2, &keyLength1);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    Uint8* pSecret_key2 = new Uint8[MAX_SIZE_KEY_DATA];
    Uint64 keyLength2;
    ret = pEcdh2->compute_secret_key(pSecret_key2, publicKeyData1, &keyLength2);
    EXPECT_EQ(ALC_ERROR_NONE, ret);

    ALCP_PRINT_TEXT(pSecret_key2, 32, " shared Secret_key      ")

    if (memcmp(pSecret_key1, pSecret_key2, keyLength1) == 0) {
        ret = ALC_ERROR_NONE;
    }

    EXPECT_EQ(ALC_ERROR_NONE, ret);
}

TEST(EC_X25519, ippcpCheckSpeed)
{
    alc_error_t   ret = ALC_ERROR_NONE;
    alc_peer_id_t peerId;
    string        st       = "X25519";
    const char*   pKeytype = st.c_str();

    /* Peer 1 */
    Uint8 publicKeyData1[32];
    peerId            = ALC_PEER_ONE;
    ippcpEcdh* pEcdh1 = NULL;
    pEcdh1            = new ippcpEcdh(pKeytype, peerId);
    // Feed KAT test input
    const Uint8* pPrivKey_input_data1 = peer1_privk_data;

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START
        pEcdh1->generate_public_key(&publicKeyData1[0], pPrivKey_input_data1);

        ALCP_CRYPT_GET_TIME(0, "key generation time")
        if (totalTimeElapsed > 1) {
            printf("\n  %5d publickeys generated per second", k);
            break;
        }
    }
    // ALCP_PRINT_TEXT(publicKeyData1, 32, "publicKeyData1      ")

    Uint8* pSecret_key = new Uint8[MAX_SIZE_KEY_DATA];
    totalTimeElapsed   = 0.0;
    for (int k = 0; k < 100000000; k++) //
    {
        ALCP_CRYPT_TIMER_START

        Uint64 keyLength;
        ret =
            pEcdh1->compute_secret_key(pSecret_key, publicKeyData1, &keyLength);
        ALCP_CRYPT_GET_TIME(0, "key generation time")

        if (totalTimeElapsed > 1) {
            printf("\n  %5d secretKey  generated per second \n", k);
            break;
        }
    }
    // ALCP_PRINT_TEXT(pSecret_key, 32, "pSecret_key      ")

    EXPECT_EQ(ALC_ERROR_NONE, ret);
}
#endif
int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
