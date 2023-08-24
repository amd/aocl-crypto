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

#include "../chacha20_inplace.cc.inc"
#include "alcp/cipher/chacha20.hh"
#include "alcp/cipher/chacha20_inplace.hh"
#include "alcp/types.h"
#include "gtest/gtest.h"
#include <openssl/bio.h>

#ifdef WIN32
#include "alcp/utils/time.hh"
#else
#include <sys/time.h>
#endif
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

using namespace alcp::cipher;
TEST(Chacha20, QuarterRoundTest)
{
    Uint32 a = 0x11111111;
    Uint32 b = 0x01020304;
    Uint32 c = 0x9b8d6f43;
    Uint32 d = 0x01234567;
    QuarterRound(a, b, c, d);
    EXPECT_EQ(a, 0xea2a92f4);
    EXPECT_EQ(b, 0xcb1cf8ce);
    EXPECT_EQ(c, 0x4581472e);
    EXPECT_EQ(d, 0x5881c4bb);
}

TEST(Chacha20, IntialState)
{
    ChaCha20 chacha20_obj;
    Uint8    key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    /*
        Uint8 iv[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0x00, 0x00, 0x00,
                       0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; */

    Uint32 counter = 0x01;
    Uint8  nonce[] = { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                       0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    ASSERT_NE(chacha20_obj.createInitialState(
                  key, sizeof(key), counter, nonce, sizeof(nonce)),
              0);
}

TEST(Chacha20, Encrypt)
{
    ChaCha20 chacha20_obj;
    Uint8    key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint32 counter     = 0x01;
    Uint8  nonce[]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    Uint8  plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
        0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e
    };
    std::vector<Uint8> output(sizeof(plaintext));

    std::vector<Uint8> expected_output = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28,
        0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5,
        0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
        0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed,
        0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d
    };
    ASSERT_NE(chacha20_obj.processInput(key,
                                        sizeof(key),
                                        counter,
                                        nonce,
                                        sizeof(nonce),
                                        plaintext,
                                        sizeof(plaintext),
                                        &output[0]),
              0);
    EXPECT_EQ(output, expected_output);
    std::cout << "CipherText after encryption" << std::endl;
    BIO_dump_fp(stdout, &output[0], output.size());
}

TEST(Chacha20, PerformanceTest)
{
    ChaCha20 chacha20_obj;
    Uint8    key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint32 counter = 0x01;
    Uint8  nonce[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    std::vector<Uint8> plaintext(16384);
    std::vector<Uint8> ciphertext(plaintext.size());

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 1000000000; k++) {
        ALCP_CRYPT_TIMER_START
        chacha20_obj.processInput(key,
                                  sizeof(key),
                                  counter,
                                  nonce,
                                  sizeof(nonce),
                                  &plaintext[0],
                                  plaintext.size(),
                                  &ciphertext[0]);
        ALCP_CRYPT_GET_TIME(0, "Encrypt")
        if (totalTimeElapsed > 1) {
            std::cout << "\n\n"
                      << std::setw(5) << k * plaintext.size()
                      << " Encrypted bytes per second\n";
            break;
        }
    }
    // std::cout << "Speed = "
    //           << (10000 * plaintext.size() / totalTimeElapsed) / 1024
    //           << " kilo bytes per second" << std::endl;
}