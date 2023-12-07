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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/chacha20_poly1305.hh"
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

TEST(ChaCha20Poly1305Test, BasicTest)
{

    ChaCha20Poly1305 chacha_poly;
    alc_error_t      err   = ALC_ERROR_NONE;
    Uint8            key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                               0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                               0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                               0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    std::vector<Uint8> plaintext = {
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

    std::vector<Uint8> expected_ciphertext = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
        0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
        0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
        0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16
    };

    std::vector<Uint8> ciphertext(plaintext.size());

    chacha_poly.setNonce(nonce, sizeof(nonce));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = chacha_poly.setKey(key, sizeof(key));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    err = chacha_poly.setAad(AAD, sizeof(AAD));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = chacha_poly.processInput(
        &plaintext[0], plaintext.size(), &ciphertext[0]);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(ciphertext, expected_ciphertext);

    std::vector<Uint8> tag(16);

    err = chacha_poly.getTag(&tag[0], 16);
#ifdef DEBUG
    std::cout << "Tag is " << std::endl;
    BIO_dump_fp(stdout, &tag[0], tag.size());
#endif
    std::vector<Uint8> expected_tag = { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
                                        0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
                                        0xd0, 0x60, 0x06, 0x91 };
    ASSERT_EQ(err, ALC_ERROR_NONE);
    EXPECT_EQ(tag, expected_tag);
}

TEST(Chacha20Poly1305, PerformanceTest)
{
    ChaCha20Poly1305 chacha_poly;
    Uint8            key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                               0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                               0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                               0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

    Uint8 AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    Uint8 nonce[] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                      0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

    std::vector<Uint8> plaintext(256);
    std::vector<Uint8> ciphertext(plaintext.size());

    chacha_poly.setNonce(nonce, sizeof(nonce));
    chacha_poly.setKey(key, sizeof(key));
    chacha_poly.setAad(AAD, sizeof(AAD));

    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 1000000000; k++) {
        ALCP_CRYPT_TIMER_START
        chacha_poly.processInput(
            &plaintext[0], plaintext.size(), &ciphertext[0]);
        ALCP_CRYPT_GET_TIME(0, "Encrypt")
        if (totalTimeElapsed > 1) {
            std::cout << "\n\n"
                      << std::setw(5) << (k * plaintext.size())
                      << " Encrypted bytes per second\n";
            break;
        }
    }
}