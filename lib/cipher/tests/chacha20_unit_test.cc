/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
#include "alcp/types.h"
#include "gtest/gtest.h"
#include <openssl/bio.h>

#include "alcp/utils/benchmark.hh"
#if 1
using namespace alcp::cipher;
TEST(Chacha20, QuarterRoundTest)
{
    Uint32 a = 0x11111111;
    Uint32 b = 0x01020304;
    Uint32 c = 0x9b8d6f43;
    Uint32 d = 0x01234567;
    QuarterRound(a, b, c, d);
    EXPECT_EQ(a, 0xea2a92f4LLU);
    EXPECT_EQ(b, 0xcb1cf8ceLLU);
    EXPECT_EQ(c, 0x4581472eLLU);
    EXPECT_EQ(d, 0x5881c4bbLLU);
}

TEST(Chacha20, IntialState)
{
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint8  iv[]    = { 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    Uint32 counter = 0x01;

    Uint32 state[16];
    ASSERT_EQ(
        CreateInitialState(state, key, sizeof(key), iv, sizeof(iv), counter),
        0LLU);
}

TEST(Chacha20, KeyStream)
{

    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    Uint8 iv[]  = { 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };

    std::vector<Uint8> expected_key_stream = {
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f,
        0xb8, 0x63, 0x1d, 0xed, 0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2,
        0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78, 0x8a, 0x3b, 0x0a, 0xa3,
        0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd, 0xea, 0x21, 0x2c, 0x4c,
        0xf0, 0x7d, 0x41, 0xb7, 0x69, 0xa6, 0x74, 0x9f, 0x3f, 0x63, 0x0f, 0x41,
        0x22, 0xca, 0xfe, 0x28, 0xec, 0x4d, 0xc4, 0x7e, 0x26, 0xd4, 0x34, 0x6d,
        0x70, 0xb9, 0x8c, 0x73, 0xf3, 0xe9, 0xc5, 0x3a, 0xc4, 0x0c, 0x59, 0x45,
        0x39, 0x8b, 0x6e, 0xda, 0x1a, 0x83, 0x2c, 0x89, 0xc1, 0x67, 0xea, 0xcd,
        0x90, 0x1d, 0x7e, 0x2b, 0xf3, 0x63
    };
    std::vector<Uint8> key_stream(expected_key_stream.size(), 0);

    ref::ChaCha256 chacha20_obj;
    chacha20_obj.setKey(key, sizeof(key) * 8);
    chacha20_obj.setIv(iv, sizeof(iv));
    chacha20_obj.encrypt(&key_stream[0], &key_stream[0], key_stream.size());

    EXPECT_EQ(key_stream, expected_key_stream);
}
TEST(Chacha20, Encrypt)
{
    ref::ChaCha256 chacha20_obj_enc, chacha20_obj_dec;
    Uint8          key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint8 iv[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
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
    std::vector<Uint8> output(plaintext.size());
    std::vector<Uint8> decrypted_plaintext(plaintext.size());

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

    chacha20_obj_enc.setKey(key, sizeof(key) * 8);
    chacha20_obj_enc.setIv(iv, sizeof(iv));
    chacha20_obj_enc.encrypt(&plaintext[0], &output[0], plaintext.size());
    ASSERT_EQ(output, expected_output);
    chacha20_obj_dec.setKey(key, sizeof(key) * 8);
    chacha20_obj_dec.setIv(iv, sizeof(iv));
    chacha20_obj_dec.decrypt(
        &output[0], &decrypted_plaintext[0], plaintext.size());
    EXPECT_EQ(decrypted_plaintext, plaintext);
}

TEST(Chacha20, Encrypt_MultipleBytes)
{
    ref::ChaCha256 chacha20_obj_enc, chacha20_obj_dec;
    Uint8          key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint8 iv[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
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
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e, 0x4c, 0x61, 0x64, 0x69, 0x65, 0x73,
        0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d,
        0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
        0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f,
        0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c,
        0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f,
        0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20,
        0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
        0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e, 0x4c, 0x61, 0x64, 0x69, 0x65, 0x73,
        0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d,
        0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
        0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f,
        0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c,
        0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f,
        0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20,
        0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e
    };
    std::vector<Uint8> output(plaintext.size());
    std::vector<Uint8> decrypted_plaintext(plaintext.size());

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
        0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d, 0x38, 0x62, 0x17, 0x49, 0x7f, 0xd2,
        0xa8, 0x9a, 0xd2, 0x8c, 0x19, 0xd6, 0xa1, 0x83, 0xbc, 0x81, 0x63, 0x21,
        0x0b, 0xfd, 0xbd, 0x2f, 0x57, 0x55, 0x9a, 0x89, 0x22, 0x70, 0x90, 0x89,
        0xc8, 0xdd, 0xf8, 0x66, 0xae, 0x2b, 0x8d, 0x6d, 0xaf, 0x11, 0xf0, 0x8f,
        0x4f, 0x2c, 0x01, 0x99, 0x2a, 0x11, 0x3c, 0xd8, 0x94, 0xab, 0xae, 0xdf,
        0xfe, 0x0a, 0x5b, 0x1a, 0x52, 0xbf, 0xb1, 0x10, 0x6d, 0xef, 0x18, 0xa7,
        0xe3, 0x81, 0xf3, 0x79, 0x24, 0x1d, 0xf2, 0xd5, 0x7e, 0xf5, 0x0d, 0x7c,
        0xdc, 0xf3, 0x81, 0x8f, 0x9f, 0xad, 0x6f, 0x29, 0x44, 0x10, 0x35, 0x4d,
        0x19, 0x44, 0xbf, 0xe6, 0x0f, 0x8c, 0x40, 0x37, 0x48, 0xd2, 0xa8, 0x56,
        0x12, 0x1a, 0xf0, 0xcc, 0x81, 0x51, 0x19, 0x64, 0xe9, 0xe4, 0x49, 0x60,
        0xcf, 0xa6, 0xc2, 0xb2, 0xc9, 0x86, 0x04, 0x81, 0xaa, 0xf6, 0x61, 0xe8,
        0xe2, 0x65, 0x67, 0x1f, 0x70, 0xc8, 0x40, 0x17, 0xc0, 0xbe, 0x23, 0x5d,
        0x0d, 0xc9, 0xa8, 0x06, 0xa8, 0x3d, 0xd4, 0xd1, 0x6e, 0x9d, 0x57, 0x6e,
        0xcc, 0x50, 0x68, 0xd2, 0xa3, 0x10, 0x9a, 0x3e, 0x7f, 0x88, 0x1a, 0xa4,
        0xd8, 0x35, 0xdf, 0x69, 0x28, 0x69, 0x3c, 0x6a, 0xb7, 0x33, 0x01, 0xd4,
        0x5e, 0x0a, 0x97, 0x2d, 0xce, 0x8d, 0x20, 0x5d, 0xf2, 0xa7, 0x70, 0x4f,
        0x74, 0x81, 0x25, 0x85, 0xaf, 0xbb, 0xaa, 0x9c, 0xb7, 0xdc, 0x45, 0x17,
        0x44, 0x5e, 0xcf, 0xd9, 0xbf, 0xf7, 0x55, 0x1d, 0xfa, 0x88, 0xb9, 0x43,
        0x08, 0xfa, 0xa5, 0x08, 0x15, 0xcb, 0x63, 0x6b, 0x75, 0xf0, 0x34, 0x9b,
        0x05, 0x81, 0x19, 0xe5, 0x40, 0xba, 0x3e, 0x4d, 0x83, 0x07, 0x15, 0xbc,
        0xb8, 0x4a, 0x6b, 0x07, 0x1a, 0x5b, 0x73, 0xe4, 0x92, 0x39, 0x47, 0x4e,
        0xcc, 0xcb, 0xc7, 0xd6, 0x76, 0x36, 0xeb, 0xbb, 0x7e, 0x40, 0x3b, 0x74,
        0x22, 0x96, 0x99, 0xaf, 0xd6, 0xc0, 0x1f, 0x18, 0x55, 0x14, 0x2e, 0x3f,
        0x53, 0xfd, 0x82, 0x9d, 0x9b, 0x0d, 0x1b, 0xfb, 0x10, 0x44, 0xae, 0x22,
        0x0e, 0x47, 0x47, 0xe6, 0xae, 0x46, 0x02, 0x20, 0x18, 0xc7, 0x89, 0xa9,
        0x34, 0xf7, 0x74, 0x2e, 0x2b, 0xd5, 0x33, 0x89, 0xc7, 0xfb, 0x83, 0xcb,
        0x65, 0x29, 0x62, 0xe0, 0x7d, 0x89, 0x2b, 0x73, 0x6c, 0x07, 0xf2, 0x58,
        0x22, 0x2a, 0xf3, 0x47, 0xa9, 0x63, 0xbe, 0xb4, 0x54, 0x9f, 0xfb, 0x69,
        0xa8, 0xc2, 0x34, 0x5a, 0xdc, 0xac, 0xf8, 0xf1, 0x01, 0x8a, 0xd3, 0x92
    };
    chacha20_obj_enc.setKey(key, sizeof(key) * 8);
    chacha20_obj_enc.setIv(iv, sizeof(iv));
    chacha20_obj_dec.setKey(key, sizeof(key));
    chacha20_obj_dec.setIv(iv, sizeof(iv));
    for (Uint64 i = 0; i < plaintext.size(); i++) {
        chacha20_obj_enc.encrypt(&plaintext[0], &output[0], i);
        ASSERT_EQ(
            std::vector<Uint8>(&output[0], &output[0] + i),
            std::vector<Uint8>(&expected_output[0], &expected_output[0] + i))
            << "Failed to Encrypt block size " << i;
        chacha20_obj_dec.decrypt(&output[0], &decrypted_plaintext[0], i);
        ASSERT_EQ(
            std::vector<Uint8>(&output[0], &output[0] + i),
            std::vector<Uint8>(&expected_output[0], &expected_output[0] + i))
            << "Failed to Decrypt block size " << i;
    }
}

TEST(Chacha20, PerformanceTest)
{
    ref::ChaCha256 chacha20_obj;
    Uint8          key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    Uint8 iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    std::vector<Uint8> plaintext(256);
    std::vector<Uint8> ciphertext(plaintext.size());
    chacha20_obj.setKey(key, sizeof(key) * 8);
    chacha20_obj.setIv(iv, sizeof(iv));
    ALCP_CRYPT_TIMER_INIT
    totalTimeElapsed = 0.0;
    for (int k = 0; k < 1000000000; k++) {
        ALCP_CRYPT_TIMER_START
        chacha20_obj.encrypt(&plaintext[0], &ciphertext[0], plaintext.size());
        ALCP_CRYPT_GET_TIME(0, "Encrypt")
        if (totalTimeElapsed > 1) {
            std::cout << "\n\n"
                      << std::setw(5) << (k * plaintext.size())
                      << " Encrypted bytes per second\n";
            break;
        }
    }
}

#endif
