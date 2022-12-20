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

// #include "cipher/alc_base.hh"
// #include "cipher/base.hh"

#include "capi/cipher/ctx.hh"
#include "cipher/aes.hh"
#include "cipher/aes_build.hh"
#include "cipher/gtest_base.hh"
#include "gtest/gtest.h"

using namespace alcp::testing;
using namespace alcp::cipher;

std::string MODE_STR = "XTS";

#define ALC_MODE ALC_AES_MODE_XTS

// KAT Data
// clang-format off
typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // tweak key
                   std::vector<Uint8>, // iv
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8> // ciphertext
                  >
            param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

/* Example Encodings
P_K128b_TW128b_IV16B_P16B_C16B 
P     -> Pass, F -> Fail
K128b -> Key 128 bit
TW128b -> Tweak Key 128 bit
IV7B   -> IV 16 byte
P0B   -> PlainText 16 byte
C0B   -> CipherText 16 byte

Tuple order
{key,nonce,aad,plain,ciphertext,tag}
*/
known_answer_map_t KATDataset{
    {
        "P_K128b_TW128b_IV16B_P16B_C16B",
        {
            { 0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,0x76,0x08,0x17,0x62},
            { 0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f},
            { 0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,0x6e,0x4b,0x92,0x01,0x3e,0x76,0x8a,0xd5},
            { 0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,0x6f,0xb3,0x50,0x39,0x07,0x90,0x31,0x1c},
            { 0x77,0x8a,0xe8,0xb4,0x3c,0xb9,0x8d,0x5a,0x82,0x50,0x81,0xd5,0xbe,0x47,0x1c,0x63},
        }
    },
    {
        "P_K128b_TW128b_IV16B_P435B_C435B",
        {
            {  0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35, 0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62 },
            {  0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18, 0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f },
            {  0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6, 0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5 },
            { 0xa8, 0xac, 0xf5, 0x7a, 0x6f, 0x86, 0x59, 0xe9, 0xba, 0x38, 0x2a, 0x4d,
                0x16, 0xba, 0xf1, 0x2a, 0x67, 0xd5, 0x43, 0x75, 0x63, 0xfd, 0x63, 0x29,
                0xd9, 0xa8, 0x87, 0xa8, 0x1,  0x4a, 0x10, 0x57, 0x63, 0xe2, 0xfd, 0xa1,
                0xc6, 0x9f, 0x7d, 0xb6, 0x8,  0x54, 0x1d, 0x7f, 0x11, 0xbc, 0xeb, 0xa9,
                0x95, 0x53, 0xa7, 0x8b, 0xc0, 0xae, 0xac, 0x5f, 0xa8, 0xf7, 0x42, 0x6f,
                0xc6, 0x92, 0xa8, 0x4b, 0xe8, 0x46, 0xed, 0xae, 0xa0, 0xdd, 0x67, 0x70,
                0xde, 0xc3, 0xc9, 0x80, 0x90, 0xc8, 0x9c, 0x96, 0xdf, 0x54, 0xee, 0x7b,
                0x81, 0x8e, 0x70, 0xf7, 0x4c, 0x8b, 0x4d, 0x1,  0xd2, 0xf1, 0x53, 0x5f,
                0x64, 0xc1, 0xd,  0x82, 0x79, 0x86, 0xe3, 0x14, 0xbe, 0xae, 0xe4, 0x4,
                0xa,  0x3b, 0x23, 0x63, 0x28, 0xc,  0x3b, 0xd7, 0x43, 0x75, 0xfa, 0xda,
                0x4c, 0x80, 0x7a, 0x96, 0x1d, 0x69, 0xdc, 0x33, 0x77, 0x70, 0xb9, 0x52,
                0x17, 0x13, 0x10, 0x4f, 0x8,  0xbc, 0x6,  0x0,  0x95, 0x19, 0xea, 0xc,
                0x53, 0x28, 0x8a, 0xf5, 0xf,  0xa6, 0x2,  0x48, 0x1b, 0xde, 0x99, 0x84,
                0x93, 0x71, 0xeb, 0x69, 0x2d, 0x38, 0x44, 0x9a, 0xba, 0x1a, 0x35, 0xae,
                0xeb, 0x71, 0x16, 0xba, 0xe1, 0x1,  0x7c, 0x57, 0xfc, 0xfa, 0xd3, 0x5f,
                0xd6, 0xb9, 0x64, 0x68, 0x70, 0xcf, 0x6d, 0xa3, 0xd4, 0x10, 0x40, 0x10,
                0x39, 0x80, 0xa9, 0x38, 0x30, 0x13, 0xf6, 0x8a, 0x54, 0x10, 0x2d, 0xcd,
                0x44, 0x42, 0xec, 0x9,  0xb1, 0x4f, 0xd1, 0xf3, 0xf5, 0x25, 0xfa, 0x12,
                0x33, 0xa6, 0x6d, 0x44, 0x48, 0xf9, 0x66, 0x54, 0x14, 0x1d, 0x7d, 0x91,
                0x43, 0x0,  0x98, 0xa7, 0xd6, 0xda, 0x2e, 0x25, 0x7e, 0x50, 0xeb, 0xd6,
                0x7e, 0xdb, 0x39, 0xa8, 0x61, 0xf1, 0x1a, 0xda, 0xf6, 0x2a, 0x42, 0x86,
                0x3a, 0xbc, 0x57, 0x5c, 0xbb, 0x8d, 0xed, 0x4e, 0xa5, 0xc4, 0x9f, 0x88,
                0x37, 0x8,  0xcb, 0x13, 0x1f, 0xff, 0x91, 0xcd, 0x1a, 0xbb, 0x9d, 0x9,
                0x13, 0x95, 0xc,  0x29, 0x94, 0x55, 0xde, 0xb3, 0x34, 0xca, 0x8,  0x38,
                0xe5, 0x62, 0x9f, 0x1d, 0x29, 0x66, 0x55, 0x89, 0x82, 0x5c, 0xc,  0xc5,
                0xf2, 0xb3, 0xfb, 0x6a, 0xd7, 0x3b, 0x1c, 0xb6, 0x1f, 0xae, 0x39, 0xa6,
                0xbb, 0x4,  0x2b, 0x99, 0x33, 0x6b, 0xdb, 0xda, 0x3a, 0xb6, 0x54, 0xa0,
                0xf8, 0x4d, 0xba, 0xfc, 0x3f, 0xd0, 0x2d, 0x7f, 0x2c, 0xe9, 0x62, 0x76,
                0xb0, 0x7d, 0x5a, 0xc8, 0xb6, 0xe4, 0xcf, 0xa,  0x8d, 0x4a, 0xee, 0xbc,
                0x62, 0xf8, 0x31, 0x5d, 0xe0, 0xe0, 0x36, 0x71, 0x8f, 0x27, 0x61, 0xed,
                0x76, 0x51, 0x56, 0xcf, 0xa2, 0x5f, 0x6e, 0xba, 0x2e, 0x3f, 0xe4, 0x33,
                0xa1, 0xdb, 0x71, 0xb6, 0xdd, 0x38, 0xd1, 0xdd, 0x8c, 0x45, 0xc3, 0x93,
                0x4d, 0xe0, 0x3c, 0x8a, 0x49, 0xb7, 0x8d, 0xa4, 0x5,  0xe9, 0x85, 0x9,
                0xed, 0x87, 0x2f, 0xc4, 0xa7, 0x3d, 0xc5, 0xa4, 0x42, 0x6e, 0xca, 0x59,
                0x4,  0x39, 0x8,  0x71, 0x55, 0x4b, 0xad, 0x6d, 0x3d, 0x47, 0xf6, 0x72,
                0x10, 0xcb, 0xa5, 0xde, 0xac, 0x9f, 0x71, 0x32, 0xd9, 0x2a, 0xa3, 0x29,
                0xd,  0xf8, 0x2,  0x5a },
            { 0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68, 0x20,
                0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65, 0x73, 0x20,
                0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x73,
                0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6f, 0x72,
                0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e, 0x64, 0x20,
                0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x61, 0x6e,
                0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x72, 0x65,
                0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x20, 0x73,
                0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x2e,
                0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76, 0x65, 0x72,
                0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x77,
                0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x64,
                0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6c, 0x6f,
                0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x20,
                0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65,
                0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20,
                0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x69, 0x6e,
                0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68,
                0x73, 0x2e, 0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70,
                0x68, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65,
                0x73, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63,
                0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20,
                0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e,
                0x64, 0x20, 0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20,
                0x61, 0x6e, 0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
                0x72, 0x65, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61,
                0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69,
                0x63, 0x2e, 0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76,
                0x65, 0x72, 0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66,
                0x20, 0x77, 0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75,
                0x20, 0x64, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20,
                0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20,
                0x61, 0x20, 0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e,
                0x63, 0x65, 0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62,
                0x65, 0x20, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20,
                0x69, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61,
                0x70, 0x68, 0x73, 0x2e },
        }
    }
};

// clang-format on

TEST(XTS, initiantiation_with_valid_input)
{
    // clang-format off
    Uint8 iv[]       = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05 };
    Uint8 key[]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8 tweakKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    // clang-format on
    alc_key_info_t tweakKeyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 128, tweakKey
    };
    const alc_cipher_algo_info_t aesInfo = { ALC_MODE,
                                             iv,
                                             { { &tweakKeyInfo } } };

    const alc_key_info_t keyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 128, key
    };
    Xts xts_obj = Xts(aesInfo, keyInfo);

    EXPECT_EQ(xts_obj.getRounds(), 10);
    // FIXME: Linking Error
    EXPECT_EQ(xts_obj.getKeySize(), 16);
    EXPECT_EQ(xts_obj.getNr(), 10);
    // FIXME: Below test is not working
    EXPECT_EQ(xts_obj.getNk(), 4);
}

TEST(XTS, initiantiation_with_invalid_iv)
{
    // clang-format off
    Uint8 iv[]       = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                         0xff, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05 };
    Uint8 key[]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8 tweakKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
    // clang-format on
    alc_key_info_t tweakKeyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, tweakKey
    };
    const alc_cipher_algo_info_t aesInfo = { ALC_MODE,
                                             iv,
                                             { { &tweakKeyInfo } } };

    const alc_key_info_t keyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, key
    };

    Xts xts_obj = Xts(aesInfo, keyInfo);

    EXPECT_EQ(xts_obj.setIv(sizeof(iv), iv), ALC_ERROR_INVALID_SIZE);
    // FIXME: Linking Error
    EXPECT_EQ(xts_obj.getKeySize(), 32);
    EXPECT_EQ(xts_obj.getNr(), 14);
    // FIXME: Below test is not working
    EXPECT_EQ(xts_obj.getNk(), 8);
}

TEST(XTS, valid_all_sizes_encrypt_decrypt_test)
{
    // clang-format off
    Uint8 iv[]       = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                         0xff, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05 };
    Uint8 key[]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8 tweakKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
    // clang-format on
    alc_key_info_t tweakKeyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, tweakKey
    };
    const alc_cipher_algo_info_t aesInfo = { ALC_MODE,
                                             iv,
                                             { { &tweakKeyInfo } } };

    const alc_key_info_t keyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, key
    };

    Xts xts_obj = Xts(aesInfo, keyInfo);

    for (int i = 16; i < 512 * 20; i++) {

        RngBase rb;

        std::vector<Uint8> plainText(i, 0);
        plainText      = rb.genRandomBytes(i);
        Uint64 ct_size = i;
        Uint8* dest    = (Uint8*)malloc(i);

        alc_error_t err = xts_obj.encrypt(&(plainText[0]), dest, ct_size, iv);

        std::vector<Uint8> pt(i, 0);

        err = xts_obj.decrypt(dest, &(pt[0]), ct_size, iv);

        EXPECT_TRUE(err == ALC_ERROR_NONE);
        ArraysMatch(plainText, pt);
    }
}

TEST(XTS, invalid_len_encrypt_decrypt_test)
{
    // clang-format off
    Uint8 iv[]       = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                         0xff, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05 };
    Uint8 key[]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8 tweakKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
    // clang-format on
    alc_key_info_t tweakKeyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, tweakKey
    };
    const alc_cipher_algo_info_t aesInfo = { ALC_MODE,
                                             iv,
                                             { { &tweakKeyInfo } } };

    const alc_key_info_t keyInfo = {
        ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256, key
    };

    Xts                xts_obj = Xts(aesInfo, keyInfo);
    std::vector<Uint8> plainText(4, 0);
    Uint64             ct_size = 4;
    Uint8*             dest    = (Uint8*)malloc(4);

    alc_error_t err = xts_obj.encrypt(&(plainText[0]), dest, ct_size, iv);

    EXPECT_TRUE(err == ALC_ERROR_INVALID_DATA);

    std::vector<Uint8> cipherText(4, 0);

    err = xts_obj.decrypt(&(cipherText[0]), dest, ct_size, iv);
    EXPECT_TRUE(err == ALC_ERROR_INVALID_DATA);

    // FIXME: Dellocate ctx variable
}

using namespace alcp::cipher;
class XTS_KAT
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{
  public:
    Xts*               pXtsObj = nullptr;
    std::vector<Uint8> m_key, m_tweak, _key, m_iv, m_plaintext, m_ciphertext;
    std::string        m_test_name;
    alc_error_t        m_err;
    // Setup Test for Encrypt/Decrypt
    void SetUp() override
    {
        // Tuple order
        // {key,nonce,aad,plain,ciphertext,tag}
        const auto params                                      = GetParam();
        const auto [key, tweak_key, iv, plaintext, ciphertext] = params.second;
        const auto test_name                                   = params.first;

        // Copy Values to class variables
        m_key        = key;
        m_tweak      = tweak_key;
        m_iv         = iv;
        m_plaintext  = plaintext;
        m_ciphertext = ciphertext;
        m_test_name  = test_name;

        /* Initialization */
        alc_key_info_t tweakKeyInfo = {
            ALC_KEY_TYPE_SYMMETRIC, ALC_KEY_FMT_RAW, {}, {}, 256,
            &(m_tweak.at(0))
        };

        const alc_cipher_algo_info_t aesInfo = { ALC_MODE,
                                                 &(iv.at(0)),
                                                 { { &tweakKeyInfo } } };

        const alc_key_info_t keyInfo = { ALC_KEY_TYPE_SYMMETRIC,
                                         ALC_KEY_FMT_RAW,
                                         {},
                                         {},
                                         static_cast<Uint32>(key.size() * 8),
                                         &(key.at(0)) };

        // Setup XTS Object
        pXtsObj = new Xts(aesInfo, keyInfo);
    }
    void TearDown() override { delete pXtsObj; }
};

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    XTS_KAT,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<XTS_KAT::ParamType>& info) {
        return info.param.first;
    });

TEST_P(XTS_KAT, valid_encrypt_request)
{
    SetUp();
    std::vector<Uint8> out(m_ciphertext.size());

    alc_error_t err = pXtsObj->encrypt(
        &(m_plaintext.at(0)), &(out.at(0)), m_plaintext.size(), &(m_iv.at(0)));
    EXPECT_EQ(err, ALC_ERROR_NONE);
    ArraysMatch(out, m_ciphertext);
    // FIXME: Dellocate ctx variable
}

TEST_P(XTS_KAT, valid_decrypt_request)
{
    SetUp();
    std::vector<Uint8> out(m_plaintext.size());

    alc_error_t err = pXtsObj->decrypt(
        &(m_ciphertext.at(0)), &(out.at(0)), m_plaintext.size(), &(m_iv.at(0)));
    EXPECT_EQ(err, ALC_ERROR_NONE);
    ArraysMatch(out, m_plaintext);
    // FIXME: Dellocate ctx variable
}

TEST_P(XTS_KAT, valid_encrypt_decrypt_test)
{
    SetUp();
    std::vector<Uint8> outct(m_ciphertext.size()), outpt(m_plaintext.size());

    alc_error_t err = pXtsObj->encrypt(&(m_plaintext.at(0)),
                                       &(outct.at(0)),
                                       m_plaintext.size(),
                                       &(m_iv.at(0)));
    err             = pXtsObj->decrypt(
        &(outct.at(0)), &(outpt.at(0)), m_plaintext.size(), &(m_iv.at(0)));

    // FIXME: Dellocate ctx variable
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    ArraysMatch(m_plaintext, outpt);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    parseArgs(argc, argv);
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
