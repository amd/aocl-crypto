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

#include "capi/cipher/builder.hh"
#include "cipher.hh"
#include "cipher/aes_build.hh"
// FIXME: Remove all the includes from gtest_base related to capi
#include "cipher/gtest_base.hh"
#include "gtest/gtest.h"

// KAT Data
// clang-format off
typedef std::tuple<std::vector<Uint8>, // key
                   std::vector<Uint8>, // nonce
                   std::vector<Uint8>, // aad
                   std::vector<Uint8>, // plaintext
                   std::vector<Uint8>, // ciphertext
                   std::vector<Uint8> // tag
                  >
            param_tuple;
typedef std::map<const std::string, param_tuple> known_answer_map_t;

/* Example Encodings
P_K128b_N7B_A0B_P0B_C0B_T4B 
P     -> Pass, F -> Fail
K128b -> Key 128 bit
N7B   -> Nonce 7 byte
A0B   -> Additional Data 0 byte
P0B   -> PlainText 0 byte
C0B   -> CipherText 0 byte
T4B   -> Tag 4 byte

Tuple order
{key,nonce,aad,plain,ciphertext,tag}
*/
known_answer_map_t KATDataset{
    {
      "P_K128b_N7B_A0B_P0B_C0B_T4B",
      {
        { 0x4a, 0xe7, 0x01, 0x10, 0x3c, 0x63, 0xde, 0xca, 0x5b, 0x5a, 0x39, 0x39, 0xd7, 0xd0, 0x59, 0x92 },
        { 0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9 },
        {},
        {},
        {},
        { 0x02, 0x20, 0x9f, 0x55 },
      }
    },
    {
      "P_K128b_N7B_A0B_P24B_C24B_T4B",
      {
        { 0x19, 0xeb, 0xfd, 0xe2, 0xd5, 0x46, 0x8b, 0xa0, 0xa3, 0x03, 0x1b, 0xde, 0x62, 0x9b, 0x11, 0xfd },
        { 0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9 },
        {},
        { 0x37, 0x96, 0xcf, 0x51, 0xb8, 0x72, 0x66, 0x52, 0xa4, 0x20, 0x47, 0x33, 0xb8, 0xfb, 0xb0, 0x47, 0xcf, 0x00, 0xfb, 0x91, 0xa9, 0x83, 0x7e, 0x22 },
        { 0xa9, 0x0e, 0x8e, 0xa4, 0x40, 0x85, 0xce, 0xd7, 0x91, 0xb2, 0xfd, 0xb7, 0xfd, 0x44, 0xb5, 0xcf, 0x0b, 0xd7, 0xd2, 0x77, 0x18, 0x02, 0x9b, 0xb7 },
        { 0x03, 0xe1, 0xfa, 0x6b },
      }
    },
    {
      "F_K128b_N7B_A0B_P0B_C0B_T4B",
      {
        { 0x4a, 0xe7, 0x01, 0x10, 0x3c, 0x63, 0xde, 0xca, 0x5b, 0x5a, 0x39, 0x39, 0xd7, 0xd0, 0x59, 0x92 },
        { 0x37, 0x96, 0xcf, 0x51, 0xb8, 0x72, 0x66 },
        {},
        {},
        {},
        { 0x9a, 0x04, 0xc2, 0x41 },
      }
    },
};
// clang-format on

class CCM_KAT
    : public testing::TestWithParam<std::pair<const std::string, param_tuple>>
{};

using namespace alcp::cipher;
TEST(CCM, Initiantiation)
{
    Uint8 iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    Uint8 key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
                                             .ai_iv   = iv };
    // clang-format off
    const alc_key_info_t keyInfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                     .fmt  = ALC_KEY_FMT_RAW,
                                     .len  = 128,
                                     .key  = key };
    Ccm                  ccm_obj = Ccm(aesInfo, keyInfo);
    // clang-format on
    EXPECT_EQ(ccm_obj.getRounds(), 10);
    // FIXME: Linking Error
    // EXPECT_EQ(ccm_obj.getKeySize(),128);
    EXPECT_EQ(ccm_obj.getNr(), 10);
    // FIXME: Below test is not working
    // EXPECT_EQ(ccm_obj.getNk(),16);
}

TEST(CCM, ZeroLEN)
{
    Uint8  iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    Uint8  key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    Uint8  tagbuff[14];
    char   ad[]      = "This is a sample additional data";
    char   message[] = "This is a sample message to encrypt!";
    Uint8* output_ct = new Uint8[strlen(message)];
    const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
                                             .ai_iv   = iv };
    // clang-format off
    const alc_key_info_t keyInfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                     .fmt  = ALC_KEY_FMT_RAW,
                                     .len  = 128,
                                     .key  = key };
    // clang-format on
    Ccm         ccm_obj = Ccm(aesInfo, keyInfo);
    alc_error_t err;
    err = ccm_obj.encryptUpdate(nullptr, nullptr, 0, iv);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    err = ccm_obj.encryptUpdate(reinterpret_cast<Uint8*>(ad), nullptr, 0, iv);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    err = ccm_obj.encryptUpdate(
        reinterpret_cast<Uint8*>(message), output_ct, 0, iv);
    EXPECT_EQ(err, ALC_ERROR_NONE);
    err = ccm_obj.encryptUpdate(nullptr, tagbuff, 0, iv);
    EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
}

TEST_P(CCM_KAT, Encrypt)
{
    // Tuple order
    // {key,nonce,aad,plain,ciphertext,tag}
    const auto params                                        = GetParam();
    const auto [key, nonce, aad, plaintext, ciphertext, tag] = params.second;
    const auto test_name                                     = params.first;

    std::vector<Uint8> out_tag(tag.size(), 0),
        out_ciphertext(plaintext.size(), 0);

    const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
                                             .ai_iv   = &(nonce.at(0)) };
    // clang-format off
    const alc_key_info_t keyInfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                     .fmt  = ALC_KEY_FMT_RAW,
                                     .len  = static_cast<Uint32>(key.size()*8),
                                     .key  = &(key.at(0)) };
    // clang-format on
    Ccm         ccm_obj = Ccm(aesInfo, keyInfo);
    alc_error_t err;
    err = ccm_obj.encryptUpdate(nullptr, nullptr, nonce.size(), &(nonce.at(0)));
    EXPECT_EQ(err, ALC_ERROR_NONE);
    if (!aad.empty()) {
        err = ccm_obj.encryptUpdate(
            &(aad.at(0)), nullptr, aad.size(), &(nonce.at(0)));
        EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    }
    if (!plaintext.empty()) {
        err = ccm_obj.encryptUpdate(&(plaintext.at(0)),
                                    &(out_ciphertext.at(0)),
                                    plaintext.size(),
                                    &(nonce.at(0)));
        EXPECT_TRUE(ArraysMatch(out_ciphertext, ciphertext));
    } else {
        Uint8 a;
        err = ccm_obj.encryptUpdate(&a, &a, 0, &(nonce.at(0)));
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);
    if (!tag.empty()) {
        printf("tagLen:%ld\n", tag.size());
        err = ccm_obj.encryptUpdate(
            nullptr, &(out_tag.at(0)), tag.size(), &(nonce.at(0)));
        if (test_name.at(0) == 'P')
            EXPECT_TRUE(ArraysMatch(out_tag, tag));
        else
            EXPECT_FALSE(ArraysMatch(out_tag, tag));
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }
}

TEST_P(CCM_KAT, Decrypt)
{
    // Tuple order
    // {key,nonce,aad,plain,ciphertext,tag}
    const auto params                                        = GetParam();
    const auto [key, nonce, aad, plaintext, ciphertext, tag] = params.second;
    const auto test_name                                     = params.first;

    std::vector<Uint8> out_tag(tag.size(), 0),
        out_plaintext(ciphertext.size(), 0);

    const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
                                             .ai_iv   = &(nonce.at(0)) };
    // clang-format off
    const alc_key_info_t keyInfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
                                     .fmt  = ALC_KEY_FMT_RAW,
                                     .len  = static_cast<Uint32>(key.size()*8),
                                     .key  = &(key.at(0)) };
    // clang-format on
    Ccm         ccm_obj = Ccm(aesInfo, keyInfo);
    alc_error_t err;
    err = ccm_obj.decryptUpdate(nullptr, nullptr, nonce.size(), &(nonce.at(0)));
    EXPECT_EQ(err, ALC_ERROR_NONE);
    if (!aad.empty()) {
        err = ccm_obj.decryptUpdate(
            &(aad.at(0)), nullptr, aad.size(), &(nonce.at(0)));
        EXPECT_EQ(err, ALC_ERROR_INVALID_SIZE);
    }
    if (!ciphertext.empty()) {
        err = ccm_obj.decryptUpdate(&(ciphertext.at(0)),
                                    &(out_plaintext.at(0)),
                                    ciphertext.size(),
                                    &(nonce.at(0)));
        EXPECT_TRUE(ArraysMatch(out_plaintext, plaintext));
    } else {
        Uint8 a;
        err = ccm_obj.decryptUpdate(&a, &a, 0, &(nonce.at(0)));
    }
    EXPECT_EQ(err, ALC_ERROR_NONE);
    if (!tag.empty()) {
        printf("tagLen:%ld\n", tag.size());
        err = ccm_obj.decryptUpdate(
            nullptr, &(out_tag.at(0)), tag.size(), &(nonce.at(0)));
        if (test_name.at(0) == 'P')
            EXPECT_TRUE(ArraysMatch(out_tag, tag));
        else
            EXPECT_FALSE(ArraysMatch(out_tag, tag));
        EXPECT_EQ(err, ALC_ERROR_NONE);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KnownAnswerTest,
    CCM_KAT,
    testing::ValuesIn(KATDataset),
    [](const testing::TestParamInfo<CCM_KAT::ParamType>& info) {
        return info.param.first;
    });

// TEST(CCM, InvalidTagLen)
// {
//     Uint8  iv[]  = { 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
//     Uint8  key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//     Uint8  tagbuff[14];
//     char*  ad        = "This is a sample additional data";
//     char*  message   = "This is a sample message to encrypt!";
//     Uint8* output_ct = new Uint8[strlen(message)];
//     const alc_cipher_algo_info_t aesInfo = { .ai_mode = ALC_AES_MODE_CCM,
//                                              .ai_iv   = iv };
//     // clang-format off
//     const alc_key_info_t keyInfo = { .type = ALC_KEY_TYPE_SYMMETRIC,
//                                      .fmt  = ALC_KEY_FMT_RAW,
//                                      .len  = 128,
//                                      .key  = key };
//     Ccm                  ccm_obj = Ccm(aesInfo, keyInfo);
//     alc_error_t err;
//     err = ccm_obj.encryptUpdate(nullptr,nullptr,0,iv);
//     EXPECT_EQ(err,ALC_ERROR_INVALID_SIZE);
//     err = ccm_obj.encryptUpdate(reinterpret_cast<Uint8 *>(ad),
//     nullptr,0,iv); EXPECT_EQ(err,ALC_ERROR_INVALID_SIZE); err =
//     ccm_obj.encryptUpdate(reinterpret_cast<Uint8
//     *>(message),output_ct,0,iv); EXPECT_EQ(err,ALC_ERROR_INVALID_SIZE);
//     err = ccm_obj.encryptUpdate(nullptr,tagbuff,0,iv);
//     EXPECT_EQ(err,ALC_ERROR_INVALID_SIZE);
// }

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
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
