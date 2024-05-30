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

#include <algorithm>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ofb.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "debug_defs.hh"
#include "dispatcher.hh"
#include "randomize.hh"

using alcp::cipher::Ofb;
namespace alcp::cipher::unittest::ofb {
std::vector<Uint8> key       = { 0x0d, 0x3c, 0x13, 0x53, 0xea, 0x0f, 0x01, 0x06,
                           0x83, 0x47, 0x98, 0xc8, 0x6d, 0x3d, 0xc7, 0x4e };
std::vector<Uint8> iv        = { 0xf6, 0xe5, 0x25, 0x16, 0x7d, 0xca, 0x50, 0xbf,
                          0x1b, 0x9f, 0xb8, 0x13, 0xd2, 0xec, 0xab, 0x5e };
std::vector<Uint8> plainText = {
    0x12, 0xb0, 0xe9, 0x9b, 0x7f, 0xf8, 0xc4, 0x6a, 0xb0, 0xae, 0x00, 0xf7,
    0xfb, 0x7a, 0xa7, 0x19, 0x3d, 0x0c, 0x87, 0xe9, 0x14, 0x01, 0x02, 0x62,
    0x8f, 0x19, 0xcd, 0x95, 0xd1, 0x64, 0x5b, 0x3d, 0xab, 0xae, 0x1d, 0x5d,
    0xd7, 0xc1, 0xa7, 0x92, 0x88, 0x5b, 0xe9, 0xac, 0x02, 0x05, 0x1d, 0xb2,
    0x52, 0x2c, 0x30, 0xc6, 0x76, 0x70, 0x0f, 0xb7, 0x0c, 0xe5, 0x71, 0x6c,
    0x6d, 0xab, 0xda, 0x18, 0x32, 0x7d, 0x4a, 0x0b, 0x31, 0xb4, 0xaa, 0xbf,
    0x09, 0x01, 0xcf, 0x22, 0xc1, 0x27, 0xb1, 0xfc, 0xda, 0x6d, 0x90, 0x88,
    0xa3, 0x41, 0xf2, 0xb0, 0x13, 0x46, 0x5a, 0x8f, 0xb7, 0xa9, 0xb0, 0xf3,
    0xb9, 0x3a, 0x6b, 0xf5, 0xe6, 0xe1, 0x6a, 0x92, 0x4c, 0xf3, 0x5e, 0xfc,
    0x58, 0x73, 0x5b, 0x49, 0xd9, 0x21, 0xc3, 0xad, 0x24, 0xff, 0xf6, 0x47,
    0x7d, 0xf6, 0x19, 0xfd, 0xbc, 0x5e, 0xc7, 0x79, 0x2a, 0x36, 0x29, 0xa9,
    0xc1, 0x58, 0xcc, 0xd1, 0x14, 0x2d, 0x1f, 0x9e, 0x0f, 0x97, 0xbb, 0xb4,
    0xc4, 0x26, 0x2a, 0xf9, 0x53, 0xce, 0xd6, 0xbd, 0xcb, 0x19, 0x89, 0xea,
    0x01, 0xe9, 0xb0, 0x3b, 0x07, 0xba, 0xef, 0xdb, 0x14, 0x52, 0x7e, 0x07,
    0xa3, 0x2c, 0x12, 0xaa, 0x8c, 0xf2, 0x02, 0x5e, 0x36, 0x84, 0xfe, 0x7c,
    0x86, 0xfe, 0x73, 0x3f, 0x77, 0xf3, 0xd9, 0x96, 0x44, 0x24, 0x0f, 0x44,
    0x50, 0x35, 0xc9, 0x12, 0xce, 0x28, 0x66, 0xfd, 0x2c, 0x5c, 0x1a, 0x14,
    0x85, 0x10, 0x02, 0xa3, 0xc5, 0x08, 0x37, 0xdc, 0x52, 0xae, 0x1b, 0x06,
    0x70, 0x2e, 0x38, 0xed, 0x2a, 0xc6, 0x59, 0xc6, 0x50, 0xf1, 0xe7, 0x64,
    0x71, 0x11, 0x47, 0x45, 0xec, 0xee, 0xf3, 0x77, 0xe0, 0x8c, 0xef, 0x6d,
    0xf2, 0xd4, 0xaa, 0x7b, 0x19, 0xec, 0x9d, 0xf2, 0x78, 0xde, 0x8d, 0x6e,
    0xea, 0x00, 0x7b, 0xaf, 0x9e, 0xf8, 0xcc, 0x3b, 0xf6, 0x31, 0x12, 0x06,
    0x54, 0xf9, 0xef, 0x51, 0xc1, 0x02, 0x52, 0x26, 0xfb, 0x1a, 0xf8, 0x4e,
    0xe4, 0x3e, 0x3e, 0x49, 0x14, 0xb3, 0x26, 0x75, 0xd6, 0x45, 0x46, 0xf8,
    0xea, 0xb9, 0xe0, 0x97, 0x05, 0x7e, 0xb6, 0xdd, 0x18, 0xf9, 0xe5, 0x82,
    0xcb, 0x4b, 0xfa, 0x71, 0x09, 0x02, 0x39, 0xfe, 0xbc, 0xc2, 0x27, 0xd2,
    0xce, 0xd3, 0x93, 0x21, 0x29, 0x26, 0x84, 0x39
};
std::vector<Uint8> cipherText = {
    0x0a, 0x92, 0x50, 0x53, 0x16, 0x94, 0x53, 0x2d, 0x2f, 0xaf, 0xc8, 0xe2,
    0xce, 0xf8, 0x9e, 0xba, 0xf4, 0x3f, 0x9b, 0xa6, 0x71, 0xfe, 0x4c, 0xe8,
    0xa5, 0xbf, 0x43, 0xa8, 0x15, 0xc3, 0xd3, 0xdc, 0x2a, 0xbe, 0x56, 0x84,
    0x63, 0x5a, 0xf1, 0xab, 0x1f, 0xc6, 0x26, 0x51, 0xdd, 0x3a, 0xd4, 0x92,
    0x43, 0x83, 0x77, 0x6a, 0x30, 0x3b, 0xef, 0x90, 0xd7, 0xd4, 0x8c, 0xb2,
    0x38, 0xcc, 0x03, 0xd7, 0x74, 0x5d, 0x9b, 0xa1, 0x5a, 0xdd, 0x38, 0xdd,
    0xce, 0x20, 0xbe, 0x4f, 0xeb, 0x23, 0xda, 0xd9, 0x42, 0x21, 0x35, 0xa2,
    0x89, 0xb2, 0xe9, 0x25, 0x40, 0xac, 0xe8, 0x38, 0x3d, 0xe0, 0x05, 0xf3,
    0x64, 0xd9, 0x34, 0xca, 0x91, 0xd4, 0x7e, 0xcc, 0xe7, 0x72, 0xe8, 0xe0,
    0x7b, 0x8c, 0xbb, 0x06, 0x83, 0x19, 0xce, 0x88, 0xbc, 0x80, 0x80, 0x4c,
    0xda, 0xe7, 0xf5, 0xfa, 0x82, 0x21, 0x7d, 0xb1, 0x46, 0xc6, 0xf0, 0xc4,
    0x6b, 0xa6, 0x53, 0x6a, 0xc6, 0xdb, 0xe6, 0x49, 0x62, 0x39, 0x94, 0xf4,
    0x37, 0xe6, 0x75, 0x77, 0x64, 0x8a, 0xeb, 0x15, 0x6f, 0x52, 0x73, 0x93,
    0xa5, 0xaa, 0xa2, 0x12, 0x0f, 0x04, 0x67, 0x91, 0x99, 0xcc, 0xb9, 0x40,
    0x33, 0xfe, 0xaa, 0x93, 0x0e, 0xa3, 0xbd, 0xf4, 0xec, 0x24, 0x1f, 0x10,
    0x1e, 0x75, 0x79, 0x86, 0xc5, 0xf8, 0x8d, 0xf7, 0x24, 0x72, 0x9e, 0xd8,
    0xad, 0xcf, 0x71, 0x7f, 0x79, 0x4f, 0x63, 0x6d, 0xa9, 0x99, 0x73, 0xa8,
    0xd4, 0xa1, 0x29, 0x5f, 0xb6, 0xcf, 0xd1, 0x3c, 0x18, 0x6b, 0x4c, 0x86,
    0x2c, 0xae, 0xa8, 0x8d, 0xc8, 0xfd, 0x02, 0x83, 0x64, 0x12, 0x0b, 0xca,
    0x31, 0xfb, 0xc9, 0x24, 0x68, 0x9c, 0xc5, 0x19, 0x89, 0xcd, 0x0a, 0x63,
    0xab, 0x7d, 0x70, 0xe1, 0xee, 0x9b, 0x0c, 0x5e, 0xd0, 0x01, 0xd6, 0x59,
    0xdb, 0xc1, 0xd9, 0x1c, 0x74, 0x55, 0x21, 0xd6, 0xc8, 0x9f, 0x86, 0x82,
    0xe0, 0xf8, 0xf6, 0x3c, 0x9b, 0xea, 0x94, 0xd0, 0xd6, 0x40, 0xc8, 0x44,
    0xb4, 0xda, 0xfd, 0x43, 0x8b, 0xac, 0xc3, 0x17, 0xaf, 0x4e, 0xdb, 0xa9,
    0x92, 0x70, 0xe6, 0xbd, 0x15, 0x4d, 0xe1, 0x03, 0xaa, 0x23, 0x84, 0x89,
    0x67, 0xb5, 0x8e, 0x6c, 0xfa, 0xa8, 0x63, 0x78, 0xaf, 0x57, 0x5d, 0xef,
    0x02, 0x1d, 0x50, 0xcc, 0xef, 0x3a, 0xf5, 0x08
};

} // namespace alcp::cipher::unittest::ofb

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::ofb;

TEST(OFB, creation)
{
    alc_cipher_data_t data;
    data.alcp_keyLen_in_bytes = key.size();
    std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);
    EXPECT_TRUE(ofb->isSupported(key.size() * 8));
}

TEST(OFB, BasicEncryption)
{
    alc_cipher_data_t data;
    data.alcp_keyLen_in_bytes = key.size();
    std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);

    EXPECT_TRUE(ofb->isSupported(key.size() * 8));

    std::vector<Uint8> output(cipherText.size());

    ofb->init(&key[0], key.size() * 8, &iv[0], iv.size());

    ofb->encrypt(&data, &plainText[0], &output[0], plainText.size());

    EXPECT_EQ(cipherText, output);
}

TEST(OFB, BasicDecryption)
{
    alc_cipher_data_t data;
    data.alcp_keyLen_in_bytes = key.size();
    std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);

    EXPECT_TRUE(ofb->isSupported(key.size() * 8));

    std::vector<Uint8> output(plainText.size());

    ofb->init(&key[0], key.size() * 8, &iv[0], iv.size());

    ofb->decrypt(&data, &cipherText[0], &output[0], cipherText.size());

    EXPECT_EQ(plainText, output);
}

TEST(OFB, MultiUpdateEncryption)
{
#ifndef OFB_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    alc_cipher_data_t data;
    data.alcp_keyLen_in_bytes = key.size();
    std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);

    EXPECT_TRUE(ofb->isSupported(key.size() * 8));

    std::vector<Uint8> output(cipherText.size());

    // api to be added to icipher
    // ctr->setKey(128, &key[0]);  or
    // ctr->setKey(128, &key[0]);

    alc_error_t err = ofb->init(&key[0], key.size() * 8, &iv[0], iv.size());

    if (alcp_is_error(err)) {
        std::cout << "Init failed!" << std::endl;
    }

    for (Uint64 i = 0; i < plainText.size() / 16; i++) {
        err = ofb->encrypt(&data,
                           &plainText[0] + i * 16,
                           &output[0] + i * 16,
                           16); // 16 byte chunks
        if (alcp_is_error(err)) {
            std::cout << "Encrypt failed!" << std::endl;
        }
        EXPECT_FALSE(alcp_is_error(err));
    }

    EXPECT_EQ(cipherText, output);
}

TEST(OFB, MultiUpdateDecryption)
{
#ifndef OFB_MULTI_UPDATE
    GTEST_SKIP() << "Multi Update functionality unavailable!";
#endif
    alc_cipher_data_t data;
    data.alcp_keyLen_in_bytes = key.size();
    std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);

    EXPECT_TRUE(ofb->isSupported(key.size() * 8));

    std::vector<Uint8> output(cipherText.size());

    alc_error_t err = ofb->init(&key[0], key.size() * 8, &iv[0], iv.size());

    if (alcp_is_error(err)) {
        std::cout << "Init failed!" << std::endl;
    }

    for (Uint64 i = 0; i < plainText.size() / 16; i++) {
        err = ofb->decrypt(
            &data, &cipherText[0] + i * 16, &output[0] + i * 16, 16);
        if (alcp_is_error(err)) {
            std::cout << "Decrypt failed!" << std::endl;
        }
        EXPECT_FALSE(alcp_is_error(err));
    }

    EXPECT_EQ(plainText, output);
}

TEST(OFB, RandomEncryptDecryptTest)
{
    Uint8 key_256[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    std::vector<Uint8> plainText_vect(100000);
    std::vector<Uint8> cipherText_vect(100000);
    Uint8              iv[16] = {};

    // Fill buffer with random data
    std::unique_ptr<IRandomize> random = std::make_unique<Randomize>(12);
    random->getRandomBytes(plainText_vect);
    random->getRandomBytes(cipherText_vect);
    random->getRandomBytes(key_256, 32);
    random->getRandomBytes(iv, 16);

    for (int i = 100000 - 16; i > 16; i -= 16) {
        const std::vector<Uint8> plainTextVect(plainText_vect.begin() + i,
                                               plainText_vect.end());
        std::vector<Uint8>       plainTextOut(plainTextVect.size());
        alc_cipher_data_t        data;
        data.alcp_keyLen_in_bytes = key.size();
        std::unique_ptr<Ofb> ofb  = std::make_unique<Ofb>(&data);

        EXPECT_TRUE(ofb->isSupported(key.size() * 8));

        ofb->init(&key[0], key.size() * 8, &iv[0], sizeof(iv));

        ofb->encrypt(&data,
                     &plainTextVect[0],
                     &cipherText_vect[0],
                     plainTextVect.size());

        ofb->init(&key[0], key.size() * 8, &iv[0], sizeof(iv));

        ofb->decrypt(
            &data, &cipherText_vect[0], &plainTextOut[0], plainTextVect.size());

        EXPECT_EQ(plainTextVect, plainTextOut);
#ifdef DEBUG
        auto ret = std::mismatch(
            plainTextVect.begin(), plainTextVect.end(), plainTextOut.begin());
        std::cout << "First:" << ret.first - plainTextVect.begin()
                  << "Second:" << ret.second - plainTextOut.begin()
                  << std::endl;
#endif
    }
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}