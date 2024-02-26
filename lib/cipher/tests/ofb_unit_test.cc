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

#include <algorithm>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "debug_defs.hh"
#include "dispatcher.hh"
#include "randomize.hh"

constexpr CpuCipherFeatures c_CpuFeatureSelect = CpuCipherFeatures::eDynamic;

using alcp::cipher::ICipher;
using alcp::cipher::Ofb;
namespace alcp::cipher::unittest::ofb {
std::vector<Uint8> key       = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<Uint8> iv        = { 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<Uint8> plainText = {
    0x02, 0x01, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
std::vector<Uint8> cipherText = { 0x5a, 0xa2, 0xf9, 0xdb, 0xe4, 0x4a,
                                  0xc9, 0x81, 0x8e, 0x03, 0x30, 0x98,
                                  0x77, 0x6d, 0xba, 0x37 };

/**
 * @brief Factory based Dynamic Dispatch with minimal branches
 * @return Instance of Ofb depending on provided architecure
 * @note Only use this with compile time resolvable expression
 */
template<utils::CpuCipherFeatures features, Uint32 keylen>
std::unique_ptr<ICipher>
OfbFactory(const Uint8 key[])
{
    std::unique_ptr<ICipher> ofb;
    if constexpr (keylen == 128) {
        ofb = std::make_unique<Ofb>(key, 128);
    } else if constexpr (keylen == 192) {
        ofb = std::make_unique<Ofb>(key, 192);
    } else if constexpr (keylen == 256) {
        ofb = std::make_unique<Ofb>(key, 256);
    } else {
        std::cout << "Keylength not supported!";
        ofb = std::make_unique<Ofb>(key, 128);
    }
    assert(ofb.get() != nullptr);
    return ofb;
}

/**
 * @brief OfbFactory but with branches
 * @return Instance of Ofb depending on provided architecure
 * @note Use this when you are going to give a runtime variable
 */
std::unique_ptr<ICipher>
OfbFactoryIndirect(utils::CpuCipherFeatures features,
                   const Uint8              key[],
                   Uint32                   keylen)
{
    switch (keylen) {
        default:
            std::cout << "Unknown Key Length" << std::endl;
        case 128:
            if (features == CpuCipherFeatures::eVaes512) {
                return OfbFactory<CpuCipherFeatures::eVaes512, 128>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return OfbFactory<CpuCipherFeatures::eVaes256, 128>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return OfbFactory<CpuCipherFeatures::eAesni, 128>(key);
            } else {
                return OfbFactory<CpuCipherFeatures::eReference, 128>(key);
            }
            break;

        case 192:
            if (features == CpuCipherFeatures::eVaes512) {
                return OfbFactory<CpuCipherFeatures::eVaes512, 192>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return OfbFactory<CpuCipherFeatures::eVaes256, 192>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return OfbFactory<CpuCipherFeatures::eAesni, 192>(key);
            } else {
                return OfbFactory<CpuCipherFeatures::eReference, 192>(key);
            }
            break;

        case 256:
            if (features == CpuCipherFeatures::eVaes512) {
                return OfbFactory<CpuCipherFeatures::eVaes512, 256>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return OfbFactory<CpuCipherFeatures::eVaes256, 256>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return OfbFactory<CpuCipherFeatures::eAesni, 256>(key);
            } else {
                return OfbFactory<CpuCipherFeatures::eReference, 256>(key);
            }
            break;
    }
}

} // namespace alcp::cipher::unittest::ofb

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::ofb;
TEST(OFB, creation)
{
    CpuCipherFeatures feature = c_CpuFeatureSelect;
#ifdef DEBUG
    std::cout
        << "Cpu Feature:"
        << static_cast<typename std::underlying_type<CpuCipherFeatures>::type>(
               feature)
        << std::endl;
#endif
    std::unique_ptr<ICipher> ofb;
    ofb = OfbFactoryIndirect(feature, &key[0], key.size() * 8);
    EXPECT_TRUE(ofb.get() != nullptr);
}

TEST(OFB, BasicEncryption)
{
    std::unique_ptr<ICipher> ofb = OfbFactory<c_CpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(ofb.get() != nullptr);

    std::vector<Uint8> output(cipherText.size());

    ofb->encrypt(&plainText[0], &output[0], plainText.size(), &iv[0]);

    EXPECT_EQ(cipherText, output);
}

TEST(OFB, BasicDecryption)
{
    std::unique_ptr<ICipher> ofb = OfbFactory<c_CpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(ofb.get() != nullptr);

    std::vector<Uint8> output(plainText.size());

    ofb->decrypt(&cipherText[0], &output[0], cipherText.size(), &iv[0]);

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

    CpuCipherFeatures feature = c_CpuFeatureSelect;

    for (int i = 100000; i > 16; i -= 16) {
        const std::vector<Uint8> plainTextVect(plainText_vect.begin() + i,
                                               plainText_vect.end());
        std::vector<Uint8>       plainTextOut(plainTextVect.size());
        std::unique_ptr<ICipher> ofb =
            OfbFactoryIndirect(feature, key_256, sizeof(key_256) * 8);

        EXPECT_TRUE(ofb.get() != nullptr);

        ofb->encrypt(
            &plainTextVect[0], &cipherText_vect[0], plainTextVect.size(), iv);

        ofb->decrypt(
            &cipherText_vect[0], &plainTextOut[0], plainTextVect.size(), iv);

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
