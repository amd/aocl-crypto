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
#if 0

#include <algorithm>
#include <memory>
#include <random>

#include <gtest/gtest.h>

#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "debug_defs.hh"
#include "dispatcher.hh"
#include "randomize.hh"

constexpr CpuCipherFeatures cCpuFeatureSelect = CpuCipherFeatures::eDynamic;

using alcp::cipher::Cbc;
using alcp::cipher::ICipher;
namespace alcp::cipher::unittest::cbc {
std::vector<Uint8> key       = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<Uint8> iv        = { 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<Uint8> plainText = {
    0x02, 0x01, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
std::vector<Uint8> cipherText = { 0x2f, 0x85, 0xce, 0xe7, 0x6f, 0xb5,
                                  0xfa, 0xe4, 0xe6, 0x4b, 0xbc, 0x9e,
                                  0x81, 0x00, 0x41, 0xb6 };

/**
 * @brief Factory based Dynamic Dispatch with minimal branches
 * @return Instance of Cbc depending on provided architecure
 * @note Only use this with compile time resolvable expression
 */
template<utils::CpuCipherFeatures features, Uint32 keylen>
std::unique_ptr<ICipher>
CbcFactory(const Uint8 key[])
{
    std::unique_ptr<ICipher> cbc;
    using namespace aesni;
    if constexpr (features == utils::CpuCipherFeatures::eAesni) {
        if constexpr (keylen == 128)
            cbc = std::make_unique<Cbc<EncryptCbc128, DecryptCbc128>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 192)
            cbc = std::make_unique<Cbc<EncryptCbc192, DecryptCbc192>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 256)
            cbc = std::make_unique<Cbc<EncryptCbc256, DecryptCbc256>>(
                key,
                keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            cbc = std::make_unique<Cbc<EncryptCbc128, DecryptCbc128>>(
                key,
                keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes256) {
        if constexpr (keylen == 128)
            cbc = std::make_unique<Cbc<EncryptCbc128, vaes::DecryptCbc128>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 192)
            cbc = std::make_unique<Cbc<EncryptCbc192, vaes::DecryptCbc192>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 256)
            cbc = std::make_unique<Cbc<EncryptCbc256, vaes::DecryptCbc256>>(
                key,
                keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            cbc = std::make_unique<Cbc<EncryptCbc128, DecryptCbc128>>(
                key,
                keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes512) {
        if constexpr (keylen == 128)
            cbc = std::make_unique<Cbc<EncryptCbc128, vaes512::DecryptCbc128>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 192)
            cbc = std::make_unique<Cbc<EncryptCbc192, vaes512::DecryptCbc192>>(
                key,
                keylen); // Create
        else if constexpr (keylen == 256)
            cbc = std::make_unique<Cbc<EncryptCbc256, vaes512::DecryptCbc256>>(
                key,
                keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            cbc = std::make_unique<Cbc<EncryptCbc128, DecryptCbc128>>(
                key,
                keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eDynamic) {
        CpuId                           cpu;
        static utils::CpuCipherFeatures max_feature = getMaxFeature();
        if (max_feature == utils::CpuCipherFeatures::eVaes512) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes512, keylen>(key);
        } else if (max_feature == utils::CpuCipherFeatures::eVaes256) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes256, keylen>(key);
        } else if (max_feature == utils::CpuCipherFeatures::eAesni) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eAesni, keylen>(key);
        }
    }
    assert(cbc.get() != nullptr);
    return cbc;
}

/**
 * @brief CbcFactory but with branches
 * @return Instance of Cbc depending on provided architecure
 * @note Use this when you are going to give a runtime variable
 */
std::unique_ptr<ICipher>
CbcFactoryIndirect(utils::CpuCipherFeatures features,
                   const Uint8              key[],
                   Uint32                   keylen)
{
    switch (keylen) {
        default:
            std::cout << "Unknown Key Length" << std::endl;
        case 128:
            if (features == CpuCipherFeatures::eVaes512) {
                return CbcFactory<CpuCipherFeatures::eVaes512, 128>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CbcFactory<CpuCipherFeatures::eVaes256, 128>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return CbcFactory<CpuCipherFeatures::eAesni, 128>(key);
            } else {
                return CbcFactory<CpuCipherFeatures::eReference, 128>(key);
            }
            break;

        case 192:
            if (features == CpuCipherFeatures::eVaes512) {
                return CbcFactory<CpuCipherFeatures::eVaes512, 192>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CbcFactory<CpuCipherFeatures::eVaes256, 192>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return CbcFactory<CpuCipherFeatures::eAesni, 192>(key);
            } else {
                return CbcFactory<CpuCipherFeatures::eReference, 192>(key);
            }
            break;

        case 256:
            if (features == CpuCipherFeatures::eVaes512) {
                return CbcFactory<CpuCipherFeatures::eVaes512, 256>(key);
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CbcFactory<CpuCipherFeatures::eVaes256, 256>(key);
            } else if (features == CpuCipherFeatures::eAesni) {
                return CbcFactory<CpuCipherFeatures::eAesni, 256>(key);
            } else {
                return CbcFactory<CpuCipherFeatures::eReference, 256>(key);
            }
            break;
    }
}

} // namespace alcp::cipher::unittest::cbc

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::cbc;
TEST(CBC, creation)
{
    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();
    for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        std::unique_ptr<ICipher> cbc;
        cbc = CbcFactoryIndirect(feature, &key[0], key.size() * 8);
        EXPECT_TRUE(cbc.get() != nullptr);
    }
}

TEST(CBC, BasicEncryption)
{
    std::unique_ptr<ICipher> cbc = CbcFactory<cCpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(cipherText.size());

    cbc->encrypt(&plainText[0], &output[0], plainText.size(), &iv[0]);

    EXPECT_EQ(cipherText, output);
}

TEST(CBC, BasicDecryption)
{
    std::unique_ptr<ICipher> cbc = CbcFactory<cCpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(plainText.size());

    cbc->decrypt(&cipherText[0], &output[0], cipherText.size(), &iv[0]);

    EXPECT_EQ(plainText, output);
}

TEST(CBC, RandomEncryptDecryptTest)
{
    Uint8        key_256[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    const Uint64 cTextSize   = 100000;
    std::vector<Uint8> plain_text_vect(cTextSize);
    std::vector<Uint8> cipher_text_vect(cTextSize);
    Uint8              iv[16] = {};

    // Fill buffer with random data
    std::unique_ptr<IRandomize> random = std::make_unique<Randomize>(12);
    random->getRandomBytes(plain_text_vect);
    random->getRandomBytes(cipher_text_vect);
    random->getRandomBytes(key_256, 32);
    random->getRandomBytes(iv, 16);

    std::vector<CpuCipherFeatures> cpu_features = getSupportedFeatures();

    for (int i = (cTextSize - 16); i > 16; i -= 16)
        for (CpuCipherFeatures feature : cpu_features) {
#ifdef DEBUG
            std::cout
                << "Cpu Feature:"
                << static_cast<
                       typename std::underlying_type<CpuCipherFeatures>::type>(
                       feature)
                << std::endl;
#endif
            const std::vector<Uint8> plainTextVect(plain_text_vect.begin() + i,
                                                   plain_text_vect.end());
            std::vector<Uint8>       plainTextOut(plainTextVect.size());
            std::unique_ptr<ICipher> cbc =
                CbcFactoryIndirect(feature, key_256, sizeof(key_256) * 8);

            EXPECT_TRUE(cbc.get() != nullptr);

            cbc->encrypt(&plainTextVect[0],
                         &cipher_text_vect[0],
                         plainTextVect.size(),
                         iv);

            cbc->decrypt(&cipher_text_vect[0],
                         &plainTextOut[0],
                         plainTextVect.size(),
                         iv);

            EXPECT_EQ(plainTextVect, plainTextOut);
#ifdef DEBUG
            auto ret = std::mismatch(plainTextVect.begin(),
                                     plainTextVect.end(),
                                     plainTextOut.begin());
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

#endif