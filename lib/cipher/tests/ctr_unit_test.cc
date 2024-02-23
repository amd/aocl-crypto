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

#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"
#include "debug_defs.hh"
#include "dispatcher.hh"
#include "randomize.hh"

constexpr CpuCipherFeatures cCpuFeatureSelect = CpuCipherFeatures::eDynamic;

using alcp::cipher::Ctr;
using alcp::cipher::ICipher;
namespace alcp::cipher::unittest::ctr {
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
 * @return Instance of Ctr depending on provided architecure
 * @note Only use this with compile time resolvable expression
 */
template<utils::CpuCipherFeatures features, Uint32 keylen>
std::unique_ptr<ICipher>
CtrFactory()
{
    std::unique_ptr<ICipher> ctr;
    if constexpr (features == utils::CpuCipherFeatures::eAesni) {
        using namespace aesni;
        if constexpr (keylen == 128) {
            ctr = std::make_unique<Ctr128>(keylen); // Create
        } else if constexpr (keylen == 192)
            ctr = std::make_unique<Ctr192>(keylen); // Create
        else if constexpr (keylen == 256)
            ctr = std::make_unique<Ctr256>(keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            ctr = std::make_unique<Ctr128>(keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes256) {
        using namespace vaes;
        if constexpr (keylen == 128) {
            ctr = std::make_unique<Ctr128>(keylen); // Create
        } else if constexpr (keylen == 192)
            ctr = std::make_unique<Ctr192>(keylen); // Create
        else if constexpr (keylen == 256)
            ctr = std::make_unique<Ctr256>(keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            ctr = std::make_unique<Ctr128>(keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes512) {
        using namespace vaes512;
        if constexpr (keylen == 128) {
            ctr = std::make_unique<Ctr128>(keylen); // Create
        } else if constexpr (keylen == 192)
            ctr = std::make_unique<Ctr192>(keylen); // Create
        else if constexpr (keylen == 256)
            ctr = std::make_unique<Ctr256>(keylen); // Create
        else {
            std::cout << "Error Keysize is not supported!" << std::endl;
            // Dispatch to something else
            ctr = std::make_unique<Ctr128>(keylen); // Create
        }
    } else if constexpr (features == utils::CpuCipherFeatures::eDynamic) {
        alcp::utils::CpuId              cpu;
        static utils::CpuCipherFeatures max_feature = getMaxFeature();
        if (max_feature == utils::CpuCipherFeatures::eVaes512) {
            ctr = CtrFactory<utils::CpuCipherFeatures::eVaes512, keylen>();
        } else if (max_feature == utils::CpuCipherFeatures::eVaes256) {
            ctr = CtrFactory<utils::CpuCipherFeatures::eVaes256, keylen>();
        } else if (max_feature == utils::CpuCipherFeatures::eAesni) {
            ctr = CtrFactory<utils::CpuCipherFeatures::eAesni, keylen>();
        }
    }
    assert(ctr.get() != nullptr);
    return ctr;
}

/**
 * @brief CtrFactory but with branches
 * @return Instance of Ctr depending on provided architecure
 * @note Use this when you are going to give a runtime variable
 */
std::unique_ptr<ICipher>
CtrFactoryIndirect(utils::CpuCipherFeatures features, Uint32 keylen)
{
    switch (keylen) {
        default:
            std::cout << "Unknown Key Length" << std::endl;
        case 128:
            if (features == CpuCipherFeatures::eVaes512) {
                return CtrFactory<CpuCipherFeatures::eVaes512, 128>();
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CtrFactory<CpuCipherFeatures::eVaes256, 128>();
            } else if (features == CpuCipherFeatures::eAesni) {
                return CtrFactory<CpuCipherFeatures::eAesni, 128>();
            } else {
                return CtrFactory<CpuCipherFeatures::eReference, 128>();
            }
            break;

        case 192:
            if (features == CpuCipherFeatures::eVaes512) {
                return CtrFactory<CpuCipherFeatures::eVaes512, 192>();
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CtrFactory<CpuCipherFeatures::eVaes256, 192>();
            } else if (features == CpuCipherFeatures::eAesni) {
                return CtrFactory<CpuCipherFeatures::eAesni, 192>();
            } else {
                return CtrFactory<CpuCipherFeatures::eReference, 192>();
            }
            break;

        case 256:
            if (features == CpuCipherFeatures::eVaes512) {
                return CtrFactory<CpuCipherFeatures::eVaes512, 256>();
            } else if (features == CpuCipherFeatures::eVaes256) {
                return CtrFactory<CpuCipherFeatures::eVaes256, 256>();
            } else if (features == CpuCipherFeatures::eAesni) {
                return CtrFactory<CpuCipherFeatures::eAesni, 256>();
            } else {
                return CtrFactory<CpuCipherFeatures::eReference, 256>();
            }
            break;
    }
}

} // namespace alcp::cipher::unittest::ctr

using namespace alcp::cipher::unittest;
using namespace alcp::cipher::unittest::ctr;
TEST(CTR, creation)
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
        std::unique_ptr<ICipher> ctr;
        ctr = CtrFactoryIndirect(feature, key.size() * 8);
        EXPECT_TRUE(ctr.get() != nullptr);
    }
}

TEST(CTR, BasicEncryption)
{
    std::unique_ptr<ICipher> ctr = CtrFactory<cCpuFeatureSelect, 128>();

    EXPECT_TRUE(ctr.get() != nullptr);

    std::vector<Uint8> output(cipherText.size());

    // api to be added to icipher
    // ctr->setKey(128, &key[0]);  or
    // ctr->initKey(128, &key[0]);

    ctr->encrypt(&plainText[0], &output[0], plainText.size(), &iv[0]);

    EXPECT_EQ(cipherText, output);
}

TEST(CTR, BasicDecryption)
{
    std::unique_ptr<ICipher> ctr = CtrFactory<cCpuFeatureSelect, 128>();

    EXPECT_TRUE(ctr.get() != nullptr);

    std::vector<Uint8> output(plainText.size());

    // ctr->setKey(128, &key[0]);

    ctr->decrypt(&cipherText[0], &output[0], cipherText.size(), &iv[0]);

    EXPECT_EQ(plainText, output);
}

TEST(CTR, RandomEncryptDecryptTest)
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
            std::unique_ptr<ICipher> ctr =
                CtrFactoryIndirect(feature, sizeof(key_256) * 8);

            EXPECT_TRUE(ctr.get() != nullptr);

            // ctr->setKey(128, &key[0]);

            ctr->encrypt(&plainTextVect[0],
                         &cipher_text_vect[0],
                         plainTextVect.size(),
                         iv);

            ctr->decrypt(&cipher_text_vect[0],
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