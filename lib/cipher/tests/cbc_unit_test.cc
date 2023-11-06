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

#include "alcp/cipher/aes_cbc.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/cpuid.hh"

using namespace alcp::utils;

constexpr CpuCipherFeatures c_CpuFeatureSelect = CpuCipherFeatures::eDynamic;

using alcp::cipher::Cbc;
using alcp::cipher::ICbc;
namespace alcp::cipher::unittest {
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

CpuCipherFeatures
getMaxFeature()
{
    CpuId             cpu;
    CpuCipherFeatures maxFeature = {};
    if (cpu.cpuHasVaes() && cpu.cpuHasAvx512f()) {
        maxFeature = utils::CpuCipherFeatures::eVaes512;
    } else if (cpu.cpuHasVaes()) {
        maxFeature = utils::CpuCipherFeatures::eVaes256;
    } else if (cpu.cpuHasAesni()) {
        maxFeature = utils::CpuCipherFeatures::eAesni;
    } else {
        maxFeature = utils::CpuCipherFeatures::eReference;
    }
    return maxFeature;
}

std::vector<CpuCipherFeatures>
getSupportedFeatures()
{
    std::vector<CpuCipherFeatures> ret        = {};
    CpuCipherFeatures              maxFeature = getMaxFeature();
    switch (maxFeature) {
        case CpuCipherFeatures::eVaes512:
            ret.insert(ret.begin(), CpuCipherFeatures::eVaes512);
        case CpuCipherFeatures::eVaes256:
            ret.insert(ret.begin(), CpuCipherFeatures::eVaes256);
        case CpuCipherFeatures::eAesni:
            ret.insert(ret.begin(), CpuCipherFeatures::eAesni);
            break;
        default:
            ret.insert(ret.begin(), CpuCipherFeatures::eReference);
            break;
    }
    return ret;
}

/**
 * @brief Factory based Dynamic Dispatch with minimal branches
 * @return Instance of Cbc depending on provided architecure
 * @note Only use this with compile time resolvable expression
 */
template<utils::CpuCipherFeatures features, Uint32 keylen>
std::unique_ptr<ICbc>
CbcFactory(const Uint8 key[])
{
    std::unique_ptr<ICbc> cbc;
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
        static utils::CpuCipherFeatures maxFeature = getMaxFeature();
        if (maxFeature == utils::CpuCipherFeatures::eVaes512) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes512, keylen>(key);
        } else if (maxFeature == utils::CpuCipherFeatures::eVaes256) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes256, keylen>(key);
        } else if (maxFeature == utils::CpuCipherFeatures::eAesni) {
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
std::unique_ptr<ICbc>
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

class IRandomize
{
  public:
    virtual void getRandomBytes(std::vector<Uint8>& out) = 0;
    virtual void getRandomBytes(Uint8* out, Uint64 size) = 0;
    virtual ~IRandomize(){};
};

class Randomize : public IRandomize
{
  private:
    std::mt19937 mt;

  public:
    Randomize() { mt = std::mt19937((time(nullptr))); }
    Randomize(Uint64 seed) { mt = std::mt19937(seed); }
    void getRandomBytes(std::vector<Uint8>& out)
    {
        std::generate(out.begin(), out.end(), mt);
    }
    void getRandomBytes(Uint8* out, Uint64 size)
    {
        std::generate(out, out + size, mt);
    }
    ~Randomize() = default;
};

} // namespace alcp::cipher::unittest

using namespace alcp::cipher::unittest;
TEST(CBC, creation)
{
    std::vector<CpuCipherFeatures> cpuFeatures = getSupportedFeatures();
    for (CpuCipherFeatures feature : cpuFeatures) {
#if 1
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        std::unique_ptr<ICbc> cbc;
        cbc = CbcFactoryIndirect(feature, &key[0], key.size() * 8);
        EXPECT_TRUE(cbc.get() != nullptr);
    }
}

TEST(CBC, BasicEncryption)
{
    std::unique_ptr<ICbc> cbc = CbcFactory<c_CpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(cipherText.size());

    cbc->encrypt(&plainText[0], &output[0], plainText.size(), &iv[0]);

    EXPECT_EQ(cipherText, output);
}

TEST(CBC, BasicDecryption)
{
    std::unique_ptr<ICbc> cbc = CbcFactory<c_CpuFeatureSelect, 128>(&key[0]);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(plainText.size());

    cbc->decrypt(&cipherText[0], &output[0], cipherText.size(), &iv[0]);

    EXPECT_EQ(plainText, output);
}

#if 1
TEST(CBC, RandomEncryptDecryptTest)
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

    std::vector<CpuCipherFeatures> cpuFeatures = getSupportedFeatures();

    for (int i = 100000; i > 16; i -= 16)
        for (CpuCipherFeatures feature : cpuFeatures) {
#if 0
            std::cout
                << "Cpu Feature:"
                << static_cast<
                       typename std::underlying_type<CpuCipherFeatures>::type>(
                       feature)
                << std::endl;
#endif
            // Use buffer back to front to create new test cases from one buffer
            // [ 1 2 3 4 5 6 7 8 9 10]
            const std::vector<Uint8> plainTextVect(plainText_vect.begin() + i,
                                                   plainText_vect.end());
            std::vector<Uint8>       plainTextOut(plainTextVect.size());
            std::unique_ptr<ICbc>    cbc =
                CbcFactoryIndirect(feature, key_256, sizeof(key_256) * 8);

            EXPECT_TRUE(cbc.get() != nullptr);

            cbc->encrypt(&plainTextVect[0],
                         &cipherText_vect[0],
                         plainTextVect.size(),
                         iv);

            cbc->decrypt(&cipherText_vect[0],
                         &plainTextOut[0],
                         plainTextVect.size(),
                         iv);

            EXPECT_EQ(plainTextVect, plainTextOut);
#if 0
            auto ret = std::mismatch(plainTextVect.begin(),
                                     plainTextVect.end(),
                                     plainTextOut.begin());
            std::cout << "First:" << ret.first - plainTextVect.begin()
                      << "Second:" << ret.second - plainTextOut.begin()
                      << std::endl;
#endif
        }
}
#endif

#if 0
TEST(CBC, RandomEncryptDecryptTest)
{
    Uint8 key_256[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    std::vector<Uint8> plainText_vect(16, 0);
    std::vector<Uint8> cipherText_vect(16, 1);
    std::vector<Uint8> exp_cipherText = { 0xb0, 0x7d, 0x4f, 0x3e, 0x2c, 0xd2,
                                          0xef, 0x2e, 0xb5, 0x45, 0x98, 0x07,
                                          0x54, 0xdf, 0xea, 0x0f };
    const Uint8        iv[16]         = {};

    // Fill buffer with random data
    // std::unique_ptr<IRandomize> random = std::make_unique<Randomize>(12);
    // random->getRandomBytes(plainText_vect);
    // random->getRandomBytes(cipherText_vect);

    // std::vector<CpuCipherFeatures> cpuFeatures = getSupportedFeatures();
    std::vector<CpuCipherFeatures> cpuFeatures = {
        CpuCipherFeatures::eVaes512,
    };

    // for (int i = 100000; i > 16; i -= 16)
    int i = 0;
    for (CpuCipherFeatures feature : cpuFeatures) {
#if 1
        std::cout
            << "Cpu Feature:"
            << static_cast<
                   typename std::underlying_type<CpuCipherFeatures>::type>(
                   feature)
            << std::endl;
#endif
        // Use buffer back to front to create new test cases from one buffer
        // [ 1 2 3 4 5 6 7 8 9 10]
        const std::vector<Uint8> plainTextVect(plainText_vect.begin() + i,
                                               plainText_vect.end());
        std::vector<Uint8>       plainTextOut(plainTextVect.size());
        std::unique_ptr<ICbc>    cbc =
            CbcFactoryIndirect(feature, key_256, sizeof(key_256) * 8);

        EXPECT_TRUE(cbc.get() != nullptr);

        // cbc->encrypt(
        //     &plainTextVect[0], &cipherText_vect[0], plainTextVect.size(),
        //     iv);

        // cbc = CbcFactoryIndirect(feature, key_256, sizeof(key_256) * 8);

        cbc->decrypt(
            &exp_cipherText[0], &plainTextOut[0], plainTextOut.size(), iv);

        // EXPECT_EQ(cipherText_vect, exp_cipherText);
        EXPECT_EQ(plainTextVect, plainTextOut);
#if 1
        auto ret = std::mismatch(
            plainTextVect.begin(), plainTextVect.end(), plainTextOut.begin());
        std::cout << "First:" << ret.first - plainTextVect.begin()
                  << "Second:" << ret.second - plainTextOut.begin()
                  << std::endl;
#endif
    }
}
#endif

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
