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
template<utils::CpuCipherFeatures features>
std::unique_ptr<ICbc>
CbcFactory(const Uint8 key[], Uint32 keylen)
{
    std::unique_ptr<ICbc> cbc;
    if constexpr (features == utils::CpuCipherFeatures::eAesni) {
        cbc = std::make_unique<Cbc<aesni::EncryptCbc128, aesni::DecryptCbc128>>(
            key,
            keylen); // Create
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes256) {
        cbc = std::make_unique<Cbc<aesni::EncryptCbc128, vaes::DecryptCbc128>>(
            key,
            keylen); // Create
    } else if constexpr (features == utils::CpuCipherFeatures::eVaes512) {
        cbc =
            std::make_unique<Cbc<aesni::EncryptCbc128, vaes512::DecryptCbc128>>(
                key,
                keylen); // Create
    } else if constexpr (features == utils::CpuCipherFeatures::eDynamic) {
        CpuId                           cpu;
        static utils::CpuCipherFeatures maxFeature = getMaxFeature();
        if (maxFeature == utils::CpuCipherFeatures::eVaes512) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes512>(key, keylen);
        } else if (maxFeature == utils::CpuCipherFeatures::eVaes256) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eVaes256>(key, keylen);
        } else if (maxFeature == utils::CpuCipherFeatures::eAesni) {
            cbc = CbcFactory<utils::CpuCipherFeatures::eAesni>(key, keylen);
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
    if (features == CpuCipherFeatures::eVaes512) {
        return CbcFactory<CpuCipherFeatures::eVaes512>(key, keylen);
    } else if (features == CpuCipherFeatures::eVaes256) {
        return CbcFactory<CpuCipherFeatures::eVaes256>(key, keylen);
    } else if (features == CpuCipherFeatures::eAesni) {
        return CbcFactory<CpuCipherFeatures::eAesni>(key, keylen);
    } else {
        return CbcFactory<CpuCipherFeatures::eReference>(key, keylen);
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
    std::unique_ptr<ICbc> cbc =
        CbcFactory<c_CpuFeatureSelect>(&key[0], key.size() * 8);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(cipherText.size());

    cbc->encrypt(&plainText[0], &output[0], plainText.size(), &iv[0]);

    EXPECT_EQ(cipherText, output);
}

TEST(CBC, BasicDecryption)
{
    std::unique_ptr<ICbc> cbc =
        CbcFactory<c_CpuFeatureSelect>(&key[0], key.size() * 8);

    EXPECT_TRUE(cbc.get() != nullptr);

    std::vector<Uint8> output(plainText.size());

    cbc->decrypt(&cipherText[0], &output[0], cipherText.size(), &iv[0]);

    EXPECT_EQ(plainText, output);
}

#if 1
TEST(CBC, RandomEncryptDecryptTest)
{
    Uint8              key[32];
    std::vector<Uint8> plainText(100000);
    std::vector<Uint8> cipherText(100000);
    Uint8              iv[16];

    // Fill buffer with random data
    std::unique_ptr<IRandomize> random = std::make_unique<Randomize>();
    random->getRandomBytes(plainText);
    random->getRandomBytes(cipherText);

    std::vector<CpuCipherFeatures> cpuFeatures = getSupportedFeatures();

    for (int i = 100000; i > 16; i -= 16)
        for (CpuCipherFeatures feature : cpuFeatures) {
            // Use buffer back to front to create new test cases from one buffer
            std::vector<Uint8>    plainTextVect(plainText.begin() + i,
                                             plainText.end());
            std::vector<Uint8>    plainTextOut(plainTextVect.size());
            std::unique_ptr<ICbc> cbc =
                CbcFactoryIndirect(feature, key, sizeof(key) * 8);

            EXPECT_TRUE(cbc.get() != nullptr);

            cbc->encrypt(
                &plainTextVect[0], &cipherText[0], plainTextVect.size(), iv);

            cbc->decrypt(
                &cipherText[0], &plainTextOut[0], plainTextVect.size(), iv);

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

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
