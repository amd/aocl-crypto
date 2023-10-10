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

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <random>

#include "cipher_experimental/factory.hh"
#include "common/experimental/gtest_essentials.hh"

#include "csv.hh"
#include "rng_base.hh"
#include "utils.hh"

using alcp::testing::Csv;

namespace alcp::testing::cipher::gcm {

#if 0
        // Will very from some x to y..
        std::vector<Uint8> datasetPlainText  
        // Intialization vector 96 bits to 128 bits
        std::vector<Uint8> datasetInitvector
        // 128 bites -> 256 bits
        std::vector<Uint8> datasetKey        
        // Same as PT
        std::vector<Uint8> datasetCipherText 
        // Can be less than or equal to 2**64 -1
        std::vector<Uint8> datasetAddData   
        // Tag size 128, 120, 112, 104, or 96 bits. 64 and 32 bits 
        std::vector<Uint8> datasetTag
#endif

struct gcm_test_data
{
    std::vector<Uint8> key;
    std::vector<Uint8> initVector;
    std::vector<Uint8> plainText;
    std::vector<Uint8> cipherText;
    std::vector<Uint8> additionalText;
    std::vector<Uint8> tag;
    Uint64             chunkSize;
};

// FIXME: Performance might be low.
Uint64
genRandom(std::vector<Uint8>& buffer)
{

    static RngBase     rngBase;
    std::vector<Uint8> seed_v = rngBase.genRandomBytes(sizeof(Uint64));
    Uint64             seed;

    std::copy(&seed_v[0],
              &seed_v[0] + seed_v.size(),
              reinterpret_cast<Uint8*>(&seed));

    std::mt19937 mt_rand(seed);
    {
        size_t iter = buffer.size() / 4;
        for (size_t i = 0; i < iter; i++) {
            Uint32 r   = mt_rand();
            Uint8* r_8 = reinterpret_cast<Uint8*>(&r);
            std::copy(r_8, r_8 + 4, (&buffer[0]) + (i * 4));
        }
    }
    int rem = buffer.size() % 4;
    if (rem) {
        Uint32 r   = mt_rand();
        Uint8* r_8 = reinterpret_cast<Uint8*>(&r);
        std::copy(r_8, r_8 + rem, ((&buffer[0]) + (buffer.size() - 1) - rem));
    }

    return seed;
}

/**
 * @brief KAT Driver to test if library passes with given data
 *
 * @param data Input & Output Data
 * @param iTestCipher Actual Kernel Use
 */
template<bool encryptor>
void
GcmCross_KAT(gcm_test_data& data, std::shared_ptr<ITestCipher> iTestCipher)
{
    std::vector<Uint8> datasetPlainText  = data.plainText;
    std::vector<Uint8> datasetInitvector = data.initVector;
    std::vector<Uint8> datasetKey        = data.key;
    std::vector<Uint8> datasetAddData    = data.additionalText;
    std::vector<Uint8> datasetCipherText = data.cipherText;
    std::vector<Uint8> datasetTag        = data.tag;

    // Output Buffers
    std::vector<Uint8> output(
        std::max(datasetPlainText.size(), datasetCipherText.size()), 1);
    std::vector<Uint8> tagbuff(datasetTag.size());

    alc_test_gcm_init_data_t dataInit;
    dataInit.m_iv      = &datasetInitvector[0];
    dataInit.m_iv_len  = datasetInitvector.size();
    dataInit.m_aad     = &datasetAddData[0];
    dataInit.m_aad_len = datasetAddData.size();
    dataInit.m_key     = &datasetKey[0];
    dataInit.m_key_len = datasetKey.size();

    alc_test_gcm_update_data_t dataUpdate;
    dataUpdate.m_iv         = &datasetInitvector[0];
    dataUpdate.m_iv_len     = datasetInitvector.size();
    dataUpdate.m_output     = &output[0];
    dataUpdate.m_output_len = output.size();

    if constexpr (encryptor) { // Encrypt
        dataUpdate.m_input = &datasetPlainText[0];
    } else { // Decrypt
        dataUpdate.m_input = &datasetCipherText[0];
    }
    dataUpdate.m_input_len = data.chunkSize;

    alc_test_gcm_finalize_data_t dataFinalize;
    dataFinalize.m_tag_expected = &datasetTag[0];
    dataFinalize.m_tag_len      = datasetTag.size();
    dataFinalize.m_tag          = &tagbuff[0];
    dataFinalize.m_out          = dataUpdate.m_output; // If needed for padding
    dataFinalize.m_pt_len       = datasetPlainText.size();
    dataFinalize.verified       = false;

    Uint64 chunks, extra_bytes;

    if constexpr (encryptor) {
        chunks      = data.plainText.size() / data.chunkSize;
        extra_bytes = (data.plainText.size() - (chunks * data.chunkSize));
    } else {
        chunks      = data.cipherText.size() / data.chunkSize;
        extra_bytes = (data.cipherText.size() - (chunks * data.chunkSize));
    }

    ASSERT_TRUE(iTestCipher->init(&dataInit));
    for (int i = 0; i < chunks; i++) {
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
        dataUpdate.m_input += data.chunkSize;
        dataUpdate.m_output += data.chunkSize;
    }
    if (extra_bytes) {
        dataUpdate.m_input_len = extra_bytes;
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
    }
    ASSERT_TRUE(iTestCipher->finalize(&dataFinalize));

    if constexpr (encryptor) { // Encrypt
        ASSERT_EQ(output, datasetCipherText);
    } else { // Decrypt
        ASSERT_EQ(output, datasetPlainText);
    }

    ASSERT_EQ(tagbuff, datasetTag);
}

/**
 * @brief Reference Driver to populate actual data
 *
 * @param data Input & Output Data
 * @param iTestCipher Actual Kernel Use
 */
void
GcmCross_REF(gcm_test_data& data, std::shared_ptr<ITestCipher> iTestCipher)
{
    std::vector<Uint8> datasetPlainText  = data.plainText;
    std::vector<Uint8> datasetInitvector = data.initVector;
    std::vector<Uint8> datasetKey        = data.key;
    std::vector<Uint8> datasetAddData    = data.additionalText;

    std::vector<Uint8> tagbuff(data.tag.size());

    alc_test_gcm_init_data_t dataInit;
    dataInit.m_iv      = &datasetInitvector[0];
    dataInit.m_iv_len  = datasetInitvector.size();
    dataInit.m_aad     = &datasetAddData[0];
    dataInit.m_aad_len = datasetAddData.size();
    dataInit.m_key     = &datasetKey[0];
    dataInit.m_key_len = datasetKey.size();

    alc_test_gcm_update_data_t dataUpdate;
    dataUpdate.m_iv         = &datasetInitvector[0];
    dataUpdate.m_iv_len     = datasetInitvector.size();
    dataUpdate.m_output     = &data.cipherText[0];
    dataUpdate.m_output_len = data.cipherText.size();
    dataUpdate.m_input      = &datasetPlainText[0];
    dataUpdate.m_input_len  = data.chunkSize;

    alc_test_gcm_finalize_data_t dataFinalize;
    dataFinalize.m_tag_expected = &data.tag[0];
    dataFinalize.m_tag_len      = data.tag.size();
    dataFinalize.m_tag          = &data.tag[0];
    dataFinalize.m_out          = dataUpdate.m_output; // If needed for padding
    dataFinalize.m_pt_len       = datasetPlainText.size();
    dataFinalize.verified       = false;

    Uint64 chunks      = data.plainText.size() / data.chunkSize;
    Uint64 extra_bytes = (data.plainText.size() - (chunks * data.chunkSize));

    ASSERT_TRUE(iTestCipher->init(&dataInit));
    for (int i = 0; i < chunks; i++) {
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
        dataUpdate.m_input += data.chunkSize;
        dataUpdate.m_output += data.chunkSize;
    }
    if (extra_bytes) {
        dataUpdate.m_input_len = extra_bytes;
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
    }
    ASSERT_TRUE(iTestCipher->finalize(&dataFinalize));
}

void
CrossTestGCM(LibrarySelect select1, LibrarySelect select2)
{
    const std::vector<Uint64> initVectSizes = {
        128, 120, 112, 104, 96
    }; // bits
    const std::vector<Uint64> additionalText_sizes = {
        20000, 128, 120, 112, 104, 96, 64, 32
    };                                                       // bits
    const std::vector<Uint64> key_sizes = { 128, 192, 256 }; // bits
    const std::vector<Uint64> tagSizes  = {
        128, 120, 112, 104, 96, 64, 32
    };                                                         // bits
    const std::vector<Uint64> chunkSizes = { 16, 32 };         // bits
    const std::vector<Uint64> ptSizes    = { 16, 1000, 2563 }; // bytes

    gcm_test_data test_data;

    Uint64 testCount = 0;

    // Constant Plaintext Test
    for (Uint64 key_size : key_sizes) {
        for (Uint64 additionalText_size : additionalText_sizes) {
            for (Uint64 tagSize : tagSizes) {
                for (int initVectSize : initVectSizes) {
                    for (int chunkSize : chunkSizes) {
                        for (int ptSize : ptSizes) {
                            test_data.key = std::vector<Uint8>(key_size / 8);
                            test_data.additionalText =
                                std::vector<Uint8>(additionalText_size / 8);
                            test_data.initVector =
                                std::vector<Uint8>(initVectSize / 8);
                            test_data.plainText = std::vector<Uint8>(ptSize);
                            test_data.cipherText =
                                std::vector<Uint8>(test_data.plainText.size());
                            test_data.tag = std::vector<Uint8>(tagSize / 8);
                            test_data.chunkSize = chunkSize;

                            genRandom(test_data.key);
                            genRandom(test_data.additionalText);
                            genRandom(test_data.initVector);
                            genRandom(test_data.plainText);

                            GcmCross_REF(test_data,
                                         GcmCipherFactory<true>(select1));

                            GcmCross_KAT<true>(test_data,
                                               GcmCipherFactory<true>(select2));

                            GcmCross_KAT<false>(
                                test_data, GcmCipherFactory<false>(select2));

                            testCount++;
                        }
                    }
                }
            }
        }
    }
    std::cout << "Tests Executed:" << testCount << std::endl;
}

// Reference :
// https://google.github.io/googletest/advanced.html#registering-tests-programmatically
class MyFixture : public ::testing::Test
{
  public:
    // All of these optional, just like in regular macro usage.
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
    void        SetUp() override {}
    void        TearDown() override {}
};

class MyTest : public MyFixture
{
  public:
    explicit MyTest(LibrarySelect select1, LibrarySelect select2)
        : _select1(select1)
        , _select2(select2)
    {}
    void TestBody() override { CrossTestGCM(_select1, _select2); }

  private:
    LibrarySelect                _select1, _select2;
    std::unique_ptr<ITestCipher> iTestCipher1, iTestCipher2;
};

void
RegisterMyTests(std::string         testSuiteName,
                std::string         testCaseName,
                const LibrarySelect select1,
                const LibrarySelect select2)
{
    ::testing::RegisterTest(
        testSuiteName.c_str(),
        testCaseName.c_str(),
        nullptr,
        nullptr,
        __FILE__,
        __LINE__,
        // Important to use the fixture type as the return type here.
        [=]() -> MyFixture* { return new MyTest(select1, select2); });
}
} // namespace alcp::testing::cipher::gcm

using namespace alcp::testing::cipher::gcm;
using alcp::testing::cipher::LibrarySelect;
using alcp::testing::utils::ArgsMap;
using alcp::testing::utils::ParamType;
using alcp::testing::utils::parseArgs;

#if 1
int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ArgsMap argsMap = parseArgs(argc, argv);
    assert(argsMap["USE_OSSL"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["USE_IPP"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["OVERRIDE_ALCP"].paramType == ParamType::TYPE_BOOL);
    // ::testing::RegisterTest("KnownAnswerTest",
    // "GCM_Encrypt_experimental", )

#ifdef USE_OSSL
    if (std::get<bool>(argsMap["USE_OSSL"].value)) {
        RegisterMyTests("KnownAnswerTest",
                        "GCM_CROSS_EXPERIMENTAL_OPENSSL",
                        LibrarySelect::OPENSSL,
                        LibrarySelect::ALCP);
    }
#endif

#ifdef USE_IPP
    if (std::get<bool>(argsMap["USE_IPP"].value)) {
        RegisterMyTests("KnownAnswerTest",
                        "GCM_CROSS_EXPERIMENTAL_IPP",
                        LibrarySelect::IPP,
                        LibrarySelect::ALCP);
    }
#endif

    return RUN_ALL_TESTS();
}
#endif
