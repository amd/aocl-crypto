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

#include "cipher_experimental/factory.hh"
#include "common/experimental/gtest_essentials.hh"

#include "csv.hh"
#include "utils.hh"

// #include "gtest"

using alcp::testing::Csv;

namespace alcp::testing::cipher::xts {

template<bool encryptor>
void
xtsKat(const std::string filename, std::unique_ptr<ITestCipher> iTestCipher)
{
    Csv csv(filename);

    while (csv.readNext()) {

        std::vector<Uint8> datasetPlainText  = csv.getVect("PLAINTEXT");
        std::vector<Uint8> datasetInitvector = csv.getVect("INITVECT");
        std::vector<Uint8> datasetKey        = csv.getVect("KEY");
        std::vector<Uint8> datasetCipherText = csv.getVect("CIPHERTEXT");
        std::vector<Uint8> datasetTweakKey   = csv.getVect("TWEAK_KEY");

        // Output Buffers
        std::vector<Uint8> output(
            std::max(datasetPlainText.size(), datasetCipherText.size()), 1);

        std::vector<Uint8> combinedKey = datasetKey;
        combinedKey.insert(
            combinedKey.end(), datasetTweakKey.begin(), datasetTweakKey.end());

        alc_test_xts_init_data_t dataInit;
        dataInit.m_iv      = &datasetInitvector[0];
        dataInit.m_iv_len  = datasetInitvector.size();
        dataInit.m_key     = &combinedKey[0]; // Combined Enc and Tweak Key
        dataInit.m_key_len = datasetKey.size();

        alc_test_xts_update_data_t dataUpdate;
        dataUpdate.m_iv           = &datasetInitvector[0];
        dataUpdate.m_iv_len       = datasetInitvector.size();
        dataUpdate.m_output       = &output[0];
        dataUpdate.m_output_len   = output.size();
        dataUpdate.m_aes_block_id = 0;
        if constexpr (encryptor) { // Encrypt
            dataUpdate.m_input     = &datasetPlainText[0];
            dataUpdate.m_input_len = datasetPlainText.size();
        } else { // Decrypt
            dataUpdate.m_input     = &datasetCipherText[0];
            dataUpdate.m_input_len = datasetCipherText.size();
        }

        alc_test_xts_finalize_data_t dataFinalize;
        dataFinalize.m_out    = dataUpdate.m_output; // If needed for padding
        dataFinalize.m_pt_len = datasetPlainText.size();
        dataFinalize.verified = false;

        ASSERT_TRUE(iTestCipher->init(&dataInit));
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
        ASSERT_TRUE(iTestCipher->finalize(&dataFinalize));

        if constexpr (encryptor) { // Encrypt
            ASSERT_EQ(output, datasetCipherText);
        } else { // Decrypt
            ASSERT_EQ(output, datasetPlainText);
        }
    }
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

template<bool encryptor>
class MyTest : public MyFixture
{
  public:
    explicit MyTest(LibrarySelect data)
        : data_(data)
    {
        iTestCipher = XtsCipherFactory<encryptor>(data);
    }
    void TestBody() override
    {
        if (iTestCipher == nullptr) {
            FAIL() << "Requested Library object could not be initialized!";
        }
        xtsKat<encryptor>("dataset_xts.csv", std::move(iTestCipher));
    }

  private:
    LibrarySelect                data_;
    std::unique_ptr<ITestCipher> iTestCipher;
};

template<bool encryptor>
void
RegisterMyTests(std::string         testSuiteName,
                std::string         testCaseName,
                const LibrarySelect value)
{
    ::testing::RegisterTest(
        testSuiteName.c_str(),
        testCaseName.c_str(),
        nullptr,
        nullptr,
        __FILE__,
        __LINE__,
        // Important to use the fixture type as the return type here.
        [=]() -> MyFixture* { return new MyTest<encryptor>(value); });
}
} // namespace alcp::testing::cipher::xts

using namespace alcp::testing::cipher::xts;
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
    // "xts_Encrypt_experimental", )
    if (std::get<bool>(argsMap["USE_OSSL"].value) == false
        && std::get<bool>(argsMap["USE_IPP"].value) == false) {
        RegisterMyTests<true>("KnownAnswerTest",
                              "XTS_Encrypt_experimental_ALCP",
                              LibrarySelect::ALCP);
        RegisterMyTests<false>("KnownAnswerTest",
                               "XTS_Decrypt_experimental_ALCP",
                               LibrarySelect::ALCP);
    }
#if 0
#ifdef USE_OSSL
    if (std::get<bool>(argsMap["USE_OSSL"].value)) {
        RegisterMyTests<true>("KnownAnswerTest",
                              "xts_Encrypt_experimental_OPENSSL",
                              LibrarySelect::OPENSSL);
        RegisterMyTests<false>("KnownAnswerTest",
                               "xts_Decrypt_experimental_OPENSSL",
                               LibrarySelect::OPENSSL);
    }
#endif

#ifdef USE_IPP
    if (std::get<bool>(argsMap["USE_IPP"].value)) {
        RegisterMyTests<true>("KnownAnswerTest",
                              "xts_Encrypt_experimental_IPP",
                              LibrarySelect::IPP);
        RegisterMyTests<false>("KnownAnswerTest",
                               "xts_Decrypt_experimental_IPP",
                               LibrarySelect::IPP);
    }
#endif
#endif

    return RUN_ALL_TESTS();
}
#endif
