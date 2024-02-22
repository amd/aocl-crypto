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

namespace alcp::testing::cipher::xts {

struct xts_test_data
{
    std::vector<Uint8> key;
    std::vector<Uint8> initVector;
    std::vector<Uint8> plainText;
    std::vector<Uint8> cipherText;
    Uint64             chunkSize;
};

/**
 * @brief KAT Driver to test if library passes with given data
 *
 * @param data Input & Output Data
 * @param iTestCipher Actual Kernel Use
 */
template<bool encryptor>
void
XtsCross_KAT(xts_test_data& data, std::shared_ptr<ITestCipher> iTestCipher)
{
    std::vector<Uint8> datasetPlainText  = data.plainText;
    std::vector<Uint8> datasetInitvector = data.initVector;
    std::vector<Uint8> datasetKey        = data.key;
    std::vector<Uint8> datasetCipherText = data.cipherText;

    // Output Buffers
    std::vector<Uint8> output(
        std::max(datasetPlainText.size(), datasetCipherText.size()), 1);

    alc_test_xts_init_data_t data_init = {};
    data_init.m_iv                     = &datasetInitvector[0];
    data_init.m_iv_len                 = datasetInitvector.size();
    data_init.m_key                    = &datasetKey[0];
    data_init.m_key_len                = datasetKey.size() / 2;

    alc_test_xts_update_data_t data_update = {};
    data_update.m_iv                       = &datasetInitvector[0];
    data_update.m_iv_len                   = datasetInitvector.size();
    data_update.m_output                   = &output[0];
    data_update.m_output_len               = output.size();
    data_update.m_total_input_len          = datasetPlainText.size();
    data_update.m_aes_block_id             = 0;

    if constexpr (encryptor) { // Encrypt
        data_update.m_input = &datasetPlainText[0];
    } else { // Decrypt
        data_update.m_input = &datasetCipherText[0];
    }
    data_update.m_input_len = data.chunkSize;

    alc_test_xts_finalize_data_t data_finalize = {};
    data_finalize.m_out    = data_update.m_output; // If needed for padding
    data_finalize.m_pt_len = datasetPlainText.size();
    data_finalize.verified = false;

    Uint64 chunks = 0, extra_bytes = 0;

    if constexpr (encryptor) {
        chunks      = data.plainText.size() / data.chunkSize;
        extra_bytes = (data.plainText.size() - (chunks * data.chunkSize));
    } else {
        chunks      = data.cipherText.size() / data.chunkSize;
        extra_bytes = (data.cipherText.size() - (chunks * data.chunkSize));
    }

    Uint64 blocks_per_chunk = data.chunkSize / 16;

    if (extra_bytes) {
        if (chunks) {
            chunks -= 1;
            extra_bytes += data.chunkSize;
        }
    }

    ASSERT_TRUE(iTestCipher->init(&data_init));
    for (int i = 0; i < chunks; i++) {
        ASSERT_TRUE(iTestCipher->update(&data_update));
        data_update.m_input += data.chunkSize;
        data_update.m_output += data.chunkSize;
        data_update.m_aes_block_id += blocks_per_chunk;
    }
    if (extra_bytes) {
        data_update.m_input_len = extra_bytes;
        ASSERT_TRUE(iTestCipher->update(&data_update));
    }
    ASSERT_TRUE(iTestCipher->finalize(&data_finalize));

    if constexpr (encryptor) { // Encrypt
#if 0
        auto ret = std::mismatch(
            output.begin(), output.end(), datasetCipherText.begin());
        std::cout << "First:" << ret.first - output.begin()
                  << "Second:" << ret.second - datasetCipherText.begin()
                  << std::endl;
        if (ret.first != output.end()) {
            std::cout << "PlainText:"
                      << utils::parseBytesToHexStr(&datasetPlainText[0],
                                                   datasetPlainText.size())
                      << std::endl;
            std::cout << "IV:"
                      << utils::parseBytesToHexStr(&datasetInitvector[0],
                                                   datasetInitvector.size())
                      << std::endl;
            std::cout << "Key:"
                      << utils::parseBytesToHexStr(&datasetKey[0],
                                                   datasetKey.size())
                      << std::endl;
            std::cout << "Expected CT:"
                      << utils::parseBytesToHexStr(&datasetCipherText[0],
                                                   datasetCipherText.size())
                      << std::endl;
            std::cout << "Observed CT:"
                      << utils::parseBytesToHexStr(&output[0], output.size())
                      << std::endl;
            std::cout << "Chunk Size:" << data.chunkSize << std::endl;
            std::cout << "Test is going to fail now, you better put a break "
                         "point here!"
                      << std::endl;
        }
#endif
        ASSERT_EQ(output, datasetCipherText);
    } else { // Decrypt
        // ASSERT_EQ(output, datasetPlainText);
    }
}

/**
 * @brief Reference Driver to populate actual data
 *
 * @param data Input & Output Data
 * @param iTestCipher Actual Kernel Use
 */
void
XtsCross_REF(xts_test_data& data, std::shared_ptr<ITestCipher> iTestCipher)
{
    std::vector<Uint8> dataset_plain_text = data.plainText;
    std::vector<Uint8> dataset_initvector = data.initVector;
    std::vector<Uint8> dataset_key        = data.key;

    alc_test_xts_init_data_t data_init = {};
    data_init.m_iv                     = &dataset_initvector[0];
    data_init.m_iv_len                 = dataset_initvector.size();
    data_init.m_key                    = &dataset_key[0];
    data_init.m_key_len                = dataset_key.size() / 2;

    alc_test_xts_update_data_t data_update = {};
    data_update.m_iv                       = &dataset_initvector[0];
    data_update.m_iv_len                   = dataset_initvector.size();
    data_update.m_output                   = &data.cipherText[0];
    data_update.m_output_len               = data.cipherText.size();
    data_update.m_input                    = &dataset_plain_text[0];
    data_update.m_input_len                = dataset_plain_text.size();
    data_update.m_total_input_len          = dataset_plain_text.size();
    data_update.m_aes_block_id             = 0;

    alc_test_xts_finalize_data_t data_finalize = {};
    data_finalize.m_out    = data_update.m_output; // If needed for padding
    data_finalize.m_pt_len = dataset_plain_text.size();
    data_finalize.verified = false;

    ASSERT_TRUE(iTestCipher->init(&data_init));
    ASSERT_TRUE(iTestCipher->update(&data_update));
    ASSERT_TRUE(iTestCipher->finalize(&data_finalize));
}

void
CrossTestXTS(std::shared_ptr<RngBase> rng,
             LibrarySelect            select1,
             LibrarySelect            select2)
{
    const std::vector<Uint64> cKeySizes   = { 128, 256 }; // bits // bits
    const std::vector<Uint64> cChunkSizes = { 32, 64 };   // bits
    const std::vector<Uint64> cPtSizes    = { 16, 1000, 8192, 65536 }; // bytes

    xts_test_data test_data = {};

    Uint64 test_count = 0;

    // Constant Plaintext Test
    for (Uint64 key_size : cKeySizes) {
        for (int chunk_size : cChunkSizes) {
            for (int pt_size : cPtSizes) {
                test_data.key = std::vector<Uint8>((key_size / 8) * 2, 0);
                test_data.initVector = std::vector<Uint8>(16, 1);
                test_data.plainText  = std::vector<Uint8>(pt_size, 2);
                test_data.cipherText =
                    std::vector<Uint8>(test_data.plainText.size(), 3);
                test_data.chunkSize = chunk_size;

                rng->genRandomMt19937(test_data.key);
                rng->genRandomMt19937(test_data.initVector);
                rng->genRandomMt19937(test_data.plainText);

                XtsCross_REF(test_data, XtsCipherFactory<true>(select1));

                XtsCross_KAT<true>(test_data, XtsCipherFactory<true>(select2));

                XtsCross_KAT<false>(test_data,
                                    XtsCipherFactory<false>(select2));

                test_count++;
            }
            // break;
        }
        // break;
    }

    const Uint64 pt_min_size = 16;
    const Uint64 pt_max_size = 160000;
    const Uint64 pt_dec_size = 31;

    const Uint64 cKeySize   = cKeySizes.back();
    const Uint64 cChunkSize = cChunkSizes.back();

    test_data.key        = std::vector<Uint8>(cKeySize / 8);
    test_data.initVector = std::vector<Uint8>(16);
    test_data.plainText  = std::vector<Uint8>(pt_max_size);
    test_data.chunkSize  = cChunkSize;
    for (int pt_size = pt_max_size; pt_size >= pt_min_size;
         pt_size -= pt_dec_size) {

        // Change size without reallocation
        test_data.plainText.resize(pt_size);
        test_data.plainText.shrink_to_fit();
        test_data.cipherText.resize(pt_size);
        test_data.cipherText.shrink_to_fit();

        rng->genRandomMt19937(test_data.key);
        rng->genRandomMt19937(test_data.initVector);
        rng->genRandomMt19937(test_data.plainText);

        XtsCross_REF(test_data, XtsCipherFactory<true>(select1));

        XtsCross_KAT<true>(test_data, XtsCipherFactory<true>(select2));

        XtsCross_KAT<false>(test_data, XtsCipherFactory<false>(select2));

        test_count++;
    }
    std::cout << "Tests Executed:" << test_count << std::endl;
}

// Reference :
// https://google.github.io/googletest/advanced.html#registering-tests-programmatically

// FIXME: We can move glow code to common code
class CrossTestFixture : public ::testing::Test
{
  public:
    // All of these optional, just like in regular macro usage.
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
    void        SetUp() override {}
    void        TearDown() override {}
};

class CrossTest : public CrossTestFixture
{
  public:
    explicit CrossTest(std::shared_ptr<RngBase> rng,
                       LibrarySelect            select1,
                       LibrarySelect            select2)
        : _select1(select1)
        , _select2(select2)
    {
        _rng = rng;
    }
    void TestBody() override { CrossTestXTS(_rng, _select1, _select2); }

  private:
    LibrarySelect                _select1, _select2;
    std::shared_ptr<RngBase>     _rng;
    std::unique_ptr<ITestCipher> iTestCipher1, iTestCipher2;
};

void
RegisterMyTests(std::string              testSuiteName,
                std::string              testCaseName,
                std::shared_ptr<RngBase> rng,
                const LibrarySelect      select1,
                const LibrarySelect      select2)
{
    ::testing::RegisterTest(
        testSuiteName.c_str(),
        testCaseName.c_str(),
        nullptr,
        nullptr,
        __FILE__,
        __LINE__,
        // Important to use the fixture type as the return type here.
        [=]() -> CrossTestFixture* {
            return new CrossTest(rng, select1, select2);
        });
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

    std::shared_ptr<alcp::testing::RngBase> rng =
        std::make_shared<alcp::testing::RngBase>();

    // std::cout << rng->getSeedMt19937() << std::endl;

    rng->setSeedMt19937(16663322004200655032ULL);

    ArgsMap argsMap = parseArgs(argc, argv);
    assert(argsMap["USE_OSSL"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["USE_IPP"].paramType == ParamType::TYPE_BOOL);
    assert(argsMap["OVERRIDE_ALCP"].paramType == ParamType::TYPE_BOOL);

    /* if no ext lib provided, openssl selected by default */
    if (std::get<bool>(argsMap["USE_OSSL"].value) == false
        && (std::get<bool>(argsMap["USE_IPP"].value) == false)) {
        argsMap["USE_OSSL"].value = true;
    }

    if (std::get<bool>(argsMap["OVERRIDE_ALCP"].value)) {
#ifdef USE_OSSL
#ifdef USE_IPP
        RegisterMyTests("KnownAnswerTest",
                        "XTS_CROSS_EXPERIMENTAL_OPENSSL_IPP",
                        rng,
                        LibrarySelect::OPENSSL,
                        LibrarySelect::IPP);
#endif
#endif

    } else {

#ifdef USE_OSSL
        if (std::get<bool>(argsMap["USE_OSSL"].value)) {
            RegisterMyTests("KnownAnswerTest",
                            "XTS_CROSS_EXPERIMENTAL_OPENSSL",
                            rng,
                            LibrarySelect::OPENSSL,
                            LibrarySelect::ALCP);
        }
#endif

#ifdef USE_IPP
        if (std::get<bool>(argsMap["USE_IPP"].value)) {
            RegisterMyTests("KnownAnswerTest",
                            "XTS_CROSS_EXPERIMENTAL_IPP",
                            rng,
                            LibrarySelect::IPP,
                            LibrarySelect::ALCP);
        }
#endif
    }
    return RUN_ALL_TESTS();
}
#endif
