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

#include "cipher_expiremental/alc_cipher_gcm.hh"
#include "csv.hh"
#include "utils.hh"

using test_data_t = std::map<const std::string, std::vector<Uint8>>;

using alcp::testing::Csv;
using alcp::testing::cipher::ITestCipher;
using namespace alcp::testing::cipher::gcm;

// Expiremental code
#if 0
class GcmParameterizedTestFixture : public ::testing::TestWithParam<test_data_t>
{

    void SetUp() override
    {
        test_data_t kat_vectors = GetParam();
        std::cout << "Key"
                  << alcp::testing::utils::parseBytesToHexStr(
                         &kat_vectors.at("Key")[0], kat_vectors["Key"].size())
                  << std::endl;
    }
    void TearDown() override {}
};

TEST_P(GcmParameterizedTestFixture, GCM) {}

void
GenerateTestsFromCsv(const std::string filename)
{
    Csv csv(filename);

    std::vector<Uint8> datasetPlainText  = csv.getVect("PLAINTEXT");
    std::vector<Uint8> datasetInitvector = csv.getVect("INTVECT");
    std::vector<Uint8> datasetKey        = csv.getVect("KEY");
    std::vector<Uint8> datasetCipherText = csv.getVect("CIPHERTEXT");
    std::vector<Uint8> datasetAddData    = csv.getVect("ADDITIONAL_DATA");
    std::vector<Uint8> datasetTag        = csv.getVect("TAG");

    test_data_t datasetMap;
    datasetMap["PT"]   = datasetPlainText;
    datasetMap["INIT"] = datasetInitvector;
    datasetMap["KEY"]  = datasetKey;
    datasetMap["CT"]   = datasetCipherText;
    datasetMap["ADD"]  = datasetAddData;
    datasetMap["TAG"]  = datasetTag;

    ::testing::RegisterTest("GcmParameterizedTestFixture",
                            "GCM",
                            filename.c_str(),
                            ::testing::internal::MapGenerator < datasetMap);
}
#endif

template<bool encryptor>
void
GcmKat(const std::string filename)
{
    Csv csv(filename);

    while (csv.readNext()) {

        std::vector<Uint8> datasetPlainText  = csv.getVect("PLAINTEXT");
        std::vector<Uint8> datasetInitvector = csv.getVect("INITVECT");
        std::vector<Uint8> datasetKey        = csv.getVect("KEY");
        std::vector<Uint8> datasetCipherText = csv.getVect("CIPHERTEXT");
        std::vector<Uint8> datasetAddData    = csv.getVect("ADDITIONAL_DATA");
        std::vector<Uint8> datasetTag        = csv.getVect("TAG");

        // Output Buffers
        std::vector<Uint8> output(
            std::max(datasetPlainText.size(), datasetCipherText.size()), 1);
        std::vector<Uint8>           tagbuff(datasetTag.size());
        std::unique_ptr<ITestCipher> iTestCipher =
            std::make_unique<AlcpGcmCipher<encryptor>>();
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
            dataUpdate.m_input     = &datasetPlainText[0];
            dataUpdate.m_input_len = datasetPlainText.size();
        } else { // Decrypt
            dataUpdate.m_input     = &datasetCipherText[0];
            dataUpdate.m_input_len = datasetCipherText.size();
        }

        alc_test_gcm_finalize_data_t dataFinalize;
        dataFinalize.m_tag_expected = &datasetTag[0];
        dataFinalize.m_tag_len      = datasetTag.size();
        dataFinalize.m_tag          = &tagbuff[0];
        dataFinalize.verified       = false;

        ASSERT_TRUE(iTestCipher->init(&dataInit));
        ASSERT_TRUE(iTestCipher->update(&dataUpdate));
        ASSERT_TRUE(iTestCipher->finalize(&dataFinalize));

        if constexpr (encryptor) { // Encrypt
            ASSERT_EQ(output, datasetCipherText);
        } else { // Decrypt
            ASSERT_EQ(output, datasetPlainText);
        }

        ASSERT_EQ(tagbuff, datasetTag);
    }
}

TEST(KnownAnswerTest, GCM_Encrypt_Expiremental)
{
    GcmKat<true>("dataset_gcm.csv");
}

TEST(KnownAnswerTest, GCM_Decrypt_Expiremental)
{
    GcmKat<false>("dataset_gcm.csv");
}

#if 1
int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
