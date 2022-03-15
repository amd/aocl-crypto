/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alc_base.hh"
#include "base.hh"
#include "gtest_base.hh"

using namespace alcp::testing;

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_KnownAnsTest)
{
    const int key_size = 128;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        auto key                 = ds.getKey();
        auto iv                  = ds.getIv();
        auto plaintext           = ds.getPt();
        auto expected_ciphertext = ds.getCt();
        int  ciphertext_len, plaintext_len = ds.getPt().size();

        // Encrypt data with above params
        auto ciphertext = cipherHander.testingEncrypt(plaintext, key, iv);
        ciphertext_len  = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                ds,
                                std::string("AES_OFB_128_ENC")));
    }
}

TEST(SYMMETRIC_ENC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        auto key                 = ds.getKey();
        auto iv                  = ds.getIv();
        auto plaintext           = ds.getPt();
        auto expected_ciphertext = ds.getCt();
        int  ciphertext_len, plaintext_len = ds.getPt().size();

        // Encrypt data with above params
        auto ciphertext = cipherHander.testingEncrypt(plaintext, key, iv);
        ciphertext_len  = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                ds,
                                std::string("AES_OFB_192_ENC")));
    }
}

TEST(SYMMETRIC_ENC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        auto key                 = ds.getKey();
        auto iv                  = ds.getIv();
        auto plaintext           = ds.getPt();
        auto expected_ciphertext = ds.getCt();
        int  ciphertext_len, plaintext_len = ds.getPt().size();

        // Encrypt data with above params
        auto ciphertext = cipherHander.testingEncrypt(plaintext, key, iv);
        ciphertext_len  = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                ds,
                                std::string("AES_OFB_256_ENC")));
    }
}

TEST(SYMMETRIC_DEC_128, 128_KnownAnsTest)
{
    const int key_size = 128;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        std::vector<uint8_t> key        = ds.getKey();
        std::vector<uint8_t> iv         = ds.getIv();
        std::vector<uint8_t> plaintext  = ds.getPt();
        std::vector<uint8_t> ciphertext = ds.getCt();
        int decryptedtext_len, ciphertext_len = ds.getCt().size();
        std::vector<uint8_t> decryptedtext;

        // Decrypt data with above params
        decryptedtext     = cipherHander.testingDecrypt(ciphertext, key, iv);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(
            decryptedtext, plaintext, ds, std::string("AES_OFB_128_DEC")));
    }
}

TEST(SYMMETRIC_DEC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        std::vector<uint8_t> key        = ds.getKey();
        std::vector<uint8_t> iv         = ds.getIv();
        std::vector<uint8_t> plaintext  = ds.getPt();
        std::vector<uint8_t> ciphertext = ds.getCt();
        int decryptedtext_len, ciphertext_len = ds.getCt().size();
        std::vector<uint8_t> decryptedtext;

        // Decrypt data with above params
        decryptedtext     = cipherHander.testingDecrypt(ciphertext, key, iv);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(
            decryptedtext, plaintext, ds, std::string("AES_OFB_192_DEC")));
    }
}

TEST(SYMMETRIC_DEC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_ofb.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_OFB, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        std::vector<uint8_t> key        = ds.getKey();
        std::vector<uint8_t> iv         = ds.getIv();
        std::vector<uint8_t> plaintext  = ds.getPt();
        std::vector<uint8_t> ciphertext = ds.getCt();
        int decryptedtext_len, ciphertext_len = ds.getCt().size();
        std::vector<uint8_t> decryptedtext;

        // Decrypt data with above params
        decryptedtext     = cipherHander.testingDecrypt(ciphertext, key, iv);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(
            decryptedtext, plaintext, ds, std::string("AES_OFB_256_DEC")));
    }
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    parseArgs(argc, argv);
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
