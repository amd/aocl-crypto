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

uint8_t
hexToNum(unsigned char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9') 
        return c - '0';

    return 0;
}

/*
 * TODO: move this to base.hh once other functions are ready
 */
const std::string
hexStringToBytesNew(const std::string& hexStr)
{
    std::stringstream ss;
    int len = hexStr.size();
    const char *cstr = hexStr.c_str();

    for (int i = 0; i < len; i+=2) {
        uint8_t val = hexToNum(cstr[0]) << 4 | hexToNum(cstr[1]);
        cstr +=2;
        ss << std::hex << val;
    }

    return ss.str();
}


/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_KnownAnsTest)
{
    const int key_size = 128;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        auto key                 = hexStringToBytesNew(ds.getKey());
        auto iv                  = hexStringToBytesNew(ds.getIv());
        auto plaintext           = hexStringToBytes(ds.getPt());
        auto expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];

        //std::cout << "key: " << key.c_str() << std::endl << "key1: " << key1 << std::endl;

        // Encrypt data with above params
        cipherHander.testingEncrypt(
            plaintext, plaintext_len, 
            (uint8_t*)key.c_str(), 
            key_size, 
            (uint8_t*)iv.c_str(), 
            ciphertext);
        ciphertext_len = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_128_ENC")));
        //delete[] key;
        //delete[] iv;
        //delete[] plaintext;
        //delete[] expected_ciphertext;
    }
}
#if 0
TEST(SYMMETRIC_ENC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key                 = hexStringToBytes(ds.getKey());
        unsigned char* iv                  = hexStringToBytes(ds.getIv());
        unsigned char* plaintext           = hexStringToBytes(ds.getPt());
        unsigned char* expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];

        // Encrypt data with above params
        cipherHander.testingEncrypt(
            plaintext, plaintext_len, key, key_size, iv, ciphertext);
        ciphertext_len = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_192_ENC")));
        delete[] key;
        delete[] iv;
        delete[] plaintext;
        delete[] expected_ciphertext;
    }
}

TEST(SYMMETRIC_ENC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key                 = hexStringToBytes(ds.getKey());
        unsigned char* iv                  = hexStringToBytes(ds.getIv());
        unsigned char* plaintext           = hexStringToBytes(ds.getPt());
        unsigned char* expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];

        // Encrypt data with above params
        cipherHander.testingEncrypt(
            plaintext, plaintext_len, key, key_size, iv, ciphertext);
        ciphertext_len = plaintext_len;

        // Check if output is correct
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_256_ENC")));
        delete[] key;
        delete[] iv;
        delete[] plaintext;
        delete[] expected_ciphertext;
    }
}

TEST(SYMMETRIC_DEC_128, 128_KnownAnsTest)
{
    const int key_size = 128;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];

        // Decrypt data with above params
        cipherHander.testingDecrypt(
            ciphertext, ciphertext_len, key, key_size, iv, decryptedtext);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                ciphertext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_128_DEC")));
        delete[] key;
        delete[] iv;
        delete[] plaintext;
        delete[] ciphertext;
    }
}

TEST(SYMMETRIC_DEC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];

        // Decrypt data with above params
        cipherHander.testingDecrypt(
            ciphertext, ciphertext_len, key, key_size, iv, decryptedtext);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                ciphertext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_192_DEC")));
        delete[] key;
        delete[] iv;
        delete[] plaintext;
        delete[] ciphertext;
    }
}

TEST(SYMMETRIC_DEC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_cbc.csv");

    // Initialize cipher testing classes
    AlcpCipherTesting cipherHander =
        AlcpCipherTesting(ALC_AES_MODE_CBC, nullptr);

    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];

        // Decrypt data with above params
        cipherHander.testingDecrypt(
            ciphertext, ciphertext_len, key, key_size, iv, decryptedtext);
        decryptedtext_len = ciphertext_len;

        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                ciphertext_len,
                                ds.getLineNumber(),
                                std::string("AES_CBC_256_DEC")));
        delete[] key;
        delete[] iv;
        delete[] plaintext;
        delete[] ciphertext;
    }
}
#endif

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
