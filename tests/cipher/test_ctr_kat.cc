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
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key                 = hexStringToBytes(ds.getKey());
        unsigned char* iv                  = hexStringToBytes(ds.getIv());
        unsigned char* plaintext           = hexStringToBytes(ds.getPt());
        unsigned char* expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];
        alcp_encrypt_data(plaintext,
                          plaintext_len,
                          key,
                          key_size,
                          iv,
                          ciphertext,
                          ALC_AES_MODE_CTR);
        ciphertext_len = plaintext_len;
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CTR_128_ENC")));
        free(key);
        free(iv);
        free(plaintext);
    }
}

TEST(SYMMETRIC_ENC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key                 = hexStringToBytes(ds.getKey());
        unsigned char* iv                  = hexStringToBytes(ds.getIv());
        unsigned char* plaintext           = hexStringToBytes(ds.getPt());
        unsigned char* expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];
        alcp_encrypt_data(plaintext,
                          plaintext_len,
                          key,
                          key_size,
                          iv,
                          ciphertext,
                          ALC_AES_MODE_CTR);
        ciphertext_len = plaintext_len;
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CTR_192_ENC")));
        free(key);
        free(iv);
        free(plaintext);
    }
}

TEST(SYMMETRIC_ENC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key                 = hexStringToBytes(ds.getKey());
        unsigned char* iv                  = hexStringToBytes(ds.getIv());
        unsigned char* plaintext           = hexStringToBytes(ds.getPt());
        unsigned char* expected_ciphertext = hexStringToBytes(ds.getCt());
        int            ciphertext_len, plaintext_len = ds.getPt().size() / 2;
        unsigned char  ciphertext[plaintext_len];
        alcp_encrypt_data(plaintext,
                          plaintext_len,
                          key,
                          key_size,
                          iv,
                          ciphertext,
                          ALC_AES_MODE_CTR);
        ciphertext_len = plaintext_len;
        EXPECT_TRUE(ArraysMatch(ciphertext,
                                expected_ciphertext,
                                plaintext_len,
                                ds.getLineNumber(),
                                std::string("AES_CTR_256_ENC")));
        free(key);
        free(iv);
        free(plaintext);
    }
}

TEST(SYMMETRIC_DEC_128, 128_KnownAnsTest)
{
    const int key_size = 128;
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];
        alcp_decrypt_data(ciphertext,
                          ciphertext_len,
                          key,
                          key_size,
                          iv,
                          decryptedtext,
                          ALC_AES_MODE_CTR);
        decryptedtext_len = ciphertext_len;
        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                ciphertext_len,
                                ds.getLineNumber(),
                                std::string("AES_CTR_128_DEC")));
        free(key);
        free(iv);
        free(plaintext);
    }
}

TEST(SYMMETRIC_DEC_192, 192_KnownAnsTest)
{
    const int key_size = 192;
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];
        alcp_decrypt_data(ciphertext,
                          ciphertext_len,
                          key,
                          key_size,
                          iv,
                          decryptedtext,
                          ALC_AES_MODE_CTR);
        decryptedtext_len = ciphertext_len;
        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                16,
                                ds.getLineNumber(),
                                std::string("AES_CTR_192_DEC")));
        free(key);
        free(iv);
        free(plaintext);
    }
}

TEST(SYMMETRIC_DEC_256, 256_KnownAnsTest)
{
    const int key_size = 256;
    DataSet   ds       = DataSet("dataset_ctr.csv");
    while (ds.readPtIvKeyCt(key_size)) {
        unsigned char* key        = hexStringToBytes(ds.getKey());
        unsigned char* iv         = hexStringToBytes(ds.getIv());
        unsigned char* plaintext  = hexStringToBytes(ds.getPt());
        unsigned char* ciphertext = hexStringToBytes(ds.getCt());
        int           decryptedtext_len, ciphertext_len = ds.getCt().size() / 2;
        unsigned char decryptedtext[ciphertext_len];
        alcp_decrypt_data(ciphertext,
                          ciphertext_len,
                          key,
                          key_size,
                          iv,
                          decryptedtext,
                          ALC_AES_MODE_CTR);
        decryptedtext_len = ciphertext_len;
        EXPECT_TRUE(ArraysMatch(decryptedtext,
                                plaintext,
                                16,
                                ds.getLineNumber(),
                                std::string("AES_CTR_256_DEC")));
        free(key);
        free(iv);
        free(plaintext);
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