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

/**
 * @brief Comparing ALCP's output to another external liberary
 *
 * Mandatory Dependances: alcp-cipher,alcp-rng,openssl/ipp (one of them needs to
 * be present)
 *
 */

#include "alc_base.hh"
#include "base.hh"
#include "gtest_base.hh"
#include "rng_base.hh"

using namespace alcp::testing;

#define ALC_MODE ALC_AES_MODE_CBC

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_CROSS_CHECK_SMALL)
{
    int          key_size = 128;
    TestingCore  alcpTC   = TestingCore(ALCP, ALC_MODE);
    TestingCore* extTC    = nullptr;
    RngBase      rb;
    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!");
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (extTC != nullptr) {
        for (int i = 16; i < 16 * 100000; i += 1616) {
            std::vector<uint8_t> pt, key, iv;
            pt  = rb.genRandomBytes(i);
            key = rb.genRandomBytes(16);
            iv  = rb.genRandomBytes(16);
            std::vector enc_1 =
                alcpTC.getCipherHandler()->testingEncrypt(pt, key, iv);
            std::vector enc_2 =
                extTC->getCipherHandler()->testingEncrypt(pt, key, iv);
            EXPECT_TRUE(ArraysMatch(enc_1, enc_2));
        }
        delete extTC;
    }
}

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_CROSS_CHECK_BIG)
{
    int          key_size = 128;
    TestingCore  alcpTC   = TestingCore(ALCP, ALC_MODE);
    TestingCore* extTC    = nullptr;
    RngBase      rb;
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!");
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (extTC != nullptr) {
        for (int i = 1; i <= 2; i++) {
            size_t size = 16 * 10000000 * i; // 0.16g
            // size *= 10;                      // 0.16g
            std::vector<uint8_t> pt, key, iv;
            try {
                pt  = rb.genRandomBytes(size);
                key = rb.genRandomBytes(16);
                iv  = rb.genRandomBytes(16);
            } catch (const char* err) {
                printErrors(std::string(err));
                std::exit(-1);
            }
            std::vector enc_1 =
                alcpTC.getCipherHandler()->testingEncrypt(pt, key, iv);
            std::vector enc_2 =
                extTC->getCipherHandler()->testingEncrypt(pt, key, iv);
            EXPECT_TRUE(ArraysMatch(enc_1, enc_2));
        }
        delete extTC;
    }
}

TEST(SYMMETRIC_DEC_128, 128_CROSS_CHECK_SMALL)
{
    int          key_size = 128;
    TestingCore  alcpTC   = TestingCore(ALCP, ALC_MODE);
    TestingCore* extTC    = nullptr;
    RngBase      rb;
    // Set extTC based on which external testing core user asks
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!");
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (extTC != nullptr) {
        for (int i = 16; i < 16 * 100000; i += 1616) {
            std::vector<uint8_t> ct, key, iv;
            ct  = rb.genRandomBytes(i);
            key = rb.genRandomBytes(16);
            iv  = rb.genRandomBytes(16);
            std::vector dec_1 =
                alcpTC.getCipherHandler()->testingDecrypt(ct, key, iv);
            std::vector dec_2 =
                extTC->getCipherHandler()->testingDecrypt(ct, key, iv);
            EXPECT_TRUE(ArraysMatch(dec_1, dec_2));
        }
        delete extTC;
    }
}

/* Testing Starts Here! */
TEST(SYMMETRIC_DEC_128, 128_CROSS_CHECK_BIG)
{
    int          key_size = 128;
    TestingCore  alcpTC   = TestingCore(ALCP, ALC_MODE);
    TestingCore* extTC    = nullptr;
    RngBase      rb;
    try {
        if (useossl)
            extTC = new TestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new TestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!");
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (extTC != nullptr) {
        for (int i = 1; i <= 2; i++) {
            size_t size = 16 * 10000000 * i; // 0.16g
            // size *= 10;                      // 0.16g
            std::vector<uint8_t> ct, key, iv;
            try {
                ct  = rb.genRandomBytes(size);
                key = rb.genRandomBytes(16);
                iv  = rb.genRandomBytes(16);
            } catch (const char* err) {
                printErrors(std::string(err));
                std::exit(-1);
            }
            // May need encryption step for GCM cuz of MAC
            std::vector dec_1 =
                alcpTC.getCipherHandler()->testingDecrypt(ct, key, iv);
            std::vector dec_2 =
                extTC->getCipherHandler()->testingDecrypt(ct, key, iv);
            EXPECT_TRUE(ArraysMatch(dec_1, dec_2));
        }
        delete extTC;
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
