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

#include "cipher/alc_base.hh"
#include "cipher/base.hh"
#include "cipher/gtest_base.hh"

using namespace alcp::testing;

std::string MODE_STR = "XTS";

#define ALC_MODE ALC_AES_MODE_XTS

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_KnownAnsTest)
{
    int            key_size    = 128;
    TestingCore    testingCore = TestingCore(MODE_STR, ALC_MODE);
    bool           test_ran    = false;
    alcp_data_ex_t data;
    while (testingCore.getDs()->readPtIvKeyCtTKey(key_size)) {
        // Checks if output is correct
        test_ran = true;
        // Create vector for cipher text
        std::vector<uint8_t> outct(testingCore.getDs()->getPt().size(), 0);
        std::vector<uint8_t> pt   = testingCore.getDs()->getPt();
        std::vector<uint8_t> iv   = testingCore.getDs()->getIv();
        std::vector<uint8_t> tkey = testingCore.getDs()->getTKey();

        data.in    = &(pt[0]);
        data.inl   = pt.size();
        data.iv    = &(iv[0]);
        data.ivl   = iv.size();
        data.out   = &(outct[0]);
        data.outl  = data.inl;
        data.tkey  = &(tkey[0]);
        data.tkeyl = tkey.size();
        testingCore.getCipherHandler()->testingEncrypt(
            data, testingCore.getDs()->getKey());
        EXPECT_TRUE(ArraysMatch(outct,
                                testingCore.getDs()->getCt(),
                                *(testingCore.getDs()),
                                std::string("AES_" + MODE_STR + "_128_ENC")));
    }
    if (!test_ran) {
        EXPECT_TRUE(::testing::AssertionFailure()
                    << "No tests to run, check dataset");
    }
}

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_256, 256_KnownAnsTest)
{
    int            key_size    = 256;
    TestingCore    testingCore = TestingCore(MODE_STR, ALC_MODE);
    bool           test_ran    = false;
    alcp_data_ex_t data;
    while (testingCore.getDs()->readPtIvKeyCtTKey(key_size)) {
        // Checks if output is correct
        test_ran = true;
        // Create vector for cipher text
        std::vector<uint8_t> outct(testingCore.getDs()->getPt().size(), 0);
        std::vector<uint8_t> pt   = testingCore.getDs()->getPt();
        std::vector<uint8_t> iv   = testingCore.getDs()->getIv();
        std::vector<uint8_t> tkey = testingCore.getDs()->getTKey();

        data.in    = &(pt[0]);
        data.inl   = pt.size();
        data.iv    = &(iv[0]);
        data.ivl   = iv.size();
        data.out   = &(outct[0]);
        data.outl  = data.inl;
        data.tkey  = &(tkey[0]);
        data.tkeyl = tkey.size();
        testingCore.getCipherHandler()->testingEncrypt(
            data, testingCore.getDs()->getKey());
        EXPECT_TRUE(ArraysMatch(outct,
                                testingCore.getDs()->getCt(),
                                *(testingCore.getDs()),
                                std::string("AES_" + MODE_STR + "_256_ENC")));
    }
    if (!test_ran) {
        EXPECT_TRUE(::testing::AssertionFailure()
                    << "No tests to run, check dataset");
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
