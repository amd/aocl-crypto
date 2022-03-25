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
#include "rng_base.hh"

using namespace alcp::testing;

std::string MODE_STR = "CBC";

#define ALC_MODE ALC_AES_MODE_CBC

/* Testing Starts Here! */
TEST(SYMMETRIC_ENC_128, 128_KnownAnsTest)
{
    int             key_size = 128;
    KATTestingCore  alcpTC   = KATTestingCore(ALCP, ALC_MODE);
    KATTestingCore* extTC    = nullptr;
    RngBase         rb;
    try {
        if (useossl)
            extTC = new KATTestingCore(OPENSSL, ALC_MODE);
        else if (useipp)
            extTC = new KATTestingCore(IPP, ALC_MODE);
        else {
            printErrors("No Lib Specified!");
        }
    } catch (const char* exc) {
        std::cerr << exc << std::endl;
    }
    if (extTC != nullptr) {
        std::vector<uint8_t> pt(50, 1), key(16, 0), iv(16, 0);
        pt = rb.genRandomBytes(50);
        std::vector enc_1 =
            alcpTC.getCipherHandler()->testingEncrypt(pt, key, iv);
        std::vector enc_2 =
            extTC->getCipherHandler()->testingEncrypt(pt, key, iv);
        ArraysMatch(enc_1, enc_2);
        std::cout << parseBytesToHexStr(&pt[0], pt.size()) << std::endl;
        std::cout << parseBytesToHexStr(&enc_1[0], enc_1.size()) << std::endl;
        std::cout << parseBytesToHexStr(&enc_2[0], enc_2.size());
        // << std::endl;
        delete extTC;
    }

    // while (testingCore.getDs()->readPtIvKeyCt(key_size)) {
    //     // Checks if output is correct
    //     EXPECT_TRUE(ArraysMatch(testingCore.getCipherHandler()->testingEncrypt(
    //                                 testingCore.getDs()->getPt(),
    //                                 testingCore.getDs()->getKey(),
    //                                 testingCore.getDs()->getIv()),
    //                             testingCore.getDs()->getCt(),
    //                             *(testingCore.getDs()),
    //                             std::string("AES_" + MODE_STR +
    //                             "_128_ENC")));
    // }
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
