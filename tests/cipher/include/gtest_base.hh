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

#pragma once
#include "alc_base.hh"
#include <base.hh>
#include <gtest/gtest.h>
#include <vector>
#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_base.hh"
#endif

using namespace alcp::testing;

#ifndef __GTEST_BASE_HH
#define __GTEST_BASE_HH 2

static bool verbose = false;
static bool useipp  = false;
static bool useossl = false;

::testing::AssertionResult
ArraysMatch(std::vector<uint8_t>    actual,
            std::vector<uint8_t>    expected,
            alcp::testing::DataSet& ds,
            std::string             testName)
{
    if (actual.size() != expected.size()) {
        return ::testing::AssertionFailure() << "Size mismatch!";
    }
    for (size_t i = 0; i < actual.size(); i++) {
        // TODO: Replace with proper cast
        if (expected[i] != actual[i]) {
            std::string actual_error   = parseBytesToHexStr(&actual[i], 1);
            std::string expected_error = parseBytesToHexStr(&expected[i], 1);
            return ::testing::AssertionFailure()
                   << "array[" << i << "] ("
                   << "0x" << actual_error << ") != expected[" << i << "]("
                   << "0x" << expected_error << ")"
                   << "Test: " << testName << " line: " << ds.getLineNumber()
                   << " Failed";
        }
    }
    if (verbose) {
        std::cout << "Test: " << testName << " line: " << ds.getLineNumber()
                  << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}
::testing::AssertionResult
ArraysMatch(std::vector<uint8_t> actual, std::vector<uint8_t> expected)
{
    if (actual.size() != expected.size()) {
        return ::testing::AssertionFailure() << "Size mismatch!";
    }
    for (size_t i = 0; i < actual.size(); i++) {
        // TODO: Replace with proper cast
        if (expected[i] != actual[i]) {
            return ::testing::AssertionFailure()
                   << "Does not match,"
                   << "Size:" << actual.size() << " Failure!";
        }
    }
    if (verbose) {
        std::cout << "Size:" << actual.size() << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}

class ConfigurableEventListener : public testing::TestEventListener
{

  protected:
    testing::TestEventListener* eventListener;

  public:
    /**
     * Show the names of each test case.
     */
    bool showTestCases;

    /**
     * Show the names of each test.
     */
    bool showTestNames;

    /**
     * Show each success.
     */
    bool showSuccesses;

    /**
     * Show each failure as it occurs. You will also see it at the bottom after
     * the full suite is run.
     */
    bool showInlineFailures;

    /**
     * Show the setup of the global environment.
     */
    bool showEnvironment;

    explicit ConfigurableEventListener(TestEventListener* theEventListener)
        : eventListener(theEventListener)
    {
        showTestCases      = true;
        showTestNames      = true;
        showSuccesses      = true;
        showInlineFailures = true;
        showEnvironment    = true;
    }

    virtual ~ConfigurableEventListener() { delete eventListener; }

    virtual void OnTestProgramStart(const testing::UnitTest& unit_test)
    {
        eventListener->OnTestProgramStart(unit_test);
    }

    virtual void OnTestIterationStart(const testing::UnitTest& unit_test,
                                      int                      iteration)
    {
        eventListener->OnTestIterationStart(unit_test, iteration);
    }

    virtual void OnEnvironmentsSetUpStart(const testing::UnitTest& unit_test)
    {
        if (showEnvironment) {
            eventListener->OnEnvironmentsSetUpStart(unit_test);
        }
    }

    virtual void OnEnvironmentsSetUpEnd(const testing::UnitTest& unit_test)
    {
        if (showEnvironment) {
            eventListener->OnEnvironmentsSetUpEnd(unit_test);
        }
    }

    virtual void OnTestCaseStart(const testing::TestCase& test_case)
    {
        if (showTestCases) {
            eventListener->OnTestCaseStart(test_case);
        }
    }

    virtual void OnTestStart(const testing::TestInfo& test_info)
    {
        if (showTestNames) {
            eventListener->OnTestStart(test_info);
        }
    }

    virtual void OnTestPartResult(const testing::TestPartResult& result)
    {
        eventListener->OnTestPartResult(result);
    }

    virtual void OnTestEnd(const testing::TestInfo& test_info)
    {
        if ((showInlineFailures && test_info.result()->Failed())
            || (showSuccesses && !test_info.result()->Failed())) {
            eventListener->OnTestEnd(test_info);
        }
    }

    virtual void OnTestCaseEnd(const testing::TestCase& test_case)
    {
        if (showTestCases) {
            eventListener->OnTestCaseEnd(test_case);
        }
    }

    virtual void OnEnvironmentsTearDownStart(const testing::UnitTest& unit_test)
    {
        if (showEnvironment) {
            eventListener->OnEnvironmentsTearDownStart(unit_test);
        }
    }

    virtual void OnEnvironmentsTearDownEnd(const testing::UnitTest& unit_test)
    {
        if (showEnvironment) {
            eventListener->OnEnvironmentsTearDownEnd(unit_test);
        }
    }

    virtual void OnTestIterationEnd(const testing::UnitTest& unit_test,
                                    int                      iteration)
    {
        eventListener->OnTestIterationEnd(unit_test, iteration);
    }

    virtual void OnTestProgramEnd(const testing::UnitTest& unit_test)
    {
        eventListener->OnTestProgramEnd(unit_test);
    }
};

typedef enum
{
    OPENSSL = 0,
    IPP,
    ALCP,
} lib_t;

// Just a class to reduce duplication of lines
class KATTestingCore
{
  private:
    DataSet*        ds            = nullptr;
    CipherTesting*  cipherHandler = nullptr;
    AlcpCipherBase* acb           = nullptr;
#ifdef USE_IPP
    IPPCipherBase* icb = nullptr;
#endif
#ifdef USE_OSSL
    OpenSSLCipherBase* ocb = nullptr;
#endif
  public:
    KATTestingCore(lib_t lib, alc_aes_mode_t alcpMode)
    {
        cipherHandler = new CipherTesting();
        switch (lib) {
            case OPENSSL:
#ifndef USE_OSSL
                delete cipherHandler;
                throw "OpenSSL not avaiable!";
#else
                if (!useossl) {
                    delete cipherHandler;
                    throw "OpenSSL disabled!";
                }
                ocb = new OpenSSLCipherBase(alcpMode, NULL);
                cipherHandler->setcb(ocb);
#endif
                break;
            case IPP:
#ifndef USE_IPP
                delete cipherHandler;
                throw "IPP not avaiable!";
#else
                if (!useipp) {
                    delete cipherHandler;
                    throw "IPP disabled!";
                }
                icb = new IPPCipherBase(alcpMode, NULL);
                cipherHandler->setcb(icb);
#endif
                break;
            case ALCP:
                acb = new AlcpCipherBase(alcpMode, NULL);
                cipherHandler->setcb(acb);
                break;
        }
    }
    KATTestingCore(std::string modeStr, alc_aes_mode_t alcpMode)
    {
        std::transform(
            modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
        ds = new DataSet(std::string("dataset_") + modeStr
                         + std::string(".csv"));

        // Initialize cipher testing classes
        cipherHandler = new CipherTesting();
        acb           = new AlcpCipherBase(alcpMode, NULL);
        cipherHandler->setcb(acb);
#ifdef USE_IPP
        icb = new IPPCipherBase(alcpMode, NULL);
        if (useipp) {
            std::cout << "Using IPP" << std::endl;
            cipherHandler->setcb(icb);
        }
#else
        if (useipp) {
            printErrors("IPP is unavailable at the moment switching to ALCP!");
        }
#endif
#ifdef USE_OSSL
        ocb = new OpenSSLCipherBase(alcpMode, NULL);
        if (useossl) {
            std::cout << "Using OpenSSL" << std::endl;
            cipherHandler->setcb(ocb);
        }
#else
        if (useossl) {
            printErrors(
                "OpenSSL is unavailable at the moment switching to ALCP!");
        }
#endif
    }
    ~KATTestingCore()
    {
        if (ds != nullptr)
            delete ds;
        if (cipherHandler != nullptr)
            delete cipherHandler;
        if (acb != nullptr)
            delete acb;
#ifdef USE_IPP
        if (icb != nullptr)
            delete icb;
#endif
#ifdef USE_OSSL
        if (ocb != nullptr)
            delete ocb;
#endif
    }
    DataSet*       getDs() { return ds; }
    CipherTesting* getCipherHandler() { return cipherHandler; }
};

void
parseArgs(int argc, char** argv)
{
    std::string currentArg;
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {
                std::cout << std::endl
                          << "Additional help for microtests" << std::endl;
                std::cout << "--verbose or -v per line status." << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
                std::cout << "--use-ossl or -o force OpenSSL use in testing"
                          << std::endl;
            } else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                verbose = true;
            } else if ((currentArg == std::string("--use-ipp"))
                       || (currentArg == std::string("-i"))) {
                useipp = true;
            } else if ((currentArg == std::string("--use-ossl"))
                       || (currentArg == std::string("-o"))) {
                useossl = true;
            }
        }
    }
}

#endif