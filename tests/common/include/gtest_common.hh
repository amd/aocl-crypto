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
#include "colors.hh"
#include <gtest/gtest.h>

using namespace alcp::testing;

static bool verbose     = false;
static bool useipp      = false;
static bool useossl     = false;
static bool bbxreplay   = false;
static bool oa_override = false;

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
ArraysMatch(std::vector<uint8_t> actual,
            std::vector<uint8_t> expected,
            size_t               len)
{
    if (actual.size() != expected.size()) {
        return ::testing::AssertionFailure() << "Size mismatch!";
    }
    for (size_t i = 0; i < actual.size(); i++) {
        if (expected[i] != actual[i]) {
            return ::testing::AssertionFailure()
                   << "Does not match,"
                   << "Length:" << len << " Failure i:" << i << " !";
        }
    }
    if (verbose) {
        std::cout << "Length:" << len << " Success" << std::endl;
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
        if (expected[i] != actual[i]) {
            return ::testing::AssertionFailure()
                   << "Does not match,"
                   << "Size:" << actual.size() << " Failure i:" << i << " ! "
                   << "Expected "
                   << parseBytesToHexStr(&(actual[0]) + i - 10, 20) << " Got "
                   << parseBytesToHexStr(&(expected[0]) + i - 10, 20);
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
                std::cout
                    << "--replay-blackbox or -r replay blackbox with log file"
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
            } else if ((currentArg == std::string("--replay-blackbox"))
                       || (currentArg == std::string("-r"))) {
                bbxreplay = true;
            } else if ((currentArg == std::string("--override-alcp"))
                       || (currentArg == std::string("-oa"))) {
                oa_override = true;
            }
        }
    }
}