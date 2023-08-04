/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include "csv.hh"
#include "rsp_parser.hh"
#include <gtest/gtest.h>
#include <memory>
#include <random>

using namespace alcp::testing;
using utils::parseBytesToHexStr;
using utils::printErrors;

// Variables for Argument Parser
static int  verbose     = 0;
static bool useipp      = false;
static bool useossl     = false;
static bool bbxreplay   = false;
static bool oa_override = false;

/**
 * @brief Check if 2 binary vectors are equal, print the current line as
 * success or failure, print the failed vectors and index where it failed.
 * Currently used for all KAT vectors
 *
 * @param actual    Output obtained from the algorithm.
 * @param expected  Expected output given the algorithm is correct.
 * @param CRspParser  CRspParser object to extract the line number.
 * @param testName  Name of the test to display.
 * @return ::testing::AssertionResult
 */
::testing::AssertionResult
ArraysMatch(const std::vector<Uint8>  actual,
            const std::vector<Uint8>  expected,
            CRspParser& CRspParser,
            std::string_view         testName)
{
    if (actual.size() != expected.size()) {
        std::cout << actual.size() <<" vs "<<expected.size() << std::endl;
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
                   << "Test: " << testName << " line: " << CRspParser.getLineNumber()
                   << " Failed";
        }
    }
    if (verbose > 0) {
        std::cout << "Test: " << testName << " line: " << CRspParser.getLineNumber()
                  << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}

/**
 * @brief Check if 2 binary vectors are equal, print the current line as
 * success or failure, print the failed vectors and index where it failed.
 * Currently used for all KAT vectors
 *
 * @param actual    Output obtained from the algorithm.
 * @param expected  Expected output given the algorithm is correct.
 * @param csv        Csv object to extract the line number.
 * @param testName  Name of the test to display.
 * @return ::testing::AssertionResult
 */
::testing::AssertionResult
ArraysMatch(std::vector<Uint8>  actual,
            std::vector<Uint8>  expected,
            alcp::testing::Csv& csv,
            std::string         testName)
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
                   << "Test: " << testName << " line: " << csv.getLineNumber()
                   << " Failed";
        }
    }
    if (verbose > 0) {
        std::cout << "Test: " << testName << " line: " << csv.getLineNumber()
                  << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}

/**
 * @brief Check if 2 binary vectors are equal, also print the size of the input.
 * Currently Used for Digest/HMAC cross tests.
 *
 * @param actual    Output obtained from the algorithm.
 * @param expected  Expected output given the algorithm is correct.
 * @param len       Length of input to the algorithm
 * @return ::testing::AssertionResult
 */
::testing::AssertionResult
ArraysMatch(std::vector<Uint8> actual, std::vector<Uint8> expected, size_t len)
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
    if (verbose > 0) {
        std::cout << "Length:" << len << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}

/**
 * @brief Check if 2 binary vectors are equal, also print the size of the
 * expected vector. Currently used for Cipher cross tests.
 *
 * @param actual    Output obtained from the algorithm.
 * @param expected  Expected output given the algorithm is correct.
 * @return ::testing::AssertionResult
 */
::testing::AssertionResult
ArraysMatch(std::vector<Uint8> actual, std::vector<Uint8> expected)
{
    if (actual.size() != expected.size()) {
        return ::testing::AssertionFailure() << "Size mismatch!";
    }
    for (size_t i = 0; i < actual.size(); i++) {
        if (expected[i] != actual[i]) {
            return ::testing::AssertionFailure()
                   << "Does not match,"
                   << "Size:" << actual.size() << " Failure i:" << i << " ! "
                   << "Actual "
                   << parseBytesToHexStr(&(actual[0]), expected.size())
                   << " Expected "
                   << parseBytesToHexStr(&(expected[0]), expected.size());
        }
    }
    if (verbose > 0) {
        std::cout << "Size:" << actual.size() << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}

typedef enum
{
    OPENSSL = 0,
    IPP,
    ALCP,
} lib_t;

/* shuffle vector */
inline std::vector<Uint8>
ShuffleVector(std::vector<Uint8> InputVec, std::default_random_engine rng)
{
    std::shuffle(std::begin(InputVec), std::end(InputVec), rng);
    return InputVec;
}

void
parseArgs(int argc, char** argv)
{
    std::string currentArg;
    std::string temp;

    std::vector<std::string> verbosity_levels = { "0", "1", "2" };

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {

                std::string verbosity_string = "(";
                for (size_t j = 0; j < verbosity_levels.size() - 1; j++) {
                    verbosity_string += static_cast<char>(j) + '/';
                }
                verbosity_string +=
                    verbosity_levels.at(verbosity_levels.size() - 1) + ")";
                std::cout << std::endl
                          << "Additional help for microtests" << std::endl;
                std::cout << "--verbose or -v <space>  <verbosity level(0/1/2)>"
                          << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
                std::cout << "--use-ossl or -o force OpenSSL use in testing"
                          << std::endl;
                std::cout << "--replay-blackbox or -r replay blackbox with "
                             "log file"
                          << std::endl;
            } else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                /* now extract the verbose level integer */
                if (((currentArg.find(std::string("--verbose"))
                      != currentArg.npos)
                     || (currentArg.find(std::string("-v")) != currentArg.npos))
                    && (i + 1 < argc)) {
                    std::string nextArg = std::string(argv[i + 1]);
                    // Skip the next iteration
                    i++;
                    // check if the provided verbosity is supported
                    auto it = std::find(verbosity_levels.begin(),
                                        verbosity_levels.end(),
                                        nextArg);
                    if (it != verbosity_levels.end()) {
                        verbose = std::stoi(nextArg);
                    } else {
                        std::cout << RED << "Invalid Verbosity Level \""
                                  << nextArg << "\"" << RESET << std::endl;
                        exit(-1);
                    }
                }

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