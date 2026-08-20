/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <random>
#include "parse_args.hh"

using namespace alcp::testing;
using utils::parseBytesToHexStr;
using utils::printErrors;

// Variables for Argument Parser
static int      verbose       = 0;
static bool     useipp        = false;
static bool     useossl       = false;
static bool     bbxreplay     = false;
static bool     oa_override   = false;
static bool     seed_set      = false;
static uint64_t seed_override = 0;

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
ArraysMatch(const std::vector<Uint8>& actual,
            const std::vector<Uint8>& expected,
            alcp::testing::Csv&       csv,
            std::string               testName)
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
ArraysMatch(const std::vector<Uint8>& actual,
            const std::vector<Uint8>& expected,
            size_t                    len)
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
ArraysMatch(const std::vector<Uint8>& actual,
            const std::vector<Uint8>& expected)
{
    if (actual.size() != expected.size()) {
        return ::testing::AssertionFailure() << "Size mismatch!";
    }
    for (size_t i = 0; i < actual.size(); i++) {
        if (expected[i] != actual[i]) {
            // Bound the dump to a fixed window centred on the first mismatch:
            // buffers here can be hundreds of MB, so dumping them whole produces
            // unusably large failure logs. CTX bytes of context each side keeps
            // the message a small constant size while still showing the
            // divergence in context.
            const size_t CTX   = 16;
            const size_t start = (i >= CTX) ? i - CTX : 0;
            const size_t end =
                std::min(actual.size(), i + CTX + 1);
            return ::testing::AssertionFailure()
                   << "Does not match,"
                   << "Size:" << actual.size() << " Failure i:" << i << " ! "
                   << "Actual[i] 0x" << parseBytesToHexStr(&(actual[i]), 1)
                   << " Expected[i] 0x" << parseBytesToHexStr(&(expected[i]), 1)
                   << " window@" << start << " Actual "
                   << parseBytesToHexStr(&(actual[start]), end - start)
                   << " Expected "
                   << parseBytesToHexStr(&(expected[start]), end - start);
        }
    }
    if (verbose > 0) {
        std::cout << "Size:" << actual.size() << " Success" << std::endl;
    }
    return ::testing::AssertionSuccess();
}


enum class LIB_TYPE
{
    OPENSSL = 0,
    IPP,
    ALCP,
};

/* shuffle vector */
inline std::vector<Uint8>
ShuffleVector(std::vector<Uint8> InputVec, std::default_random_engine rng)
{
    std::shuffle(std::begin(InputVec), std::end(InputVec), rng);
    return InputVec;
}

/* check if pointer is aligned */
static inline bool
is_aligned(const Uint8* ptr)
{
    return reinterpret_cast<uintptr_t>(ptr) % 2 == 0;
}

void
parseTestArgs(int argc, char** argv)
{
    alcp::bench::args::ParsedArgs parsed;
    alcp::bench::args::strip_custom_args(&argc, argv, parsed);

    useipp        = parsed.use_ipp;
    useossl       = parsed.use_ossl;
    oa_override   = parsed.override_alcp;
    bbxreplay     = parsed.replay_blackbox;
    verbose       = parsed.verbose;
    seed_set      = parsed.seed_set;
    seed_override = parsed.seed;

    /* --help is consumed by testing::InitGoogleTest before this function is
     * reached in the normal call flow.  If called before InitGoogleTest (e.g.
     * to surface AOCL options first), print our section so gtest's own help
     * follows naturally. */
    if (parsed.help_requested) {
        alcp::bench::args::print_test_help();
    }
}

template<typename T>
T*
getPtr(std::vector<T>& vect)
{
    if (vect.size() == 0) {
        return nullptr;
    } else {
        return &vect[0];
    }
}

/**
 * @brief Check if 2 binary arrays (given as pointers) are equal.
 *
 * @param actual      Pointer to the output obtained from the algorithm.
 * @param expected    Pointer to the expected output.
 * @param actual_len  Length of the actual array.
 * @param expected_len Length of the expected array.
 * @return ::testing::AssertionResult
 */
::testing::AssertionResult
ArraysMatch( Uint8* actual,  Uint8* expected,
            size_t actual_len, size_t expected_len)
{
    if (actual_len != expected_len) {
        return ::testing::AssertionFailure() << "Size mismatch! actual_len: " 
                                            << actual_len << ", expected_len: " 
                                            << expected_len;
    }
    
    for (size_t i = 0; i < actual_len; i++) {
        if (expected[i] != actual[i]) {
            std::string actual_error = parseBytesToHexStr(&actual[i], 1);
            std::string expected_error = parseBytesToHexStr(&expected[i], 1);
            return ::testing::AssertionFailure()<< "Does not match,"
                   << "actual[" << i << "] ("
                   << "0x" << actual_error << ") != expected[" << i << "]("
                   << "0x" << expected_error << ")"
                   << " actual_len: " << actual_len
                   << " expected_len: " << expected_len;
        }

    }
    return ::testing::AssertionSuccess()
           << "Size: " << actual_len << " Success";
}
