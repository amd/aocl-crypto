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

#include "alcp/experimental/types.hh"
#include "alcp/utils/bignum.hh"

#include "gtest/gtest.h"

#include <limits>
#include <map>

// using namespace std;
using namespace alcp;

namespace {

using string = alcp::String;

/**************************
 * String to String
 **************************/
typedef std::tuple<const string, const string>  bn_str_params_t;
typedef std::map<const string, bn_str_params_t> bn_kat_str_map_t;

static const bn_kat_str_map_t bignum_str_known_answers = {
    { "zero_test", { "0", "0" } },           //
    { "one_test", { "1", "1" } },            //
    { "negative_one_test", { "-1", "-1" } }, //
    { "five", { "5", "5" } },                //
    { "negative_five", { "-5", "-5" } },     //
};

class StrConversion
    : public testing::TestWithParam<std::pair<const string, bn_str_params_t>>
{};

TEST_P(StrConversion, Simple)
{
    const auto [intput_str, output_str] = GetParam().second;
    BigNum n;
    n.fromString(intput_str);

    EXPECT_STREQ(n.toString().c_str(), output_str.c_str());
}

INSTANTIATE_TEST_SUITE_P(
    BigNumKAT,
    StrConversion,
    testing::ValuesIn(bignum_str_known_answers),
    [](const testing::TestParamInfo<StrConversion::ParamType>& info) {
        return info.param.first;
    });

/**************************
 * Integer to string
 **************************/
typedef std::pair<const Int64, const string> int_params_t;
typedef std::map<const string, int_params_t> known_answer_int_map_t;

static const known_answer_int_map_t bignum_int_known_answers = {
    { "zero_test", { 0, "0" } },            //
    { "one_test", { 1, "1" } },             //
    { "negative_one_test", { -1, "-1" } },  //
    { "five_test", { 5, "5" } },            //
    { "negative_five_test", { -5, "-5" } }, //
    { "min_int32_test",
      { std::numeric_limits<alcp::Int32>::min(), "-2147483648" } },
    { "max_int32_test",
      { std::numeric_limits<alcp::Int32>::max(), "2147483647" } },
    { "min_int_test",
      { std::numeric_limits<alcp::Int64>::min(), "-9223372036854775808" } },
    { "max_int_test",
      { std::numeric_limits<alcp::Int64>::max(), "9223372036854775807" } },
};

class SimpleInt
    : public testing::TestWithParam<std::pair<const string, int_params_t>>
{};

TEST_P(SimpleInt, Integers)
{
    BigNum n;
    auto [input, output] = GetParam().second;

    n.fromInt64(input);

    EXPECT_STREQ(n.toString().c_str(), output.c_str());
}

INSTANTIATE_TEST_SUITE_P(
    BigNumKAT,
    SimpleInt,
    testing::ValuesIn(bignum_int_known_answers),
    [](const testing::TestParamInfo<SimpleInt::ParamType>& info) {
        return info.param.first;
    });

TEST(BigNumTest, MaxUint64)
{
    BigNum n;

    n.fromUint64(std::numeric_limits<alcp::Uint64>::max());

    EXPECT_STREQ(n.toString().c_str(), "18446744073709551615");
}

/***************************
 * Arithmetic operations
 ***************************/
TEST(BigNumTest, Add)
{
    BigNum a, b;

    a.fromInt64(0);
    b.fromInt64(1);

    EXPECT_EQ(1, (a + b).toInt64());
}

} // namespace
