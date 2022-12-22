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

#include "alcp/utils/bignum.hh"

#include "gtest/gtest.h"

#include <limits>
#include <map>

// using namespace std;
using namespace alcp;
using namespace alcp::base;

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

class FromString
    : public testing::TestWithParam<std::pair<const string, bn_str_params_t>>
{};

TEST_P(FromString, Simple)
{
    const auto [input_str, output_str] = GetParam().second;
    BigNum n;
    n.fromString(input_str);

    EXPECT_EQ(n.toString(), output_str);
}

INSTANTIATE_TEST_SUITE_P(
    BigNumKAT,
    FromString,
    testing::ValuesIn(bignum_str_known_answers),
    [](const testing::TestParamInfo<FromString::ParamType>& info) {
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

class FromInteger
    : public testing::TestWithParam<std::pair<const string, int_params_t>>
{};

TEST_P(FromInteger, Integers)
{
    BigNum n;
    auto [input, output] = GetParam().second;

    n.fromInt64(input);

    EXPECT_STREQ(n.toString().c_str(), output.c_str());
}

INSTANTIATE_TEST_SUITE_P(
    BigNumKAT,
    FromInteger,
    testing::ValuesIn(bignum_int_known_answers),
    [](const testing::TestParamInfo<FromInteger::ParamType>& info) {
        return info.param.first;
    });

TEST(BigNumTest, MaxUint64)
{
    BigNum      n;
    std::string res(std::to_string(std::numeric_limits<alcp::Uint64>::max()));

    n.fromUint64(std::numeric_limits<alcp::Uint64>::max());

    EXPECT_EQ(n.toString(), res);
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

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(0);

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), (a + b).toInt64());
}

TEST(BigNumTest, AddAssign)
{
    BigNum a, b;

    a.fromInt64(0);
    b.fromInt64(1);

    a += b;
    EXPECT_EQ(1, a.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(0);

    a += b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), a.toInt64());
}

TEST(BigNumTest, Increment)
{
    BigNum a;

    a.fromInt64(0);

    ++a;
    EXPECT_EQ(1, a.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max() - 1);

    ++a;
    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), a.toInt64());
}

TEST(BigNumTest, Sub)
{
    BigNum a, b;

    a.fromInt64(0);
    b.fromInt64(1);

    BigNum c = a - b;

    EXPECT_EQ(-1, c.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    c = b - a;
    EXPECT_EQ(0, c.toInt64());
}

TEST(BigNumTest, SubAssign)
{
    BigNum a, b;

    a.fromInt64(0);
    b.fromInt64(1);

    a -= b;

    EXPECT_EQ(-1, a.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    a -= b;
    EXPECT_EQ(0, a.toInt64());
}

TEST(BigNumTest, Decrement)
{
    BigNum a, b;

    a.fromInt64(0);
    --a;

    EXPECT_EQ(-1, a.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    --a;
    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max() - 1, a.toInt64());
}

TEST(BigNumTest, InvalidString)
{
    BigNum a;

    Status s = a.fromString(String("123xyz"));

    EXPECT_EQ(s.ok(), false);
}

TEST(BigNumTest, Mul)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);

    BigNum c = a * b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), c.toInt64());
}

TEST(BigNumTest, MulAssign)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);

    a *= b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), a.toInt64());
}

TEST(BigNumTest, Div)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);

    BigNum c = a / b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), c.toInt64());
}

TEST(BigNumTest, DivAssign)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);

    a /= b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), a.toInt64());
}

TEST(BigNumTest, Mod)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    BigNum c = a % b;

    EXPECT_EQ(0, c.toInt64());
}

TEST(BigNumTest, ModAssign)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    a %= b;

    EXPECT_EQ(0, a.toInt64());
}

TEST(BigNumTest, Equal)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    EXPECT_EQ(true, a == b);
}

TEST(BigNumTest, NotEqual)
{
    BigNum a, b;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::min());

    EXPECT_EQ(true, a != b);
}

TEST(BigNumTest, LeftShift)
{
    BigNum a;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());

    a >>= 1;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max() >> 1, a.toInt64());

    // left shift by 2
    a >>= 2;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max() >> 3, a.toInt64());
}

TEST(BigNumTest, RightShift)
{
    BigNum a;

    a.fromInt64(1);

    a <<= 1;

    EXPECT_EQ(2, a.toInt64());

    // right shift by 2
    a <<= 2;

    EXPECT_EQ(8, a.toInt64());
}

} // namespace
