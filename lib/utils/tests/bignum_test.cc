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
    { "bignum_string_test",
      { "-45235740967409352069236923505460823975",
        "-220816391617C1AD17ECF60010E2C7A7" } },
};

class FromString
    : public testing::TestWithParam<std::pair<const string, bn_str_params_t>>
{};

TEST_P(FromString, Simple)
{
    const auto [input_str, output_str] = GetParam().second;
    BigNum n;
    n.fromString(input_str);

    EXPECT_EQ(n.toString(BigNum::Format::eHex), output_str);
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

TEST(BigNumTest, From_To_StringTest)
{
    BigNum bn, dn, hn;

    bn.fromString(
        "1000100000100000010110001110010001011000010111110000011010110100010111"
        "11101100111101100000000000010000111000101100011110100111",
        BigNum::Format::eBinary);
    dn.fromString("45235740967409352069236923505460823975");
    hn.fromString("220816391617C1AD17ECF60010E2C7A7", BigNum::Format::eHex);
    EXPECT_EQ(dn.toString(), "45235740967409352069236923505460823975");
    EXPECT_EQ(dn.toString(BigNum::Format::eHex),
              "220816391617C1AD17ECF60010E2C7A7");
    EXPECT_EQ(dn.toString(BigNum::Format::eBinary),
              "1000100000100000010110001110010001011000010111110000011010110100"
              "01011111101100111101100000000000010000111000101100011110100111");
    EXPECT_EQ(bn.toString(), "45235740967409352069236923505460823975");
    EXPECT_EQ(bn.toString(BigNum::Format::eHex),
              "220816391617C1AD17ECF60010E2C7A7");
    EXPECT_EQ(bn.toString(BigNum::Format::eBinary),
              "1000100000100000010110001110010001011000010111110000011010110100"
              "01011111101100111101100000000000010000111000101100011110100111");
    EXPECT_EQ(hn.toString(), "45235740967409352069236923505460823975");
    EXPECT_EQ(hn.toString(BigNum::Format::eHex),
              "220816391617C1AD17ECF60010E2C7A7");
    EXPECT_EQ(hn.toString(BigNum::Format::eBinary),
              "1000100000100000010110001110010001011000010111110000011010110100"
              "01011111101100111101100000000000010000111000101100011110100111");
}

TEST(BigNumTest, MaxUint64)
{
    BigNum            n;
    std::stringstream ss;
    std::string res(std::to_string(std::numeric_limits<alcp::Uint64>::max()));
    ss << std::uppercase << std::hex
       << std::numeric_limits<alcp::Uint64>::max();

    n.fromUint64(std::numeric_limits<alcp::Uint64>::max());

    EXPECT_EQ(n.toString(BigNum::Format::eHex), ss.str());
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

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    EXPECT_EQ("FFFFFFFFFFFFFFFE", (a + b).toString(BigNum::Format::eHex));
    a.fromUint64(std::numeric_limits<alcp::Uint64>::max());
    b.fromUint64(std::numeric_limits<alcp::Uint64>::max());

    EXPECT_EQ("1FFFFFFFFFFFFFFFE", (a + b).toString(BigNum::Format::eHex));
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
    a.fromUint64(std::numeric_limits<alcp::Uint64>::max());
    b.fromUint64(std::numeric_limits<alcp::Uint64>::max());

    EXPECT_EQ("1FFFFFFFFFFFFFFFE", (a + b).toString(BigNum::Format::eHex));
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
    BigNum a, b, d, e, g, h;

    a.fromInt64(0);
    b.fromInt64(1);

    BigNum c = a - b;

    EXPECT_EQ(-1, c.toInt64());

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());

    c = b - a;

    d.fromString("1208925819614629174706176");
    e.fromString("9614629174706178");

    BigNum f = (e - d);
    EXPECT_EQ(0, c.toInt64());
    EXPECT_EQ((d - e).toString(BigNum::Format::eHex), "FFFFFFDDD78BB364FFFE");
    EXPECT_EQ((f).toString(BigNum::Format::eHex), "-FFFFFFDDD78BB364FFFE");
    g.fromString(
        "DA5374ADCDAC435726DACDA6485837594375644397489DCAC4843960528A125E"
        "0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101B9B0AA7"
        "03CBA8AC10DE4000000000000000000",
        BigNum::Format::eHex);
    h.fromString(
        "DA5374ADCDAC435726DACDA6485837594375644397489DCAC4843960528A125E"
        "0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101B9B0AA7"
        "03CBA8AC10DE4000000000000000001",
        BigNum::Format::eHex);
    a = g - h;
    EXPECT_EQ((a).toString(BigNum::Format::eHex), "-1");
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
    BigNum a, b, d;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);
    d.fromInt64(std::numeric_limits<alcp::Int64>::max());

    BigNum c = a * b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), c.toInt64());
    c = a * d;
    EXPECT_EQ("3FFFFFFFFFFFFFFF0000000000000001",
              c.toString(BigNum::Format::eHex));
    c = a * (d + b);
    EXPECT_EQ("3FFFFFFFFFFFFFFF8000000000000000",
              c.toString(BigNum::Format::eHex));
}

TEST(BigNumTest, MulAssign)
{
    BigNum a, b, d;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(1);
    d.fromInt64(std::numeric_limits<alcp::Int64>::max());
    a *= b;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), a.toInt64());
    a *= d;
    EXPECT_EQ("3FFFFFFFFFFFFFFF0000000000000001",
              a.toString(BigNum::Format::eHex));
}

TEST(BigNumTest, Div)
{
    BigNum a, b, d, e;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromUint64(1);
    e.fromUint64(std::numeric_limits<alcp::Int64>::max());
    d.fromString("3E70BA2F31841D818E3F9E", BigNum::Format::eHex);

    BigNum c = a / b;
    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max(), c.toInt64());

    BigNum x = d / e;
    EXPECT_EQ("7CE174", x.toString(BigNum::Format::eHex));
    b.fromUint64(0);
    ASSERT_THROW((x / b), base::Status);
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
    BigNum a, b, d, e;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    b.fromInt64(std::numeric_limits<alcp::Int64>::max());
    d.fromString("3E70BA2F31841D818E3F9E", BigNum::Format::eHex);
    e.fromUint64(std::numeric_limits<alcp::Int64>::max());
    BigNum c = a % b;

    EXPECT_EQ(0, c.toInt64());
    BigNum x = d % e;
    EXPECT_EQ("2F31841D820B2112", x.toString(BigNum::Format::eHex));
    b.fromUint64(0);
    ASSERT_THROW((x % b), base::Status);
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
    BigNum a, b, c, d, e, g;

    a.fromInt64(1);
    d.fromInt64(5);
    e.fromInt64(0);
    a <<= 1;
    b.fromString("2BD33E7F190894F0773D574A430", BigNum::Format::eHex);
    c.fromString("2BD33E7F190894F0773D574A430", BigNum::Format::eHex);
    e <<= 100;
    EXPECT_EQ(0, e.toInt64());

    b <<= 1;
    c <<= 2;
    EXPECT_EQ(2, a.toInt64());
    EXPECT_EQ("57A67CFE321129E0EE7AAE94860", b.toString(BigNum::Format::eHex));
    b <<= 1;
    EXPECT_EQ("AF4CF9FC642253C1DCF55D290C0", b.toString(BigNum::Format::eHex));
    EXPECT_EQ("AF4CF9FC642253C1DCF55D290C0", c.toString(BigNum::Format::eHex));
    // left shift by 2
    a <<= 2;
    d <<= 80;
    EXPECT_EQ(8, a.toInt64());
    EXPECT_EQ("500000000000000000000", d.toString(BigNum::Format::eHex));
    b.fromString("125E0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101"
                 "B9B0AA703CBA8AC10DE4878800000000000000",
                 BigNum::Format::eHex);
    b <<= 3;
    EXPECT_EQ("92F0653C2E7899FDD5133DA9AFE2C840C84E13D2849304425BE599492080DCD8"
              "55381E5D456086F243C4000000000000000",
              b.toString(BigNum::Format::eHex));
    b.fromString("45922", BigNum::Format::eHex);
    b <<= 88;
    EXPECT_EQ("459220000000000000000000000", b.toString(BigNum::Format::eHex));
    b.fromString("DA5374ADCDAC435726DACDA6485837594375644397489DCAC4843960528A1"
                 "25E0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101B"
                 "9B0AA703CBA8AC10DE4",
                 BigNum::Format::eHex);
    b <<= 72;
    EXPECT_EQ("DA5374ADCDAC435726DACDA6485837594375644397489DCAC4843960528A125E"
              "0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101B9B0AA7"
              "03CBA8AC10DE4000000000000000000",
              b.toString(BigNum::Format::eHex));
    g.fromString("DA53", BigNum::Format::eHex);
    g <<= 620;
    EXPECT_EQ("DA53000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000",
              g.toString(BigNum::Format::eHex));
}

TEST(BigNumTest, RightShift)
{
    BigNum a, b, c, d, e, g;

    a.fromInt64(std::numeric_limits<alcp::Int64>::max());
    d.fromString("500000000000000000000", BigNum::Format::eHex);
    e.fromInt64(0);
    e >>= 100;
    EXPECT_EQ(0, e.toInt64());
    a >>= 1;
    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max() >> 1, a.toInt64());

    // right shift by 2
    a >>= 2;

    EXPECT_EQ(std::numeric_limits<alcp::Int64>::max() >> 3, a.toInt64());

    b.fromString("57A67CFE321129E0EE7AAE94861", BigNum::Format::eHex);
    b >>= 1;
    EXPECT_EQ("2BD33E7F190894F0773D574A430", b.toString(BigNum::Format::eHex));
    b >>= 1;
    EXPECT_EQ("15E99F3F8C844A783B9EABA5218", b.toString(BigNum::Format::eHex));
    b >>= 1;
    c.fromString("AF4CF9FC642253C1DCF55D290C", BigNum::Format::eHex);
    EXPECT_EQ(c.toString(BigNum::Format::eHex),
              b.toString(BigNum::Format::eHex));
    d >>= 80;
    EXPECT_EQ("5", d.toString(BigNum::Format::eHex));
    g.fromString(
        "DA5374ADCDAC435726DACDA6485837594375644397489DCAC4843960528A125E"
        "0CA785CF133FBAA267B535FC59081909C27A509260884B7CB32924101B9B0AA7"
        "03CBA8AC10DE4000000000000000000",
        BigNum::Format::eHex);
    g >>= 620;
    EXPECT_EQ("DA53", g.toString(BigNum::Format::eHex));
}

} // namespace
