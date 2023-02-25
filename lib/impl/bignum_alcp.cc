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
#include "bignum/bignumerror.hh"
#include <algorithm>
#include <bitset>
#include <climits>
#include <iomanip>
#include <type_traits>

#include <iostream>
#define p_data(x) (x.pImpl()->m_data)
#define p_neg(x)  (x.pImpl()->m_is_negative)

#define l_shift(x, shift)           (x << (shift))
#define l_shift_minus_one(x, shift) ((x << (shift)) - 1)
#define r_shift(x, shift)           (x >> (shift))
#define r_shift_minus_one(x, shift) ((x >> (shift)) - 1)

namespace alcp {

class BigNum::Impl
{
    using typeT = Uint64;

  public:
    Impl();
    ~Impl(){};
    void operator=(const BigNum& rhs);
    void operator=(const BigNum::Impl& rhs);

  public:
    BigNum minus(BigNum const& self);
    BigNum add(const BigNum& rhs);

    BigNum add(Uint64 val);
    BigNum sub(const BigNum& rhs);
    BigNum internal_div(const BigNum& b, BigNum* rem);
    BigNum mul(const BigNum& rhs);
    BigNum div(const BigNum& rhs);
    BigNum mod(const BigNum& rhs);
    BigNum lshift(int shifts);
    BigNum rshift(int shifts);
    int    total_bits() const;
    /* Cant compare BigNum at the moment */
    inline bool neq(const BigNum& rhs) { return m_is_negative; }

    /* Cant compare BigNum at the moment */
    inline bool eq(const BigNum& rhs)
    {
        return toString(BigNum::Format::eHex)
               == rhs.pImpl()->toString(BigNum::Format::eHex);
    }

    Int64 toInt64() const;
    Int32 toInt32() const;
    void  fromUint64(const Uint64 val);
    void  fromInt64(const Int64 val);
    void  fromInt32(const Int32 val);

    Status       fromString(const String& str, Format f);
    const String toString(Format f) const;

    const void* data() const;
    std::size_t size() const;

  private:
    std::vector<typeT> m_data;
    bool               m_is_negative;
    void               clear();

  private:
    void invert();
};

BigNum::Impl::Impl()
    : m_is_negative{ false }
{}

void
BigNum::Impl::operator=(const BigNum& rhs)
{
    this->m_data        = p_data(rhs);
    this->m_is_negative = p_neg(rhs);
}

void
BigNum::Impl::operator=(const BigNum::Impl& rhsImpl)
{
    this->m_data        = rhsImpl.m_data;
    this->m_is_negative = rhsImpl.m_is_negative;
}

void
BigNum::Impl::invert()
{
    for (auto b = m_data.begin(); b != m_data.end(); b++) {
        *b = ~(*b);
    }
}

BigNum
BigNum::Impl::minus(BigNum const& self)
{
    BigNum        bn{ self };
    BigNum::Impl& ip = *bn.pImpl();

    /* Get 2's complement form */
    ip.invert();
    ip.add(1ULL);
    ip.m_is_negative = true;

    return bn;
}

Int64
BigNum::Impl::toInt64() const
{
    Int64 x = m_data.front() & 0x7fffffffffffffff;
    return m_is_negative ? -1 * x : x;
}

Int32
BigNum::Impl::toInt32() const
{
    Int32 x = m_data.front() & 0x7fffffff;
    return m_is_negative ? -1 * x : x;
}

void
BigNum::Impl::fromUint64(const Uint64 val)
{

    m_data.resize(1);
    m_data[0] = val;
    ALCP_ASSERT(toString() == val,
                "fromUint64: BIGNUM struct constructor failed");
}

void
BigNum::Impl::fromInt64(const Int64 val)
{
    m_is_negative = val < 0 ? true : false;

    m_data.resize(1);
    m_data[0] = m_is_negative ? -1 * val : val;
    ALCP_ASSERT(toInt64() == val,
                "fromInt64: BIGNUM struct constructor failed");
}

void
BigNum::Impl::fromInt32(const Int32 val)
{

    fromInt64(val);

    ALCP_ASSERT(toInt32() == val,
                "fromInt32: BIGNUM struct constructor failed");
}

int
BigNum::Impl::total_bits() const
{
    int ans = 0;
    if (m_data.size() > 1)
        ans = (m_data.size() - 1) * 64;
    ans += 64 - __builtin_clzll(m_data.back());
    return ans;
}

bool
compare_ge(vector<Uint64> a, vector<Uint64> b)
{
    if (a.size() > b.size())
        return true;
    if (a.size() < b.size())
        return false;
    for (int i = a.size() - 1; i >= 0; i--) {
        if (a[i] > b[i])
            return true;
        else if (a[i] < b[i])
            return false;
    }
    return true;
}

bool
__add(const std::vector<Uint64>& l,
      const std::vector<Uint64>& r,
      std::vector<Uint64>&       res)
{

    Uint64 carry  = 0;
    auto   lstart = l.begin(), lend = l.end();
    auto   rstart = r.begin(), rend = r.end();
    while (lstart != l.end() && rstart != r.end()) {
        auto sum = *lstart + *rstart + carry;
        res.push_back(sum);
        carry = ((*lstart > sum)) ? 1 : 0;

        lstart++;
        rstart++;
    }

    /*
     * If vectors were of different length, we have reached end of at least
     * one of them
     */
    if (lstart == lend) {
        lstart = rstart;
        lend   = rend;
    }

    while (lstart != lend) {
        auto sum = *lstart + carry;
        res.push_back(sum);
        carry = (sum == 0) ? 1 : 0;
        lstart++;
    }

    if (carry)
        res.push_back(carry);

    return carry;
}

bool
__sub(const std::vector<Uint64>& l,
      const std::vector<Uint64>& r,
      std::vector<Uint64>&       res)
{

    Uint64 carry  = 0;
    auto   lstart = l.begin(), lend = l.end();
    auto   rstart = r.begin();
    while (rstart != r.end()) {
        auto sum = 0ULL;
        if (((*lstart - carry) < (*rstart))) {
            sum   = (0xffffffffffffffff + *lstart - *rstart - carry + 1);
            carry = 1;
        } else {
            sum   = *lstart - *rstart - carry;
            carry = 0;
        }

        res.push_back(sum);

        lstart++;
        rstart++;
    }

    while (lstart != lend) {
        // carry    = *lstart < carry ? 1 : 0;
        auto sum = 0ULL;
        if (*lstart < carry) {
            sum   = (0xffffffffffffffff + *lstart - carry);
            carry = 1;
        } else {
            sum   = (*lstart - carry);
            carry = 0;
        }
        res.push_back(sum);

        lstart++;
    }
    while (res.back() == 0 && res.size() > 1)
        res.pop_back();

    return carry;
}

BigNum
BigNum::Impl::add(const BigNum& rhs)
{
    BigNum result;

    auto rimpl   = rhs.pImpl();
    auto resimpl = result.pImpl();
    // auto carry_occured = 0UL;
    auto is_neg = (int)m_is_negative ^ (int)rimpl->m_is_negative;

    if (!is_neg) {
        __add(m_data, rimpl->m_data, resimpl->m_data);
        result.pImpl()->m_is_negative = m_is_negative;
    } else {
        if (compare_ge(m_data, rimpl->m_data)) {
            __sub(m_data, rimpl->m_data, resimpl->m_data);
            result.pImpl()->m_is_negative = m_is_negative;

        } else {
            __sub(rimpl->m_data, m_data, resimpl->m_data);
            result.pImpl()->m_is_negative = rimpl->m_is_negative;
        }
    }

    return result;
}

BigNum
BigNum::Impl::add(Uint64 val)
{
    BigNum result, bval;
    bval.fromUint64(val);

    auto carry_occured =
        __add(m_data, bval.pImpl()->m_data, result.pImpl()->m_data);

    if (carry_occured) {
        result.pImpl()->m_data.push_back(1);
    }

    return result;
}

BigNum
BigNum::Impl::sub(const BigNum& rhs)
{
    BigNum result;

    auto rimpl   = rhs.pImpl();
    auto resimpl = result.pImpl();

    // auto carry_occured = 0UL;
    auto is_neg = (int)m_is_negative ^ (int)rimpl->m_is_negative;

    if (is_neg) {

        __add(m_data, rimpl->m_data, resimpl->m_data);
        p_neg(result) = m_is_negative;
    } else {
        if (compare_ge(m_data, rimpl->m_data)) {

            __sub(m_data, rimpl->m_data, resimpl->m_data);
            p_neg(result) = m_is_negative;
        } else {
            __sub(rimpl->m_data, m_data, resimpl->m_data);
            p_neg(result) = 1 ^ rimpl->m_is_negative;
        }
    }

    return result;
    /* FIXME: re-do this */
}

BigNum
BigNum::Impl::mul(const BigNum& rhs)
{
    // fast exponentation for multiplication
    BigNum result, tmp;
    result.fromUint64(0ULL);
    auto data           = rhs.pImpl()->m_data;
    tmp.pImpl()->m_data = m_data;
    for (auto&& val : data) {
        while (val > 0) {
            if (val & 1)
                result += tmp;
            tmp <<= 1;
            val >>= 1;
        }
    }

    return result;
}

BigNum
BigNum::Impl::internal_div(const BigNum& b, BigNum* rem)
{
    BigNum result;
    result.fromUint64(0UL);

    if (p_data(b).size() == 0 || (p_data(b).size() == 1 && p_data(b)[0] == 0)) {

        throw Status{ alcp::bn::BigNumError{ bn::ErrorCode::eFloatingPoint } };
    }

    // getting total no of bits to compare a and b

    int x = total_bits();
    int y = b.pImpl()->total_bits();

    // return 0 if divisor is greater than dividend

    if (!compare_ge(m_data, p_data(b))) {
        if (rem != NULL) {
            p_data((*rem)) = m_data;
            p_neg((*rem))  = m_is_negative;
        }
        return result;
    }

    // making a copy of a and b and shifting b by x-y+1 bits so that original
    // data does not get updated

    BigNum rh = b, lh, d;

    p_data(lh) = m_data;
    p_neg(lh)  = m_is_negative;
    d.fromUint64(1UL);

    rh <<= (x - y + 1);
    d <<= (x - y + 1);

    // dividing lh till it become lower than b when rh == b than lh can't be
    // divided more

    while (rh != b) {
        rh >>= 1;
        d >>= 1;

        if (compare_ge(p_data(lh), p_data(rh))) {

            lh -= rh;
            result += d;
        }
    }
    if (rem != NULL) {
        p_data((*rem)) = p_data(lh);
        p_neg((*rem))  = p_neg(lh);
    }
    return result;
}

BigNum
BigNum::Impl::div(const BigNum& rhs)
{
    BigNum result;
    try {
        result = internal_div(rhs, NULL);
    } catch (Status e) {
        throw e;
    }
    return result;
}

BigNum
BigNum::Impl::mod(const BigNum& rhs)
{
    BigNum result = BigNum();
    try {
        internal_div(rhs, &result);
    } catch (Status e) {
        throw e;
    }
    return result;
}

void
__rshift(std::vector<Uint64>& r, std::vector<Uint64> a, int shifts)
{
    int rlen = r.size(), alen = a.size();

    uint64_t carry = 0;
    int      j     = rlen - 1;
    shifts %= 64;

    for (int k = alen - 1; j >= 0; k--) {

        // taking last x bits of carry and appending to front of result +
        // taking first 64-x bits of data and appending to back of result
        r[j] =
            ((l_shift(carry, 64 - shifts)
              & (ULLONG_MAX - l_shift_minus_one(1UL, shifts)))
             | (r_shift(a[k], shifts) & l_shift_minus_one(1UL, 64 - shifts)));

        // storing carry for next round
        carry = a[k] & l_shift_minus_one(1UL, shifts);

        j--;
    }
    int k = 0;
    while (r[rlen - 1 - k] == 0 && rlen - k > 1) {
        k++;
    }
    if (k > 0) {
        r.resize(rlen - k);
    }
}

void
__lshift(std::vector<Uint64>& r, std::vector<Uint64> a, int shifts)
{
    int    alen  = a.size();
    Uint64 carry = 0;
    int    j     = (shifts / 64);
    shifts %= 64;
    for (int k = 0; k < j; k++) {
        r[k] = 0;
    }

    for (int k = 0; k < alen; k++) {

        // taking first x bits of carry and appending to end of result +
        // taking last 64-x bits of data and appending to the front of result
        r[j] = (carry & l_shift_minus_one(1UL, shifts))
               | (l_shift(a[k], shifts)
                  & (ULLONG_MAX - l_shift_minus_one(1UL, shifts)));

        // storing carry for next round
        carry = r_shift(a[k], 64 - shifts) & l_shift_minus_one(1UL, shifts);

        j++;
    }
    if (carry > 0) {
        r[j] = carry;
    }
}

BigNum
BigNum::Impl::lshift(int shifts)
{
    BigNum result;
    int    len = m_data.size() + (shifts / 64)
              + (((shifts % 64) > __builtin_clzll(m_data.back())));

    result.pImpl()->m_data.resize(len);

    __lshift(result.pImpl()->m_data, m_data, shifts);

    return result;
}

BigNum
BigNum::Impl::rshift(int shifts)
{
    BigNum result;
    int    len = m_data.size() - (shifts / 64)
              - (((shifts % 64) > (64 - __builtin_clzll(m_data.back()))));
    if (len <= 0)
        return result;
    result.pImpl()->m_data.resize(len);

    __rshift(result.pImpl()->m_data, m_data, shifts);

    return result;
}

const String
BigNum::Impl::toString(Format f) const
{
    std::stringstream ss;
    string            bignumstr;

    if (m_is_negative) {
        ss << "-";
    }

    switch (f) {
        case BigNum::Format::eBinary: {
            for (int i = m_data.size() - 1; i >= 0; i--) {
                std::bitset<sizeof(Uint64) * 8> b(m_data[i]);
                if (i != (int)m_data.size() - 1)
                    ss << b.to_string();
                else {
                    string x = b.to_string();
                    x.erase(0,
                            std::min(x.find_first_not_of('0'), x.length() - 1));
                    ss << x;
                }
            }

            bignumstr = ss.str();
        } break;

        case Format::eDecimal: {

            BigNum temp, mul;
            p_data(temp) = m_data;
            mul.fromUint64(10000000000000000000UL);

            while (p_data(temp).size() > 0 && p_data(temp)[0] > 0) {
                std::stringstream sss;

                BigNum res;

                temp = temp.pImpl()->internal_div(mul, &res);

                sss << std::dec << p_data(res)[0];

                bignumstr = sss.str() + bignumstr;
            }
            bignumstr = (m_is_negative ? "-" : "") + bignumstr;
            break;

        } break;
        default: {
            for (int i = m_data.size() - 1; i >= 0; i--) {
                Uint64 x = m_data[i];
                if (i == (int)m_data.size() - 1) {
                    ss << std::setw(0) << std::hex << x;
                } else {
                    ss << std::setfill('0') << std::setw(16) << std::hex << x;
                }
            }

            bignumstr = ss.str();
        } break;
    }
    transform(bignumstr.begin(), bignumstr.end(), bignumstr.begin(), ::toupper);
    if (bignumstr.length() == 0)
        bignumstr = "0";
    return bignumstr;
}

Status
BigNum::Impl::fromString(const String& str, BigNum::Format f)
{
    string dstr = str;
    transform(dstr.begin(), dstr.end(), dstr.begin(), ::tolower);

    if (str[0] == '-') {
        m_is_negative = 1;
        dstr          = str.substr(1);
    }
    if (dstr.length() > 1
        && (dstr[1] == 'x'
            || (dstr[1] == 'b' && (f == BigNum::Format::eBinary)))) {
        dstr = str.substr(2);
    }
    switch (f) {
        case BigNum::Format::eBinary: {

            m_data.resize((dstr.length() / 512) + (dstr.length() % 512 != 0));

            Uint64 x = 0, j = 0, k = 0;

            for (int i = dstr.length() - 1; i >= 0; i--) {

                if (dstr[i] != '0' && dstr[i] != '1') {
                    Status s = Status{ alcp::bn::BigNumError{
                        ErrorCode::eInvalidArgument } };
                    return s;
                }
                x += (dstr[i] == '1') ? (1 << j) : 0;
                j++;

                if (j == 64) {
                    m_data[k] = x;
                    j         = 0;
                    x         = 0;
                    k++;
                }
            }
            if (x > 0)
                m_data[k] = x;
        } break;
        case BigNum::Format::eDecimal: {
            BigNum r, m;
            r.fromUint64(0);
            m.fromUint64(10000000000000000000UL);

            Uint64 x = 0, k = (19 - (dstr.length() % 19)) % 19;
            for (Uint64 i = 0; i < dstr.length(); i++) {

                if (!(dstr[i] >= '0' && dstr[i] <= '9')) {
                    Status s = Status{ alcp::bn::BigNumError{
                        ErrorCode::eInvalidArgument } };
                    return s;
                    return InvalidArgumentError(
                        " decimal string has invalid value ! " + str);
                }
                x *= 10;
                x += (dstr[i] - '0');
                k++;

                if (k == 19) {
                    BigNum a;
                    a.fromUint64(x);

                    r *= m;
                    r += a;

                    x = 0;
                    k = 0;
                }
            }

            if (m_is_negative == 1)
                p_neg(r) = 1;
            m_data = p_data(r);
        } break;
        default: {

            m_data.resize((dstr.length() / 16) + (dstr.length() % 16 > 0));

            Uint64 x = 0, k = 0, bits = 0, mul = 1;

            for (int i = dstr.length() - 1; i >= 0; i--) {

                if (!isxdigit(dstr[i])) {
                    Status s = Status{ alcp::bn::BigNumError{
                        ErrorCode::eInvalidArgument } };
                    return s;
                    return InvalidArgumentError(
                        " hex string has invalid value ! " + str);
                }

                x += ((dstr[i] >= '0' && dstr[i] <= '9') ? dstr[i] - '0'
                                                         : (dstr[i] - 'a') + 10)
                     * mul;

                mul *= 16;
                bits += 4;

                if (bits == 64) {

                    m_data[k++] = x;
                    x           = 0;
                    bits        = 0;
                    mul         = 1;
                }
            }
            if (x > 0) {

                m_data[k] = x;
            }
        }
    }
    ALCP_ASSERT(data[0] == val, "fromInt64: BIGNUM struct constructor failed");

    return StatusOk();
}

const void*
BigNum::Impl::data() const
{
    if (m_data.size() == 0)
        return nullptr;
    return &m_data;
}

std::size_t
BigNum::Impl::size() const
{
    return m_data.size() * sizeof(typeT);
}

} // namespace alcp
