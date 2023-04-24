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

#include "../../rng/include/system_rng.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/rng/drbg_hmac.hh"
#include "alcp/utils/bignum.hh"
#include <algorithm>
#include <bitset>
#include <climits>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <vector>

namespace alcp {
class BigNum::Impl
{
    using typeT = Uint64;

  public:
    Impl();
    ~Impl(){};
    void                       operator=(const BigNum& rhs);
    void                       operator=(const BigNum::Impl& rhs);
    static rng::drbg::HmacDrbg m_drbg;

  public:
    BigNum minus(BigNum const& self);
    BigNum add(const BigNum& rhs);

    BigNum add(Uint64 val);
    BigNum sub(const BigNum& rhs);
    BigNum mul(const BigNum& rhs);
    BigNum div(const BigNum& rhs);
    BigNum mod(const BigNum& rhs);
    BigNum lshift(int shifts);
    BigNum rshift(int shifts);

    void exp_mod(const BigNum& num, const BigNum& exp, const BigNum& mod);

    int total_bits() const;
    /* Cant compare BigNum at the moment */
    inline bool neq(const BigNum& rhs) { return m_is_negative; }

    /* Cant compare BigNum at the moment */
    inline bool eq(const BigNum& rhs)
    {
        return toString(BigNum::Format::eHex)
               == rhs.pImpl()->toString(BigNum::Format::eHex);
    }

    /* Cant compare BigNum at the moment */
    inline bool lt(const BigNum& rhs)
    {
        return toString(BigNum::Format::eHex)
               < rhs.pImpl()->toString(BigNum::Format::eHex);
    }

    /* Cant compare BigNum at the moment */
    inline bool gt(const BigNum& rhs)
    {
        return toString(BigNum::Format::eHex)
               > rhs.pImpl()->toString(BigNum::Format::eHex);
    }

    Int64 toInt64() const;
    Int32 toInt32() const;
    void  toBinary(Uint8* buf, Uint64 size);
    void  fromUint64(const Uint64 val);
    void  fromUint32(const Uint32 val);
    void  fromInt64(const Int64 val);
    void  fromInt32(const Int32 val);
    void  fromBinary(const Uint8* buf, Uint64 size);

    Status       fromString(const String& str, Format f);
    const String toString(Format f) const;

    int randomGenerate(int bits, int top, int bottom, unsigned int strength);
    int randomGenerate(int bits, int top, int bottom);

    int randomRange(const BigNum* range, unsigned int strength);
    int randomRange(const BigNum* range);

    const void* data() const;
    std::size_t size() const;

  private:
    std::vector<typeT> m_data;
    bool               m_is_negative;
    void               clear();

  private:
    int    privateRandom(int bits, int top, int bottom, unsigned int strength);
    int    privateRandom(int bits, int top, int bottom);
    int    privateRandomRange(const BigNum* range, unsigned int strength);
    int    privateRandomRange(const BigNum* range);
    void   invert();
    BigNum __div(const BigNum& b, BigNum& rem);
    static void init()
    {
        static bool isDrbg = false;
        if (isDrbg)
            return;
        vector<Uint8>                   data;
        std::shared_ptr<digest::Sha256> digest256 =
            std::make_shared<digest::Sha256>();
        m_drbg.setDigest(digest256);
        m_drbg.setRng(std::make_shared<alcp::rng::SystemRng>());

        if (!m_drbg.initialize(256, data).ok())
            std::cout << "Error While init od drbg for bignum";
        isDrbg = true;
    };
};

rng::drbg::HmacDrbg BigNum::Impl::m_drbg;

bool
compare_ge(const vector<Uint64>& a, const vector<Uint64>& b)
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
compare_gt(const vector<Uint64>& a, const vector<Uint64>& b)
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
    return false;
}

static inline Uint64
leftShift(Uint64 x, int shift)
{
    return (x << (shift));
}

static inline Uint64
leftShiftMinusOne(Uint64 x, int shift)
{
    return ((x << (shift)) - 1);
}

static inline Uint64
rightShift(Uint64 x, int shift)
{
    return (x >> (shift));
}

static inline Uint64
rightShiftMinusOne(Uint64 x, int shift)
{
    return ((x >> (shift)) - 1);
}

static inline int
ceil_64(int bits)
{
    // used to get ceil value when divided by 64
    constexpr int extra_bits_for_ceil = 63, bits_in_Uint64 = 64;
    return (bits + extra_bits_for_ceil) / bits_in_Uint64;
}

BigNum::Impl::Impl()
    : m_is_negative{ false }
{
    init();
}

void
BigNum::Impl::operator=(const BigNum& rhs)
{
    this->m_data        = rhs.pImpl()->m_data;
    this->m_is_negative = rhs.pImpl()->m_is_negative;
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

int
BigNum::Impl::randomGenerate(int bits, int top, int bottom)
{
    if (bits == 0 && (top || bottom))
        return ALC_ERROR_INVALID_SIZE;
    int            max_bytes  = ceil_64(bits);
    int            extra_bits = bits % 64;
    vector<Uint64> data(max_bytes, 0);
    Uint8*         p_data_8 = reinterpret_cast<Uint8*>(&(data[0]));
    if (!m_drbg.randomize(p_data_8, max_bytes * 8).ok()) {
        return ALC_ERROR_BAD_STATE;
    }
    m_drbg.reseed();
    long long mask = leftShiftMinusOne(1ULL, extra_bits);
    m_data         = data;
    m_data.back() &= mask;
    m_data[0] |= bottom;
    if (top)
        m_data.back() |= ((mask + 1) >> 1);
    else
        m_data.back() &= ((mask) >> 1);
    return ALC_ERROR_NONE;
}

int
BigNum::Impl::randomGenerate(int          bits,
                             int          top,
                             int          bottom,
                             unsigned int strength)
{
    if (bits == 0 && (top || bottom))
        return ALC_ERROR_INVALID_SIZE;
    vector<Uint8> personalizeString;
    if (!m_drbg.initialize(strength, personalizeString).ok())
        return ALC_ERROR_BAD_STATE;
    return randomGenerate(bits, top, bottom);
}

int
BigNum::Impl::randomRange(const BigNum* range)
{
    int            bits       = range->pImpl()->total_bits();
    int            max_bytes  = ceil_64(bits);
    int            extra_bits = bits % 64;
    vector<Uint64> data(max_bytes, 0);
    Uint8*         p_data_8 = reinterpret_cast<Uint8*>(&(data[0]));
    if (!m_drbg.randomize(p_data_8, max_bytes * 8).ok()) {
        return ALC_ERROR_BAD_STATE;
    }
    m_drbg.reseed();
    long long mask = leftShiftMinusOne(1ULL, extra_bits);
    m_data         = data;
    m_data.back() &= mask;
    while (compare_gt(m_data, range->pImpl()->m_data)) {
        *this = sub(*range);
    }
    return ALC_ERROR_NONE;
}

int
BigNum::Impl::randomRange(const BigNum* range, unsigned int strength)
{

    vector<Uint8> personalizeString;
    if (!m_drbg.initialize(strength, personalizeString).ok())
        return ALC_ERROR_BAD_STATE;
    return randomRange(range);
}

int
BigNum::Impl::privateRandom(int bits, int top, int bottom)
{
    return randomGenerate(bits, top, bottom);
}

int
BigNum::Impl::privateRandom(int          bits,
                            int          top,
                            int          bottom,
                            unsigned int strength)
{
    return randomGenerate(bits, top, bottom, strength);
}

int
BigNum::Impl::privateRandomRange(const BigNum* range)
{

    return randomRange(range);
}

int
BigNum::Impl::privateRandomRange(const BigNum* range, unsigned int strength)
{
    return randomRange(range, strength);
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
BigNum::Impl::fromUint32(const Uint32 val)
{
    m_data.resize(1);
    m_data[0] = val;
    ALCP_ASSERT(toString() == val,
                "fromUint32: BIGNUM struct constructor failed");
}

void
BigNum::Impl::fromInt64(const Int64 val)
{
    m_is_negative = val < 0 ? true : false;

    m_data.resize(1);
    m_data[0] = m_is_negative ? -1ULL * val : val;
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
    ans += (m_data.back() == 0 ? 64 : 64 - (__builtin_clzll(m_data.back())));
    return ans;
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
        carry = ((*lstart > sum)) ? 1 : 0;
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

    auto is_neg = (int)m_is_negative ^ (int)rimpl->m_is_negative;

    if (is_neg) {

        __add(m_data, rimpl->m_data, resimpl->m_data);
        result.pImpl()->m_is_negative = m_is_negative;
    } else {
        if (compare_ge(m_data, rimpl->m_data)) {

            __sub(m_data, rimpl->m_data, resimpl->m_data);
            result.pImpl()->m_is_negative = m_is_negative;
        } else {
            __sub(rimpl->m_data, m_data, resimpl->m_data);
            result.pImpl()->m_is_negative = 1 ^ rimpl->m_is_negative;
        }
    }

    return result;
}

BigNum
BigNum::Impl::mul(const BigNum& rhs)
{
    // fast exponentation for multiplication

    // TODO : Will need to implement other Algo to remove risk of exposing data

    BigNum result, tmp;
    result.fromUint64(0ULL);
    auto data           = rhs.pImpl()->m_data;
    tmp.pImpl()->m_data = m_data;
    for (auto&& val : data) {
        int tb = 64;
        while (val > 0) {
            while (val & 1) {
                result += tmp;
                tmp = tmp << 1;
                val >>= 1;
                tb--;
            }
            int k = 0;
            while (k < 63 && val && !(val & (1ULL << k))) {
                k++;
            }
            tmp = tmp << k;
            val >>= k;
            tb -= k;
        }
        tmp = tmp << tb;
    }

    return result;
}

BigNum
BigNum::Impl::__div(const BigNum& b, BigNum& rem)
{
    BigNum result;
    result.fromUint64(0UL);

    if (b.pImpl()->m_data.size() == 0
        || (b.pImpl()->m_data.size() == 1 && b.pImpl()->m_data[0] == 0)) {

        throw status::InvalidArgument("Floating Point Error : divide by 0 !");
    }

    // getting total no of bits to compare a and b

    int x = total_bits();
    int y = b.pImpl()->total_bits();

    // return 0 if divisor is greater than dividend

    if (!compare_ge(m_data, b.pImpl()->m_data)) {
        // if (rem != NULL) {
        rem.pImpl()->m_data        = m_data;
        rem.pImpl()->m_is_negative = m_is_negative;
        // }
        return result;
    }

    // making a copy of a and b and shifting b by x-y+1 bits so that original
    // data does not get updated

    BigNum rh = b, lh, d;

    lh.pImpl()->m_data        = m_data;
    lh.pImpl()->m_is_negative = m_is_negative;
    d.fromUint64(1UL);

    rh <<= (x - y + 1);
    d <<= (x - y + 1);

    // recursively subtracting different ((2^x) * divisor) from dividend till x
    // becomes 0 so that we can get remainder and divident in one go

    while (rh != b) {
        rh >>= 1;
        d >>= 1;

        if (compare_ge(lh.pImpl()->m_data, rh.pImpl()->m_data)) {

            lh -= rh;
            result += d;
        }
    }
    // if (rem != NULL) {
    rem.pImpl()->m_data        = lh.pImpl()->m_data;
    rem.pImpl()->m_is_negative = lh.pImpl()->m_is_negative;
    // }
    return result;
}

BigNum
BigNum::Impl::div(const BigNum& rhs)
{
    BigNum result, rem;
    try {
        result = __div(rhs, rem);
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
        __div(rhs, result);
    } catch (Status e) {
        throw e;
    }
    return result;
}

void
__rshift(std::vector<Uint64>& r, std::vector<Uint64> a, int shifts)
{
    int rlen = r.size(), alen = a.size();

    Uint64 carry = 0;
    int    j     = rlen - 1;
    shifts %= 64;
    if (shifts == 0) {
        for (int k = alen - 1; j >= 0; k--) {
            r[j--] = a[k];
        }
        return;
    }
    for (int k = alen - 1; j >= 0; k--) {

        // using overflow data of previous index present in carry
        r[j] = ((leftShift(carry, 64 - shifts)
                 & (ULLONG_MAX - leftShiftMinusOne(1UL, shifts)))
                | (rightShift(a[k], shifts)
                   & leftShiftMinusOne(1UL, 64 - shifts)));

        // storing overflow data in carry to used for next index
        carry = a[k] & leftShiftMinusOne(1UL, shifts);

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
    if (shifts == 0) {
        for (int k = 0; k < alen; k++) {
            r[j++] = a[k];
        }
        return;
    }
    for (int k = 0; k < alen; k++) {

        // using overflow data of previous index present in carry
        r[j] = (carry & leftShiftMinusOne(1UL, shifts))
               | (leftShift(a[k], shifts)
                  & (ULLONG_MAX - leftShiftMinusOne(1UL, shifts)));

        // storing overflow data in carry to used for next index
        carry = rightShift(a[k], 64 - shifts) & leftShiftMinusOne(1UL, shifts);

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
              + (m_data.back() == 0
                     ? 0
                     : (((shifts % 64) > __builtin_clzll(m_data.back()))));

    result.pImpl()->m_data.resize(len);

    __lshift(result.pImpl()->m_data, m_data, shifts);

    return result;
}

BigNum
BigNum::Impl::rshift(int shifts)
{
    BigNum result;
    int    len =
        m_data.size() - (shifts / 64)
        - (((shifts % 64)
            > (64
               - (m_data.back() != 0 ? __builtin_clzll(m_data.back()) : 64))));
    if (len <= 0) {
        result.fromInt32(0);
        return result;
    }

    result.pImpl()->m_data.resize(len);

    __rshift(result.pImpl()->m_data, m_data, shifts);

    return result;
}

void
BigNum::Impl::exp_mod(const BigNum& num, const BigNum& exp, const BigNum& mod)
{
    ALCP_ASSERT(false, "Not Implemented");
}

/**
 * Converts BigNum to string with binary, decimal or hexadecimal Format
 *
 * @note Default Format is for toString is hexadecimal
 */
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
            temp.pImpl()->m_data = m_data;
            mul.fromUint64(10000000000000000000UL);

            while (temp.pImpl()->m_data.size() > 1
                   || (temp.pImpl()->m_data.size() == 1
                       && temp.pImpl()->m_data[0] > 0)) {
                std::stringstream sss;

                BigNum res;

                temp = temp.pImpl()->__div(mul, res);

                sss << std::dec << res.pImpl()->m_data[0];

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

/**
 * Converts string with binary, decimal or hexadecimal Format to BigNum
 *
 * @note Default Format is hexadecimal
 */

Status
BigNum::Impl::fromString(const String& str, BigNum::Format f)
{

    string dstr = str;
    transform(dstr.begin(), dstr.end(), dstr.begin(), ::tolower);

    // Resetting the data already present to accomodate new data
    clear();

    if (str[0] == '-') {
        m_is_negative = true;
        dstr          = str.substr(1);
    }
    if (dstr.length() > 1
        && (dstr[1] == 'x'
            || (dstr[1] == 'b' && (f == BigNum::Format::eBinary)))) {
        dstr = str.substr(2);
    }
    switch (f) {
        case BigNum::Format::eBinary: {

            if (strspn(dstr.c_str(), "01") != dstr.length()) {

                Status s =
                    status::InvalidArgument("binary string has invalid value");
                return s;
            }
            Uint64 k = (dstr.length() % 64);
            if (k == 0)
                k = 64;
            for (Uint64 j = 0; j < dstr.length(); j += k, k = 64) {

                Uint64 x = strtoull(dstr.substr(j, k).c_str(), nullptr, 2);
                m_data.push_back(x);
            }
            reverse(m_data.begin(), m_data.end());

        } break;
        case BigNum::Format::eDecimal: {

            if (strspn(dstr.c_str(), "0123456789") != dstr.length()) {

                Status s =
                    status::InvalidArgument("decimal string has invalid value");
                return s;
            }
            BigNum r, m;
            r.fromUint64(0);
            m.fromUint64(10000000000000000000UL);
            Uint64 k = (dstr.length() % 19);
            if (k == 0)
                k = 19;
            for (Uint64 j = 0; j < dstr.length(); j += k, k = 19) {
                Uint64 x = strtoull(dstr.substr(j, k).c_str(), nullptr, 10);

                BigNum a;
                a.fromUint64(x);

                r *= m;
                r += a;
            }

            if (m_is_negative)
                r.pImpl()->m_is_negative = true;
            m_data = r.pImpl()->m_data;
        } break;
        default: {

            if (strspn(dstr.c_str(), "0123456789abcdef") != dstr.length()) {

                Status s = status::InvalidArgument(
                    "hexadecimal string has invalid value");
                return s;
            }

            Uint64 k = (dstr.length() % 16);

            if (k == 0)
                k = 16;
            for (Uint64 j = 0; j < dstr.length(); j += k, k = 16) {

                Uint64 x = strtoull(dstr.substr(j, k).c_str(), nullptr, 16);
                m_data.push_back(x);
            }
            reverse(m_data.begin(), m_data.end());
        }
    }
    ALCP_ASSERT(data[0] == val, "fromInt64: BIGNUM struct constructor failed");

    return StatusOk();
}

void
BigNum::Impl::fromBinary(const Uint8* buf, Uint64 size)
{
    ALCP_ASSERT(false, "Not Implemented");
}

void
BigNum::Impl::toBinary(Uint8* buf, Uint64 size)
{
    ALCP_ASSERT(false, "Not Implemented");
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
    return (total_bits() + 7) / 8;
}

void
BigNum::Impl::clear()
{
    m_data.clear();
    m_is_negative = false;
}

} // namespace alcp
