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

#include <bitset>
#include <type_traits>

namespace alcp {

class BigNum::Impl
{
    using typeT = Uint64;

  public:
    Impl();
    ~Impl() {}

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

    /* Cant compare BigNum at the moment */
    inline bool neq(const BigNum& rhs) { return true; }

    /* Cant compare BigNum at the moment */
    inline bool eq(const BigNum& rhs) { return false; }

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
{
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
    Int64 v = val;
    if (v < 0) {
        v             = -v;
        m_is_negative = true;
    }

    m_data.resize(1);
    m_data[0] = v;
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
        carry = ((*lstart > sum) && (*rstart > sum)) ? 1 : 0;

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
        carry = *lstart > sum ? 1 : 0;
        lstart++;
    }

    return carry;
}

BigNum
BigNum::Impl::add(const BigNum& rhs)
{
    BigNum result;

    auto rimpl   = rhs.pImpl();
    auto resimpl = result.pImpl();

    auto is_neg = (int)m_is_negative ^ (int)rimpl->m_is_negative;

    auto carry_occured = __add(m_data, rimpl->m_data, resimpl->m_data);

    if (!is_neg) {
        if (carry_occured) {
            resimpl->m_data.push_back(1);
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
    /* FIXME: re-do this */
    return rhs;
}

BigNum
BigNum::Impl::mul(const BigNum& rhs)
{
    // fast exponentation for multiplication
    BigNum result, tmp;
    auto   data = rhs.pImpl()->m_data;

    for (auto&& val : data) {
        while (val > 0) {
            result += tmp;
            tmp <<= 1;
            val >>= 1;
        }
    }

    return result;
}

BigNum
BigNum::Impl::div(const BigNum& rhs)
{
    BigNum result;

    ALCP_ASSERT(p_data(result) == NULL, "BN_div failed");

    return result;
}

BigNum
BigNum::Impl::mod(const BigNum& rhs)
{
    BigNum result = BigNum();
    ALCP_ASSERT(p_data(result) == NULL, "BN_div failed");

    return result;
}

BigNum
BigNum::Impl::lshift(int shifts)
{
    BigNum result;
    int    len = m_data.size() + (shifts / 64)
              + (((shifts % 64) > __builtin_clzll(m_data.back())));
    result.pImpl()->m_data.resize(len);

    return result;
}

BigNum
BigNum::Impl::rshift(int shifts)
{
    BigNum result;
    int    len = m_data.size() - (shifts / 64)
              - (((shifts % 64) > (64 - __builtin_clzll(m_data.back()))));
    result.pImpl()->m_data.resize(len);

    return result;
}

const String
BigNum::Impl::toString(Format f) const
{
    std::stringstream ss;
    BigNum::Impl      bn{ *this };

    if (m_is_negative) {
        ss << "-";
        bn.invert();
    }

    switch (f) {
        case BigNum::Format::eBinary: {
            for (auto&& v : bn.m_data) {
                std::bitset<sizeof(Uint64) * 8> b(v);

                ss << b.to_string();
            }
        } break;

        case Format::eDecimal: {
            for (auto&& v : bn.m_data) {

                ss << std::dec << v;
            }
        } break;
        default: {
            for (auto&& v : bn.m_data) {
                ss << std::hex << v;
            }
        } break;
    }

    return ss.str();
}

Status
BigNum::Impl::fromString(const String& str, BigNum::Format f)
{
    /* FIXME: re-do this */
    return StatusOk();
}

const void*
BigNum::Impl::data() const
{
    return nullptr;
}

std::size_t
BigNum::Impl::size() const
{
    return m_data.size() * sizeof(typeT);
}

} // namespace alcp
