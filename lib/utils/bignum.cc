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

/* FIXME: remove this once we have ALCP's own BigNum */
#define ALCP_BIGNUM_USE_OPENSSL 1

#if defined(ALCP_BIGNUM_USE_OPENSSL)
#include "../impl/bignum_openssl.cc"
#elif defined(ALCP_BIGNUM_USE_IPP)
#include "../impl/bignum_openssl.cc"
#else
#include "../impl/bignum_alcp.cc"
#endif

namespace alcp {

BigNum::BigNum()
    : m_pimpl{ std::make_unique<BigNum::Impl>() }
{}

BigNum::~BigNum() {}


BigNum::BigNum(const BigNum& b)
{
    // throw NotImplementedException(ALCP_SOURCE_LOCATION());
}

BigNum::BigNum(const BigNum&& b)
{
    // throw NotImplementedException(ALCP_SOURCE_LOCATION());
}

Int64
BigNum::toInt64() const
{
    return pImpl()->toInt64();
}

Int32
BigNum::toInt32() const
{
    return pImpl()->toInt32();
}

void
BigNum::fromUint64(const Uint64 val)
{
    pImpl()->fromUint64(val);
}

void
BigNum::fromInt64(const Int64 val)
{
    pImpl()->fromInt64(val);
}

void
BigNum::fromInt32(const Int32 val)
{
    pImpl()->fromInt32(val);
}

Status
BigNum::fromString(const String& str, Format f)
{
    return pImpl()->fromString(str, f);
}

const String
BigNum::toString() const
{
    return pImpl()->toString();
}

void
BigNum::operator=(const BigNum& rhs)
{
    // throw NotImplementedException(ALCP_SOURCE_LOCATION());
}

BigNum
BigNum::operator+(const BigNum& rhs)
{
    return pImpl()->add(rhs);
}

BigNum
BigNum::operator-(const BigNum& rhs)
{
    return pImpl()->sub(rhs);
}

#if 0
BigNum
BigNum::operator*(const BigNum& rhs)
{
    return pImpl()->mul(rhs);
}

BigNum
BigNum::operator/(const BigNum& rhs)
{
    return pImpl()->div(rhs);
}

inline BigNum
BigNum::operator%(const BigNum& rhs)
{
    return pImpl()->mod(rhs);
}

bool
BigNum::operator==(const BigNum& rhs)
{
    return pImpl()->eq(rhs);
}

bool
BigNum::operator!=(const BigNum& rhs)
{
    return pImpl()->neq(rhs);
}

#endif
} // namespace alcp
