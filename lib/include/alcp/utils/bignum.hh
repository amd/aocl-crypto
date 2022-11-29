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

#include "alcp/base.hh"
#include "alcp/exception.hh"

#include <memory> /* for unique_ptr */

namespace alcp {

class BigNum final
{
  public:
    BigNum();
    ~BigNum();

    BigNum(const BigNum& b) { NotImplemented(); }
    BigNum(const BigNum&& b) { NotImplemented(); }
    void operator=(const BigNum& rhs) { NotImplemented(); }

  public:
    /* Arithmetic operation */
    BigNum operator+(const BigNum& rhs);

    /* Arithmetic + Assignment */
    inline BigNum& operator+=(const BigNum& rhs)
    {
        *this = *this + rhs;
        return *this;
    }

#if 0

    BigNum operator-(const BigNum& rhs);
    BigNum operator*(const BigNum& rhs);
    BigNum operator/(const BigNum& rhs);
    BigNum operator%(const BigNum& rhs);

    /* Arithmetic + Assignment */
    BigNum& operator+=(const BigNum& rhs);
    BigNum& operator-=(const BigNum& rhs);
    BigNum& operator*=(const BigNum& rhs);
    BigNum& operator/=(const BigNum& rhs);
    BigNum& operator%=(const BigNum& rhs);

    /* Logical + Assignment */
    BigNum& operator>>=(const BigNum& rhs);
    BigNum& operator<<=(const BigNum& rhs);

    BigNum& operator==(const BigNum& rhs);
    BigNum& operator!=(const BigNum& rhs);

    /* Increment/Decrement */
    BigNum& operator++();
    BigNum& operator--();
#endif

    bool isZero();
    bool isOne();
    bool isNegative();

    Int64 toInt64();
    Int32 toInt32();

    void fromInt64(const Int64 val);
    void fromInt32(const Int32 val);

    void          fromString(const StringView& str);
    const String& toString() const;

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace alcp
