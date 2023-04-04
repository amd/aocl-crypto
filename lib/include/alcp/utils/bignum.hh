/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.hh"
#include "alcp/base.hh"
#include "alcp/macros.h"
#include "alcp/rng.h"

namespace alcp {

class ALCP_API_EXPORT BigNum final
{

  public:
    BigNum();
    ~BigNum();

    BigNum(const BigNum& b);
    BigNum(const BigNum&& b);
    BigNum& operator=(const BigNum& rhs);

  public:
    /* Unary -(minus) operator */
    BigNum operator-();

    /* Arithmetic operation */
    BigNum operator+(const BigNum& rhs);
    BigNum operator-(const BigNum& rhs);

    BigNum operator*(const BigNum& rhs);

    BigNum operator/(const BigNum& rhs);

    BigNum operator%(const BigNum& rhs);

    /* Binary operation */
    BigNum operator>>(int shifts);
    BigNum operator<<(int shifts);

    void exp_mod(const BigNum& num, const BigNum& exp, const BigNum& mod);

    /* Arithmetic + Assignment */
    void operator+=(const BigNum& rhs);
    void operator-=(const BigNum& rhs);
    void operator*=(const BigNum& rhs);
    void operator/=(const BigNum& rhs);
    void operator%=(const BigNum& rhs);
    /* Logical + Assignment */
    void operator>>=(int shifts);
    void operator<<=(int shifts);
    bool operator==(const BigNum& rhs);
    bool operator!=(const BigNum& rhs);
    bool operator>(const BigNum& rhs);
    bool operator<(const BigNum& rhs);

    /* Increment/Decrement */
    void operator++();
    void operator--();

    bool isZero() const;
    bool isOne() const;
    bool isNegative() const;

    Int64 toInt64() const;
    Int32 toInt32() const;
    void  toBinary(Uint8* buf, Uint64 size);

    void fromInt64(const Int64 val);
    void fromInt32(const Int32 val);

    void fromUint64(const Uint64 val);
    void fromUint32(const Uint32 val);
    void fromBinary(const Uint8* buf, Uint64 size);

    int randomGenerate(int bits, int top, int bottom, unsigned int strength);
    int randomGenerate(int bytes, int top, int bottom);
    int privateRandom(int bits, int top, int bottom, unsigned int strength);
    int privateRandom(int bits, int top, int bottom);
    int randomRange(const BigNum* range, unsigned int strength);
    int randomRange(const BigNum* range);
    int privateRandomRange(const BigNum* range, unsigned int strength);
    int privateRandomRange(const BigNum* range);

    enum class Format
    {
        eBinary,
        eDecimal,
        eHex,
    };

    /**
     * @brief Convert from Decimal or Hex string to BigNum
     *
     * @param str       The string containing the number
     * @param format    Format of the string, Binary,Decimal,Hex
     */
    Status       fromString(const String& str, Format f = Format::eDecimal);
    const String toString(Format f = Format::eDecimal) const;

    const void* data() const;
    std::size_t size() const;
    std::size_t size_bits() const;

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace alcp
