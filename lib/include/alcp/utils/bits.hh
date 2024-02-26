/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base/exception.hh"
#include "alcp/types.hh"

#include <type_traits>

namespace alcp::utils {

static inline Uint32
RotateRight(Uint32 value, Uint32 count)
{
#if 0
    __asm__("rorl %%cl, %0" : "+r"(value) : "c"(count));
    return value;
#else
    return value >> count | value << (32 - count);
#endif
}

static inline Uint64
RotateRight(Uint64 value, Uint64 count)
{
#if 0
    __asm__("rorq %%cl, %0" : "+r"(value) : "c"(count));
    return value;
#else
    return value >> count | value << (64 - count);
#endif
}

static inline Uint32
RotateLeft(Uint32 value, Uint32 count)
{
    return value << count | value >> (32 - count);
}

static inline Uint64
RotateLeft(Uint64 value, Uint64 count)
{
    return value << count | value >> (64 - count);
}

constexpr Uint32 BitsPerByte   = 8;
constexpr Uint32 BytesPerWord  = 4;
constexpr Uint32 BytesPerDWord = 8;

template<typename T>
T
BytesPer()
{
    return sizeof(T);
}

template<typename T>
constexpr T
BitsInBytes(T x)
{
    return x / 8;
}

template<typename T>
constexpr T
BitSizeOf(T x)
{
    return x / BitsPerByte;
}

template<typename T>
constexpr T
ByteSizeOf(T x)
{
    return x * BytesPer<T>();
}

template<typename T>
constexpr T
GetByte(T val, int idx)
{
    Uint32 offset = idx * 8;

    return (val & (0xff << offset)) >> offset;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
constexpr Uint32
BytesToWord(T byte0, T byte1, T byte2, T byte3)
{
    return ((Uint32)byte3 << 24) | ((Uint32)byte2 << 16) | ((Uint32)byte1 << 8)
           | (byte0);
}

template<typename T,
         int size                                = sizeof(T) * 8,
         std::enable_if_t<std::is_integral_v<T>> = 0>
class Bits
{
  public:
    explicit Bits(T t)
        : m_val{ t }
    {}

    T extract(int start, int end) const
    {
        assert(end >= start);
        int nbits = end - start;
        T   mask  = ~(1UL << nbits);

        return (T)(m_val >> start) & mask;
    }

    void set(int start, int end)
    {
        NotImplementedException(SourceLocation(__FILE__, __LINE__, "set"));
    }
    void reset(int start, int end)
    {
        NotImplementedException(SourceLocation(__FILE__, __LINE__, "reset"));
    }
    void replace(int start, int end)
    {
        NotImplementedException(SourceLocation(__FILE__, __LINE__, "replace"));
    }

  private:
    Bits() {}
    Bits(const Bits&) {}
    Bits& operator=(const Bits&) {}

  private:
    T m_val;
};

} // namespace alcp::utils
