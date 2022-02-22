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

#include <type_traits>

#include "types.hh"

namespace alcp::utils {

constexpr uint32 BitsPerByte   = 8;
constexpr uint32 BytesPerWord  = 4;
constexpr uint32 BytesPerDWord = 8;

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
BytesInBits(T x)
{
    return x / BitsPerByte;
}

template<typename T>
constexpr T
BytesIn(T x)
{
    return x * BytesPer<T>();
}

template<typename T>
constexpr T
GetByte(T val, int idx)
{
    uint32 offset = idx * 8;

    return (val & (0xff << offset)) >> offset;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>, int> = 0>
constexpr uint32
BytesToWord(T byte0, T byte1, T byte2, T byte3)
{
    return ((uint32)byte3 << 24) | ((uint32)byte2 << 16) | ((uint32)byte1 << 8)
           | (byte0);
}

} // namespace alcp::utils
