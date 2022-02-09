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

#include "config.h"
#include "types.hh"

namespace alcp::utils {

template<typename T>
constexpr inline T
ToBigEndian(T value);

template<typename T>
constexpr inline T
ToLittleEndian(T value);

template<typename T>
constexpr inline T
ReverseBytes(T value);

template<>
constexpr inline uint64
ReverseBytes(uint64 value)
{
    value = ((value & 0xFF00FF00FF00FF00ULL) >> 8U)
            | ((value & 0x00FF00FF00FF00FFULL) << 8U);
    value = ((value & 0xFFFF0000FFFF0000ULL) >> 16U)
            | ((value & 0x0000FFFF0000FFFFULL) << 16U);
    value = (value >> 32U) | (value << 32U);

    return value;
}

template<>
constexpr inline uint32
ReverseBytes(uint32 value)
{
    value = ((value & 0xFF00FF00U) >> 8U) | ((value & 0x00FF00FFU) << 8U);
    value = (value >> 16U) | (value << 16U);

    return value;
}

template<>
constexpr inline uint16
ReverseBytes(uint16 value)
{
    value = ((value & 0xFF00U) >> 8U) | ((value & 0x00FFU) << 8U);

    return value;
}

#if defined(ALCP_CONFIG_LITTLE_ENDIAN)
template<typename T>
constexpr T
ToLittleEndian(T value)
{
    return value;
}

template<typename T>
constexpr inline T
ToBigEndian(T value)
{
    return ReverseBytes<T>(value);
}

#else

template<typename T>
constexpr T
ToBigEndian(T value)
{
    return value;
}

template<typename T>
constexpr inline T
ToLittleEndian(T value)
{
    return ReverseBytes<T>(value);
}

#endif

} // namespace alcp::utils
