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

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Few useful types from 'std' so that we dont have to use the std::
// prefix everytime we refer to them, we also restrict their use in 'alcp'
// namespace
namespace alcp {

using std::pair;
using std::string;
using std::vector;

using String     = ::std::string;
using StringView = ::std::string_view;

} // namespace alcp

#include "alcp/macros.h"
#include "alcp/types.h"
namespace alcp {

typedef char          Schar;
typedef unsigned char Uchar;
typedef int           Sint;
typedef unsigned int  Uint;
typedef long          Slong;
typedef unsigned long Ulong;

typedef char*          pSchar;
typedef unsigned char* pUchar;
typedef long*          pSlong;
typedef unsigned long* pUlong;
typedef int*           pSint;
typedef unsigned int*  pUint;

typedef int8_t  Int8;
typedef int16_t Int16;
typedef int32_t Int32;
typedef int64_t Int64;

typedef uint8_t  Uint8;
typedef uint16_t Uint16;
typedef uint32_t Uint32;
typedef uint64_t Uint64;

/* Pointers */
typedef void* pVoid;

typedef int8_t*  pInt8;
typedef int16_t* pInt16;
typedef int32_t* pInt32;
typedef int64_t* pInt64;

typedef uint8_t*  pUint8;
typedef uint16_t* pUint16;
typedef uint32_t* pUint32;
typedef uint64_t* pUint64;

} // namespace alcp
