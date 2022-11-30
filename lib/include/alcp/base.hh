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

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <memory>
#include <sstream>
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

#if defined(__GNUC__) || defined(CLANG)

template<typename... Args>
std::string
formatter(Args&&... args)
{
    std::stringstream oss;
    // using fold expression
    (oss << ... << args);
    return oss.str();
}

#else
string
formatter(const char* format, ...) printf(format, __VA_ARGS__);
string
va_formatter(const char* format, va_list ap) vprintf(format, ap);
#endif

string
demangle(const char*);

} // namespace alcp


#include "alcp/experimental/defs.hh"
#include "alcp/experimental/types.hh"
#include "alcp/experimental/error.hh"
#include "alcp/experimental/status.hh"
#include "alcp/experimental/statusor.hh"
#include "alcp/experimental/exception.hh"

