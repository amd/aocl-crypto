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

#include "alcp/types.hh"

#include <sstream>

namespace alcp {


#if defined(__GNUC__) || defined(CLANG)
template<typename... Args>
String
formatter(Args&&... args)
{
    std::stringstream oss;
    // using fold expression
    (oss << ... << args);
    return oss.str();
}

#else
#define formatter(const char* format, ...) printf(format, __VA_ARGS__)
#define va_formatter(const char* format, va_list ap) vprintf(format, ap)
#endif

String demangle(const char*);

/**
 * Describes the location of a line of code.
 * You can get one of these with #ALCP_CURRENT_LINE.
 */
struct SourceLocation
{
    /// Called by #ALCP_CURRENT_LINE only.
    SourceLocation(const char* file, const Uint32 line, const char* function)
        : SourceLocation{ file, line, function, nullptr }
    {
    }

    SourceLocation(const char*  file,
                   const Uint32 line,
                   const char*  function,
                   const char*  prettyFunction)
        : m_file{ file }
        , m_line{ line }
        , m_function{ function }
        , m_pretty_function{ prettyFunction }
    {
    }

    string str() const
    {
        return formatter(
            "  ", m_function, "@", relativeFile(), ":", std::to_string(m_line));
    }

    string relativeFile() const;
    string qualifiedFunction() const;

    /// __FILE__
    const char* m_file;
    /// __LINE__
    Uint32 m_line;
    /// __func__
    const char* m_function;
    /// __PRETTY_FUNCTION__
    const char* m_pretty_function;
};

#if defined(MSVC)
#define ALCP_PRETTY_FUNCTION __FUNCSIG__
#elif defined(__GNUC__) || defined(CLANG)
#define ALCP_PRETTY_FUNCTION __PRETTY_FUNCTION__
#endif

/**
 * Construct fully qualified source location
 */
#define ALCP_SORUCE_LOCATION_PRETTY()                                          \
    alcp::SourceLocation(__FILE__, __LINE__, __func__, ALCP_PRETTY_FUNCTION)

#define ALCP_SOURCE_LOCATION()                                                 \
    alcp::SourceLocation(__FILE__, __LINE__, __func__)

} // namespace alcp

