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

#include "sourcelocation.hh"

#include <cstring>
#include <string>

namespace alcp {

/**
 * The base class for all exceptions.
 */
struct Exception : public std::exception
{
    Exception(const SourceLocation& where, string msg, int errNo)
        : m_message(msg + ": " + strerror(errNo))
        , m_errNo(errNo)
        , m_where(where)
    {}

    explicit Exception(const SourceLocation& where)
        : Exception(where, "", 0)
    {}

    Exception(const SourceLocation& where, std::string msg)
        : Exception(where, msg, 0)
    {}

    Exception(const SourceLocation& where, int errNo)
        : Exception(where, "", errNo)
    {
        m_message = strerror(errNo);
    }

    Exception(const Exception& other)
        : Exception(other.m_where, other.m_message, other.m_errNo)
    {}

    virtual ~Exception() throw() {}

    string str() const { return formatter(m_message, m_where.str()); }

    const char* what() const throw()
    {
        string s(str());
        /* FIXME: the 'new' could fail */
        /* TODO: convert this to stack based , and use strncopy() */
        char* cStr = new char[s.length() + 1];
        memcpy(cStr, s.c_str(), s.length() + 1);
        return cStr;
    }

    string         m_message;
    int            m_errNo;
    SourceLocation m_where;
};

/**
 * A fatal error that should exit the program.
 */
struct FatalErrorException : public Exception
{
    explicit FatalErrorException(const SourceLocation& where)
        : Exception(where)
    {}
    FatalErrorException(const SourceLocation& where, std::string msg)
        : Exception(where, msg)
    {}
    FatalErrorException(const SourceLocation& where, int errNo)
        : Exception(where, errNo)
    {}
    FatalErrorException(const SourceLocation& where, string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

struct DataFormatException : public Exception
{
    explicit DataFormatException(const SourceLocation& where)
        : DataFormatException(where, "", -1)
    {}
    DataFormatException(const SourceLocation& where, std::string msg)
        : DataFormatException(where, msg, -1)
    {}
    DataFormatException(const SourceLocation& where, int errNo)
        : DataFormatException(where, "", errNo)
    {}
    DataFormatException(const SourceLocation& where, string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

struct NotReachedException : public Exception
{
    explicit NotReachedException(const SourceLocation& where)
        : Exception(where)
    {}
    NotReachedException(const SourceLocation& where, std::string msg)
        : NotReachedException(where, msg, -1)
    {}
    NotReachedException(const SourceLocation& where, int errNo)
        : NotReachedException(where, "", errNo)
    {}
    NotReachedException(const SourceLocation& where, string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

struct NotImplementedException : public Exception
{
    explicit NotImplementedException(const SourceLocation& where)
        : Exception(where)
    {}
    NotImplementedException(const SourceLocation& where, std::string msg)
        : NotImplementedException(where, msg, -1)
    {}
    NotImplementedException(const SourceLocation& where, int errNo)
        : NotImplementedException(where, "", errNo)
    {}
    NotImplementedException(const SourceLocation& where, string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

} // namespace alcp
