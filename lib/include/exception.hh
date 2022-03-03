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

#include <exception>
#include <string>

#include <alcp/error.h>

#include <error.hh>

namespace alcp {

/**
 * \brief        ALCP exception base class
 * \notes        Builds on top of easy to use alc_error_t
 *
 */
class Exception : public std::exception
{
  public:
    virtual ~Exception() throw() {}

    explicit Exception(alc_error_t e, const std::string& s)
        : m_error_type{ e }
        , m_what{ s }
    {}

    explicit Exception(alc_error_t e, const char* s)
        : Exception{ e, std::string(s) }
    {}

    const char* what() const throw() { return m_what.c_str(); }

    const std::string& getDetails() const { return m_what; }

    void setDetails(const std::string& s) { m_what = s; }

    alc_error_t getError() const { return m_error_type; }

    void setError(alc_error_t e) { m_error_type = e; }

  private:
    alc_error_t m_error_type;
    std::string m_what;
};

class InvalidArgumentException : public Exception
{
  public:
    explicit InvalidArgumentException(const std::string& s)
        : Exception{ ALC_ERROR_INVALID_ARG, s }
    {}

    explicit InvalidArgumentException(const char* s)
        : InvalidArgumentException{ std::string(s) }
    {}
};

class NotSupportedException : public Exception
{};

class GenericException : public Exception
{
  public:
    explicit GenericException(const std::string& s)
        : Exception{ ALC_ERROR_GENERIC, s }
    {}
};

class NotImplemented : public Exception
{
  private:
    NotImplemented(const std::string& pMsg, const std::string& pFunc)
        : Exception{ ALC_ERROR_NOT_EXISTS, "" }
    {
        m_text = pFunc + pMsg;
        setDetails(m_text);
    }

  public:
    NotImplemented()
        : NotImplemented(m_def_str, __FUNCTION__)
    {}

    virtual const char* what() const noexcept { return m_text.c_str(); }

  private:
    static const std::string m_def_str;
    std::string              m_text;
};

} // namespace alcp
