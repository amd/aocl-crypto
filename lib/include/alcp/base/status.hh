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

#include "alcp/base/error.hh"
#include "alcp/interface/Ierror.hh"
#include "alcp/types.hh"

namespace alcp::base {

/*
 * Example:
 *
 *   alcp::Status result = DoSomething();
 *   if (!result.ok()) {
 *     LOG(ERROR) << result;
 *   }
 */

class Status final
{
  public:
    // Should initialize with an OK status
    Status() {}

    Status(ErrorCode code)
        : m_error{ code }
    {}

    Status(ErrorCode code, std::string_view msg)
        : m_error{ code }
        , m_message{ msg }
    {}

    Status(StringView msg)
        : m_err_message { msg }
    {
    }

    Status(IError& ie, StringView msg)
        : m_code { ie.code() }
        ,m_err_message { msg }
    {
    }

    Status(IError& ie, const String& msg)
        : Status{}
    {
        m_message = makeMessage(ie.message(), msg);
    }

    ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT(Status);

    bool operator==(const Status& other) const;
    bool operator!=(const Status& other) const;

    // Status::ok()
    // All is Well !!! if m_error is eOk or eNone
    ALCP_DEFS_MUST_USE_RETURN bool ok() const;
    std::string_view               message() const { return m_message; }

    /**
     * @name code()
     *
     * @detail
     * Returns encoded error code
     *
     * @params
     * n/a
     *
     * @result          Uint64          encoded error code
     */
    Uint64 code() const { return m_code; }

    /**
     * @name update()
     *
     * @detail
     * Update the error code and message only if there was no error earlier;
     * this is done to presever the very first error that happens
     *
     * @param[in]       ie      IError interface from any component
     *
     * @return          boolean Indication if the update was successful
     */
    bool update(IError& ie, const String& msg)
    {
        if (m_code)
            return false;

        m_code    = ie.code();
        m_message = makeMessage(ie.message(), msg);
        return true;
    }

    bool update(const Status& s)
    {
        if (m_code)
            return false;

        m_code        = s.code();
        m_err_message = s.message();
        // m_err_specifics = msg;

        return true;
    }

  private:
    String& makeMessage(const String& module_error, const String& details)
    {
        m_message = module_error + String(" ") + details;
        return m_message;
    }

    Uint64 m_code;
    String m_message;

    StringView m_err_message, m_err_specifics;
};

inline bool
Status::operator==(const Status& other) const
{
    return this->m_code == other.m_code;
}

inline bool
Status::ok() const
{
    return m_code == 0;
}

/**
 * @brief StatusOk()
 * Useful function when returning from a function
 *
 * @detail
 * Status some_function(some_arg_t arg)
 * {
 *    // .. do something important ..
 *
 *    return StatusOk();
 * }
 *
 * @return
 * Status with message and a code.
 */
inline Status
StatusOk()
{
    return Status();
}

// clang-format off
/*
 * Easy to use chekers
 */
ALCP_DEFS_MUST_USE_RETURN bool IsAborted(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsAlreadyExists(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsInternalError(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsInvalidArgument(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsNotFound(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsNotAvailable(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsNotImplemented(const Status& status);
ALCP_DEFS_MUST_USE_RETURN bool IsUnknown(const Status& status);

/*
 * Handy creators that return Status
 */
Status AbortedError(std::string_view msg);
Status AlreadyExistsError(std::string_view msg);
Status InternalError(std::string_view msg);
Status InvalidArgumentError(std::string_view msg);
Status NotFoundError(std::string_view msg);
Status NotAvailableError(std::string_view msg);
Status NotImplementedError(std::string_view msg);
Status UnknownError(std::string_view msg);

// clang-format on

} // namespace alcp::base
