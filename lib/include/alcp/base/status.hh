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

//#include "alcp/base/error.hh"
#include "alcp/interface/Ierror.hh"
#include "alcp/types.hh"

#include <sstream>

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
    explicit Status(IError&& ie)
        : m_code{ ie.code() }
        , m_message{ ie.message() }
    {
    }

    explicit Status(IError& ie)
        : m_code{ ie.code() }
        , m_message{ ie.message() }
    {
    }

    Status(IError& ie, const String& msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {
    }

    Status(IError& ie, const StringView msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {
    }

    Status(IError&& ie, const StringView msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {
    }

    ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT(Status);

    bool operator==(const Status& other) const;
    bool operator!=(const Status& other) const;

    // Status::ok()
    // All is Well !!! if m_error is eOk or eNone
    ALCP_DEFS_NO_DISCARD bool ok() const;
    std::string_view          message() const { return m_message; }

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
    // Should initialize with an OK status
    explicit Status(Uint64 code)
        : m_code{ code }
    {
    }

    friend Status StatusOk();

    String makeMessage(String const& module_error, String const& details)
    {
        std::ostringstream ss{ module_error, std::ios_base::ate };
        ss << module_error << " " << details;
        // m_message = module_error + String(" ") + details;
        // return m_message;
        return ss.str();
    }

    String makeMessage(const StringView& module_error,
                       const StringView& details)
    {
        std::ostringstream ss{ "", std::ios_base::ate };
        ss << module_error << " " << details;
        return ss.str();
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
Status
StatusOk();

// clang-format off
/*
 * Easy to use chekers
 */
ALCP_DEFS_NO_DISCARD bool IsAborted(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsAlreadyExists(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsInternalError(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsInvalidArgument(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsNotFound(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsNotAvailable(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsNotImplemented(const Status& status);
ALCP_DEFS_NO_DISCARD bool IsUnknown(const Status& status);
// clang-format on

/*
 * Handy creators that return Status
 */
namespace status {
    Status Aborted(StringView msg);
    Status AlreadyExists(StringView msg);
    Status InternalError(StringView msg);
    Status InvalidArgument(StringView msg);
    Status NotFound(StringView msg);
    Status NotAvailable(StringView msg);
    Status NotImplemented(StringView msg);
    Status Unknown(StringView msg);
} // namespace status

} // namespace alcp::base
