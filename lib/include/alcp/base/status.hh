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

#include "alcp/alcp.hh"
#include "alcp/interface/Ierror.hh"
#include "alcp/types.hh"
#include "error.hh"

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
  private:
    static constexpr StringView cAlcpErrorPrefix = "ALCP ERROR";

  public:
    explicit Status(IError&& ie)
        : m_code{ ie.code() }
        , m_message{ ie.message() }
    {}

    explicit Status(IError& ie)
        : m_code{ ie.code() }
        , m_message{ ie.message() }
    {}

    Status(IError& ie, const String& msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {}

    Status(IError& ie, const StringView msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {}

    Status(IError&& ie, const StringView msg)
        : m_code{ ie.code() }
        , m_message{ makeMessage(ie.message(), msg) }
    {}

    Status(const Status& s)
    {
        this->m_code = s.m_code;
        if (s.m_code != 0)
            this->m_message = s.m_message;
    }

    Status& operator=(const Status& s)
    {
        this->m_code = s.m_code;
        if (s.m_code != 0)
            this->m_message = s.m_message;
        // operator=(s);
        return *this;
    }

    // ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT(Status);

    bool operator==(const Status& other) const;
    bool operator!=(const Status& other) const;

    // Status::ok()
    // All is Well !!! if m_error is eOk or eNone
    ALCP_DEFS_NO_DISCARD bool ok() const;
    StringView                message() const { return m_message; }

    /**
     * @name code()
     *
     * @brief
     * Returns encoded error code
     *
     * @result          Uint64          encoded error code
     */
    Uint64 code() const { return m_code; }

    /**
     * @name update()
     *
     * @brief
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

#if 0
    bool update(ErrorBase& eb, const String& msg)
    {
        if (m_code)
            return false;

        m_code    = eb.code();
        m_message = makeMessage(eb, msg);
        return true;
    }
#endif
    bool update(const Status& s)
    {
        if (m_code)
            return false;

        m_code    = s.code();
        m_message = s.message();

        return true;
    }

  private:
    // Should initialize with an OK status
    explicit Status(Uint64 code)
        : m_code{ code }
    {
        // FIXME m_message has to be set somehow
    }

    friend ALCP_API_EXPORT Status StatusOk();

    String makeMessage(const StringView& module_error,
                       const StringView& details)
    {
        std::ostringstream ss{ "", std::ios_base::ate };
        ss << module_error << " : " << details;
        return ss.str();
    }

    Uint64 m_code;
    String m_message;

    // StringView m_err_message, m_err_specifics;
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
    ALCP_API_EXPORT Status Aborted(StringView msg);
    ALCP_API_EXPORT Status AlreadyExists(StringView msg);
    ALCP_API_EXPORT Status InternalError(StringView msg);
    ALCP_API_EXPORT Status InvalidArgument(StringView msg);
    ALCP_API_EXPORT Status NotFound(StringView msg);
    ALCP_API_EXPORT Status NotAvailable(StringView msg);
    ALCP_API_EXPORT Status NotImplemented(StringView msg);
    ALCP_API_EXPORT Status Unknown(StringView msg);
} // namespace status

} // namespace alcp::base
