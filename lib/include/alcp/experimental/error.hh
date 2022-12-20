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
 */

#include "types.hh"

#include <string>
#include <string_view>
#include <unordered_map>

#pragma once

namespace alcp {

/**
 * Some of the Error codes are similar but based on the
 * application one makes more sense than other.
 * Application developers are encouraged to use them accordingly.
 */
enum ErrorCode : Uint16
{
    /* ErrorCode:eOk
     *
     * Though this does not signify an error, but a status
     * that is a success. Application should always check
     * for this before proceeding.
     */
    eOk   = 0,
    eNone = eOk,

    /* ErrorCode:eUknown
     *
     * An error has occured but cannot be categorized under
     * any of the other
     */
    eUnknown = 1,

    /* ErrorCode:eInvalidArgument
     *
     * Argument passed to a function, or part of the configuration
     * Should be used to indicate that the application cannot request
     * for services as the configuration sent across is not valid
     */
    eInvalidArgument = 2,

    /* ErrorCode:eNotFound
     */
    eNotFound = 4,

    /* ErrorCode:eExists
     *
     * A plugin that already exists, but register is called again
     * A file that to be created but an entry exits, etc
     */
    eExists = 8,

    /* ErrorCode::eNotImplemented
     *
     * A feature, function, subsystem not yet implemented
     */
    eNotImplemented = 16,

    /* ErrorCode::eNotAvailable
     *
     * A feature, function, sybsystem, or a device exists/implemented but
     * not available for use
     */
    eNotAvailable = 32,

    /* ErrorCode::eInternal
     *
     * Internal Error could be described by rest of the error code
     */
    eInternal = 64,

    /* ErrorCode::eMaxDontUse
     *
     * Dont use, here to mark the largest error code
     */
    eMaxDontUse = 128,
};

class Error
{
  public:
    Error()
        : m_error_code{ ErrorCode::eOk }
    {}

    Error(ErrorCode ecode)
        : m_error_code{ ecode }
    {}

    virtual ~Error(){};

    virtual bool operator==(const Error& other) const
    {
        return this->m_error_code == other.m_error_code;
    }

    virtual bool operator!=(const Error& other) const
    {
        return this->m_error_code not_eq other.m_error_code;
    }

    /**
     * @brief
     *
     * @return Uint64   A combined error code,
     */
    virtual Uint64 code() const { return static_cast<Uint64>(m_error_code); }

    virtual std::string_view message() const
    {
        using ec        = alcp::ErrorCode;
        using ErrorMapT = std::unordered_map<ErrorCode, std::string>;

        static const ErrorMapT str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eExists, "Already Exists" },
            { ec::eInternal, "Internal Error" },
            { ec::eInvalidArgument, "Invalid Argument" },
            { ec::eNotAvailable, "Not Available" },
            { ec::eNotFound, "Not Found" },
            { ec::eNotImplemented, "Not Implemented" },
        };

        ErrorMapT::const_iterator it = str_map.find(m_error_code);

        if (it != str_map.end()) {
            return it->second;
        } else {
            return "Unknown Error";
        }
    }

  protected:
    ErrorCode m_error_code;
};

} // namespace alcp
