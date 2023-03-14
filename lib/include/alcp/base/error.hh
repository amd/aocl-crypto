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
 */

#pragma once

#include "alcp/errorbase.hh"

namespace alcp::base {

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

class GenericError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        auto l = dynamic_cast<const GenericError&>(lhs);
        auto r = dynamic_cast<const GenericError&>(rhs);

        return l.moduleId() == r.moduleId()
               && l.getModuleError() == r.getModuleError();
    }

    /* Module ID for Generic errors is 0 */
    virtual Uint16 moduleId() const override { return 0; }

  public:
    GenericError()
        : ErrorBase{ ErrorCode::eOk }
    {
    }

    GenericError(Uint64 ecode)
        : ErrorBase{ ecode }
    {
    }

    GenericError(ErrorCode ecode)
        : ErrorBase{ static_cast<Uint64>(ecode) }
    {
    }

    virtual ~GenericError(){};

    // Gets the module name
    virtual String getName() override { return mapModuleName(moduleId()); }

    virtual alc_module_type_t getType() override
    {
        return static_cast<alc_module_type_t>(moduleId());
    }

    /**
     * @brief
     *
     * @return Uint64   A combined error code,
     */
    virtual Uint64 code() const override { return ErrorBase::code(); }

    /**
     * @detail
     *  Convert a given error code into message
     * @param
     * @return  String containing message description of the error
     */
    virtual const String message() const override
    {
        return __toStr(ErrorBase::getGenericError());
    }

  private:
    static const String __toStr(Uint16 mod_err)
    {
        using ec        = alcp::base::ErrorCode;
        using ErrorMapT = std::unordered_map<Uint16, std::string>;

        static const ErrorMapT err_to_str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eExists, "Already Exists" },
            { ec::eInternal, "Internal Error" },
            { ec::eInvalidArgument, "Invalid Argument" },
            { ec::eNotAvailable, "Not Available" },
            { ec::eNotFound, "Not Found" },
            { ec::eNotImplemented, "Not Implemented" },
        };

        ErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "Unknown Error";
        }
    }
};

} // namespace alcp::base
