/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/errorbase.hh"
#include "alcp/module.hh"

namespace alcp::bn {

enum ErrorCode : Uint16
{
    /* ErrorCode:eOk */
    eOk   = 0,
    eNone = eOk,

    /* ErrorCode:eInvalidArgument
     *
     * Argument passed to a function, or part of the configuration
     * Should be used to indicate that the application cannot request
     * for services as the configuration sent across is not valid
     */
    eInvalidArgument = 2,
    eFloatingPoint   = 3,
};

class BigNumError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        return false;
    }

    virtual Uint16 moduleId() const override { return ALC_MODULE_TYPE_BIGNUM; }

  public:
    BigNumError()
        : ErrorBase{ ErrorCode::eOk }
    {
        setModuleError(ErrorCode::eOk);
    }

    BigNumError(Uint64 ecode)
        : ErrorBase{ ecode }
    {}

    BigNumError(bn::ErrorCode ecode)
        : ErrorBase{ ErrorCode::eOk }
    {
        if (ecode != eOk) {
            ErrorBase::setModuleError(toUint16(ecode));
        }
    }

    static Uint16 toUint16(bn::ErrorCode ecode)
    {
        return static_cast<Uint16>(ecode);
    }

    virtual ~BigNumError() {}

    // virtual Uint64 code() const override { return ErrorBase::code(); }

    virtual const String message() const override
    {
        return __toStr(ErrorBase::getModuleError());
    };

  private:
    static const String __toStr(Uint16 mod_err)
    {
        using ec              = alcp::bn::ErrorCode;
        using BigNumErrorMapT = std::unordered_map<Uint16, String>;
        static const BigNumErrorMapT err_to_str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eInvalidArgument, "Invalid Asrgument" },
            { ec::eFloatingPoint, " Invalid Operation : Divide By Null or 0 " },
        };

        BigNumErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<bn::ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "BigNum: Unknown Error Occured";
        }
    }
};

} // namespace alcp::bn
