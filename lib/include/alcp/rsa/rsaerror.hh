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
#include <string_view>

namespace alcp::rsa {

enum ErrorCode : Uint16
{
    /* ErrorCode:eOk */
    eOk   = 0,
    eNone = eOk,
    eNotPermitted,
    eUnavailable,
    eInternal
};

class RsaError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        return false;
    }

  public:
    RsaError()
        : ErrorBase{ ErrorCode::eOk }
    {}

    RsaError(Uint64 ecode)
        : ErrorBase{ RsaError::toUint16(ecode) }
    {}

    RsaError(rsa::ErrorCode ecode)
        : ErrorBase{ ecode }
    {}

    RsaError(base::ErrorCode bcode, rsa::ErrorCode ecode)
        : ErrorBase{ ecode }
    {
        setBaseError(static_cast<Uint16>(bcode));
        setModuleId(static_cast<Uint16>(alcp::module::Type::eModuleRsa));
    }

    static Uint16 toUint16(Uint64 ecode) { return static_cast<Uint16>(ecode); }

    virtual ~RsaError() {}

    virtual const String detailedError() const override
    {
        return __toStr(getModuleError());
    };

  private:
    static const String __toStr(Uint16 mod_err)
    {
        using ec           = alcp::rsa::ErrorCode;
        using RsaErrorMapT = std::unordered_map<Uint16, String>;
        static const RsaErrorMapT err_to_str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eNotPermitted, "Not Permitted" },
            { ec::eUnavailable,
              "Functionality is not Implemented or not Capable" },
        };

        RsaErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<rsa::ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "Rsa: Unknown Error Occured";
        }
    }
};

namespace status {
    ALCP_API_EXPORT Status Unavailable(StringView msg);
    ALCP_API_EXPORT Status NotPermitted(StringView msg);
    ALCP_API_EXPORT Status Generic(StringView msg);
} // namespace status

} // namespace alcp::rsa
