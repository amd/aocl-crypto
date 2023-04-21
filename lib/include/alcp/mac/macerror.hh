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

namespace alcp::mac {

enum ErrorCode : Uint16
{
    /* ErrorCode:eOk */
    eOk   = 0,
    eNone = eOk,
    eUpdateAfterFinalize,
    eEmptyKey,
    eAlreadyFinalized,
    eCopyWithoutFinalize,
    eDigestOperationError,
    eEmptyDigest
};

class MacError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        return false;
    }

  public:
    MacError()
        : ErrorBase{ ErrorCode::eOk }
    {}

    MacError(Uint64 ecode)
        : ErrorBase{ MacError::toUint16(ecode) }
    {}

    MacError(mac::ErrorCode ecode)
        : ErrorBase{ ecode }
    {}

    MacError(base::ErrorCode bcode, mac::ErrorCode ecode)
        : ErrorBase{ ecode }
    {
        setBaseError(static_cast<Uint16>(bcode));
        setModuleId(static_cast<Uint16>(alcp::module::Type::eModuleMac));
    }

    static Uint16 toUint16(Uint64 ecode) { return static_cast<Uint16>(ecode); }

    virtual ~MacError() {}

    virtual const String detailedError() const override
    {
        return __toStr(getModuleError());
    };

  private:
    static const String __toStr(Uint16 mod_err)
    {
        // using mac          = alcp::mac::ErrorCode;
        using MacErrorMapT = std::unordered_map<Uint16, String>;
        static const MacErrorMapT err_to_str_map = {
            { alcp::mac::ErrorCode::eOk, "All is Well !!" },
            { alcp::mac::ErrorCode::eUpdateAfterFinalize,
              "Cannot call update after finalize without reseting" },
            { alcp::mac::ErrorCode::eAlreadyFinalized,
              "Already finalized. Call reset before updating or finalizing "
              "Again" },
            { alcp::mac::ErrorCode::eCopyWithoutFinalize,
              "Cannot Copy MAC without finalizing" },
            { alcp::mac::ErrorCode::eEmptyKey, "MAC key cannot be empty" },
            { alcp::mac::ErrorCode::eEmptyDigest,
              "HMAC Digest cannot be empty" },
            { alcp::mac::ErrorCode::eDigestOperationError,
              "HMAC Failed During Internal Digest Operation" }
        };

        MacErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<alcp::mac::ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "MAC: Unknown Error Occured";
        }
    }
};

namespace status {
    ALCP_API_EXPORT Status UpdateAfterFinalzeError(StringView msg);
    ALCP_API_EXPORT Status AlreadyFinalizedError(StringView msg);
    ALCP_API_EXPORT Status CopyWithoutFinalizeError(StringView msg);
    ALCP_API_EXPORT Status EmptyKeyError(StringView msg);
    ALCP_API_EXPORT Status HMACDigestOperationError(StringView msg);
    ALCP_API_EXPORT Status EmptyHMACDigestError(StringView msg);

} // namespace status

} // namespace alcp::mac
