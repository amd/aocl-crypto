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

namespace alcp::cipher {

enum ErrorCode : Uint16
{
    /* ErrorCode:eOk */
    eOk   = 0,
    eNone = eOk,

    /* ErrorCode:eInvaidValue */
    eInvaidValue = 5,

    /* ErrorCode:eNotPermitted */
    eNotPermitted = 7,

    /* ErrorCode:eAuthenticationFailure */
    eAuthenticationFailure = 9,

    /* ErrorCode:eInavlidCipher */
    eInavlidCipher = 11,

    /* ErrorCode:eInavlidMode */
    eInavlidMode = 13,

    /* ErrorCode:eHardwareFailed */
    eHardwareFailed = 15,

    /* ErrorCode:eDecryptFailed */
    eDecryptFailed = 17,

    /* ErrorCode:eEncryptFailed */
    eEncryptFailed = 19,

    // TODO: Need to extend this as time goes
};

class AesError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        return false;
    }

    virtual Uint16 moduleId() const override { return ALC_MODULE_TYPE_RNG; }

  public:
    AesError()
        : ErrorBase{ ErrorCode::eOk }
    {
        setModuleError(ErrorCode::eOk);
    }

    AesError(Uint64 ecode)
        : ErrorBase{ ecode }
    {
    }

    AesError(cipher::ErrorCode ecode)
        : ErrorBase{ ErrorCode::eOk }
    {
        if (ecode != eOk) {
            ErrorBase::setModuleError(toUint16(ecode));
        }
    }

    static Uint16 toUint16(cipher::ErrorCode ecode)
    {
        return static_cast<Uint16>(ecode);
    }

    virtual ~AesError() {}

    // virtual Uint64 code() const override { return ErrorBase::code(); }

    virtual const String message() const override
    {
        return __toStr(ErrorBase::getModuleError());
    };

    // Gets the module name
    virtual String getName() override { return mapModuleName(moduleId()); }

    virtual alc_module_type_t getType() override
    {
        return static_cast<alc_module_type_t>(moduleId());
    }

  private:
    static const String __toStr(Uint16 mod_err)
    {
        using ec           = alcp::cipher::ErrorCode;
        using AesErrorMapT = std::unordered_map<Uint16, String>;
        static const AesErrorMapT err_to_str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eInvaidValue, "Invalid Value for Argument" },
            { ec::eAuthenticationFailure,
              "Authenticty/Integrity check failed!" },
            { ec::eInavlidCipher,
              "Cannot find implementation for requested Cipher!" },
            { ec::eInavlidMode,
              "Cannot find implementation for requested mode!" },
            { ec::eInavlidMode, "Hardware reported error/failed state!" },
            { ec::eDecryptFailed,
              "Decryption algorithm reported unexpected failure!" },
            { ec::eEncryptFailed,
              "Encryption algorithm reported unexpected failure!" },
        };

        // FIXME: An AES namespace might be needed in future.
        AesErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<cipher::ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "Rng: Unknown Error Occured";
        }
    }
};

} // namespace alcp::cipher
