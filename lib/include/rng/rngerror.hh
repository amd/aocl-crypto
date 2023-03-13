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

namespace alcp::rng {

enum ErrorCode : Uint16
{
    /* ErrorCode:eOk */
    eOk   = 0,
    eNone = eOk,

    /* ErrorCode:eNoEntropy */
    eNoEntropy = 5,

    /* ErrorCode:eNotPermitted */
    eNotPermitted = 7,

    /* ErrorCode:eNoEntropySource */
    eNoEntropySource = 9,
};

class RngError final : public ErrorBase
{

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override final
    {
        return false;
    }

    virtual Uint16 moduleId() const override { return ALC_MODULE_TYPE_RNG; }

  public:
    RngError()
        : ErrorBase{ ALC_MODULE_TYPE_RNG, ErrorCode::eOk }
    {
    }

    RngError(Uint64 ecode)
        : ErrorBase{ ALC_MODULE_TYPE_RNG, RngError::toUint16(ecode) }
    {
    }

    RngError(rng::ErrorCode ecode)
        : ErrorBase{ ALC_MODULE_TYPE_RNG, ecode }
    {
    }

    static Uint16 toUint16(Uint64 ecode) { return static_cast<Uint16>(ecode); }

    virtual ~RngError() {}

    // virtual Uint64 code() const override { return ErrorBase::code(); }

    virtual const String message() const override
    {
        return __toStr(ErrorBase::getModuleError());
    };

  private:
    static const String __toStr(Uint16 mod_err)
    {
        using ec           = alcp::rng::ErrorCode;
        using RngErrorMapT = std::unordered_map<Uint16, String>;
        static const RngErrorMapT err_to_str_map = {
            { ec::eOk, "All is Well !!" },
            { ec::eNoEntropy, "Not Enough Entropy" },
            { ec::eNotPermitted, "Not Permitted" },
            { ec::eNoEntropySource, "Entropy source not defined" },
        };

        RngErrorMapT::const_iterator it =
            err_to_str_map.find(static_cast<rng::ErrorCode>(mod_err));

        if (it != err_to_str_map.end()) {
            return it->second;
        } else {
            return "Rng: Unknown Error Occured";
        }
    }
};

} // namespace alcp::rng
