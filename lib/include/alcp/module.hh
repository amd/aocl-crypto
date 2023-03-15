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

#include "alcp/interface/Ierror.hh"
#include "alcp/interface/Imodule.hh"
#include "alcp/types.hh"
#include "rng/rngerror.hh"

#include <map>
#include <string>

namespace alcp::module {

enum Type : Uint16
{
    eModuleNone = 0,
    eModuleBase = eModuleNone,

    eModuleCipher,
    eModuleDigest,
    eModuleRng,
    eModuleMac,
    eModuleEc,

    eModuleMax, /* should be last entry */
};

/* FIXME: following must be removed in favour of alcp::module::Type */
typedef enum _alc_module_type
{
    ALC_MODULE_TYPE_NONE = 0,

    ALC_MODULE_TYPE_CIPHER,
    ALC_MODULE_TYPE_DIGEST,
    ALC_MODULE_TYPE_RNG,
    ALC_MODULE_TYPE_MAC,
    ALC_MODULE_TYPE_EC,

    ALC_MODULE_TYPE_MAX,
} alc_module_type_t;

class ModuleBase : public IModule
{
  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(ModuleBase);

    virtual String moduleName() const override { return "Base"; }
    virtual Uint16 moduleId() const override
    {
        return static_cast<Uint16>(eModuleBase);
    };
};

} // namespace alcp::module

// FIXME: contents below should end up in lib/rng/rng_module.cc
namespace alcp::rng {
class RngModule final : public alcp::module::ModuleBase
{
  public:
    virtual String moduleName() const override { return "Rng"; }

    virtual Uint16 moduleId() const override
    {
        return static_cast<Uint16>(alcp::module::eModuleRng);
    };

    virtual const IError& getModuleError(Uint64 code) const override
    {
        auto aa = new RngError(code);
        return *aa;
    }
};

} // namespace alcp::rng
