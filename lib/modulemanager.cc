/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#include <iostream> /* TODO: Remove this after testing */
#include <list>
#include <unordered_map>
#include <vector>

#include "alcp/base/error.hh"
#include "alcp/cipher/cipher_module.hh"
#include "alcp/module.hh"
#include "alcp/modulemanager.hh"
#include "rng/include/rng_module.hh"

namespace alcp {
using namespace alcp::module;

using errorMapT = std::unordered_map<Uint16, IModule&>;
static errorMapT m_module_error_map;

#if 0
class ModuleManager::Impl
{
  private:
    using errorMapT = std::unordered_map<Uint16, IError&>;
    errorMapT m_module_error_map;

  public:
    bool addModuleError(Uint16 moduleId, IError const& ie);
};
#endif

// ModuleManager::ModuleManager()
//: impl{ new Impl }
//{
// std::cout << "Size is : " << sizeof(ModuleManager)
//           << "  and pimpl: " << sizeof(Impl) << std::endl;
//}

class NullError : public ErrorBase
{
  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(NullError);

    NullError(Uint64 code)
        : ErrorBase(code)
    {
    }

    virtual const String detailedError() const override
    {
        return "NullErrorModule";
    }

    bool operator==(const IError& other) { return isEq(*this, other); }

  protected:
    virtual bool isEq(IError const& lhs, IError const& rhs) const override
    {
        return false;
    }
};

class DefaultModule : public ModuleBase
{

  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(DefaultModule);

    DefaultModule(Uint16 mid) {}

    virtual const std::unique_ptr<IError> getModuleError(
        Uint64 code) const override
    {
        auto ne = std::make_unique<NullError>();
        return ne;
    }
};

class GenericModule : public ModuleBase
{

  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(GenericModule);

    GenericModule(Uint16 mid) {}

    virtual const std::unique_ptr<IError> getModuleError(
        Uint64 code) const override
    {
        auto ge = std::make_unique<GenericError>(code);
        return ge;
    }
};

const IModule&
ModuleManager::getModule(Uint16 mid)
{
    errorMapT::const_iterator it = m_module_error_map.find(mid);
    static DefaultModule      dm;

    if (it != m_module_error_map.end()) {
        return it->second;
    }

    return dm;
}

bool
ModuleManager::addModuleError(Uint16 moduleId, IError const& ie)
{
    errorMapT::const_iterator it = m_module_error_map.find(moduleId);

    if (it != m_module_error_map.end()) {
        // return it->setModuleError();
    }

    return true;
}

template<typename Module>
void
registerModule(Uint16 moduleType)
{
    static Module  modulename;
    static Module& ref_module = modulename;
    m_module_error_map.insert({ moduleType, ref_module });
}

static void
registerModules()
{
    registerModule<alcp::cipher::CipherModule>(alcp::module::eModuleCipher);
    registerModule<alcp::rng::RngModule>(alcp::module::eModuleRng);
    registerModule<GenericModule>(alcp::module::eModuleGeneric);
}
ModuleManager::ModuleManager()
{
    registerModules();
}

#if 0
IError const&
ModuleManager::getModuleError(Uint16 moduleId)
{
    errorMapT::const_iterator it = m_module_error_map.find(moduleId);

    if (it != m_module_error_map.end()) {
        return it->second;
    }

    return NullError{};
}
#endif

} // namespace alcp
