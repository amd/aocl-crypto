/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"

#include "error.hh"
#include "modulemanager.hh"

namespace alcp {

class ModuleManager::Impl
{
  public:
    std::unordered_map<alc_module_type_t, std::vector<Module*>> m_modules;
};

ModuleManager::ModuleManager()
    : impl{ new Impl }
{
    std::cout << "Size is : " << sizeof(ModuleManager)
              << "  and pimpl: " << sizeof(Impl) << std::endl;
}

ModuleManager&
ModuleManager::getInstance()
{
    static ModuleManager mm;
    return mm;
}

ModuleManager::~ModuleManager() {}

Module*
ModuleManager::findModule(const alc_module_info_t* ainfo, alc_error_t& err)
{

    std::vector<Module*> loc = impl->m_modules.at(ainfo->type);

    for (auto& m : loc) {
        switch (m->getType()) {

            case ALC_MODULE_TYPE_CIPHER: {
                alc_error_t e;
                if (m->isSupported(ainfo->data.cipher, e))
                    if (Error::isError(e))
                        return m;
            } break;

            case ALC_MODULE_TYPE_MAC:
                break;
            case ALC_MODULE_TYPE_RNG:
                break;
            case ALC_MODULE_TYPE_DIGEST:
                break;
            default:
                break;
        }
    }
    return nullptr;
}
} // namespace alcp
