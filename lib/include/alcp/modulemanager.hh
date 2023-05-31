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

#include "alcp/base.hh"
#include "alcp/defs.hh"
#include "alcp/module.hh"

#include "alcp/pattern/singleton.hh"

#include <memory> /* for std::unique_ptr */
#include <vector>

namespace alcp {

class ModuleManager : public Singleton<ModuleManager>
{
  public:
    static bool           addModule(IModule const& im);
    static IModule const& getModule(Uint16 id);
    /**
     * @brief   Register a module specific error handler
     *
     * @param[in]       mt      Module type
     * @param[in]       ie      Error Interface to the module error handler
     *
     * @return  boolean Status of whether the registration was success
     */
    static bool addModuleError(Uint16 moduleId, IError const& ie);

  public:
    ModuleManager();
    ~ModuleManager() = default;

    ModuleManager(ModuleManager const&) = delete;
    void operator=(ModuleManager const&) = delete;

  private:
    // class Impl;
    // std::unique_ptr<Impl> impl;
};

} // namespace alcp
