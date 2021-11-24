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

#ifndef _INCLUDE_MODULEMANAGER_H_
#define _INCLUDE_MODULEMANAGER_H_ 2

#include <memory> /* for std::unique_ptr */
#include <vector>

#include "alcp/alcp.h"

#include "module.hh"

namespace alcp {

class ModuleManager
{
  public:
    static ModuleManager& getInstance();

    bool isSupported(const alc_cipher_info_t* cinfo, Error& err);
#if 0
    // bool isSupported(const alc_digest_info_t* cinfo);
    // bool isSupported(const alc_rng_info_t* cinfo);
#endif

    Error* addModule(alc_module_info_t* minfo);
    Error* deleteModule(alc_module_info_t* minfo);

    bool requestModule(const alc_cipher_info_t* cinfo,
                       alc_cipher_ctx_t*        ctx,
                       Error&                   err);

#if 0
    bool   requestModule(const alc_digest_info_t* cinfo,
                         alc_digest_ctx_t*        ctx,
                         Error&                   err);
    bool   requestModule(const alc_rng_info_t* cinfo,
                         alc_rng_ctx_t*        ctx,
                         Error&                   err);
#endif

  public:
    ModuleManager(ModuleManager const&) = delete;
    void operator=(ModuleManager const&) = delete;

  private:
    ModuleManager();
    ~ModuleManager();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;

    std::vector<Module*> m_cipher;
    std::vector<Module*> m_digest;
    std::vector<Module*> m_rng;
    std::vector<Module*> m_mac;
};

} // namespace alcp

#endif /* _INCLUDE_MODULEMANAGER_H_ */
