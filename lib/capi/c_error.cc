/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/error.h"

#include "alcp/base/error.hh"
#include "alcp/modulemanager.hh"
#include "alcp/types.hh"

#include <cstring>

EXTERN_C_BEGIN

using namespace alcp;
using namespace alcp::base;
using namespace alcp::module;

void
alc_error_str_internal(
    alc_error_t err, Uint8* buf, Uint64 size, const char* file, Uint64 line)
{
}

void
alcp_error_str(alc_error_t err, Uint8* buf, Uint64 size)
{
    auto  _code = static_cast<Uint64>(err);
    auto& m     = ModuleManager::getModule(_code);
    auto& e     = m.getModuleError(_code);

    auto str = e->message();
    size     = std::min(str.size(), size);

    snprintf((char*)buf, size, "%s", str.c_str());
}

Uint8
alcp_is_error(alc_error_t err)
{
    /*FIXME: Temporary fix for coverage mode error*/
    alc_error_t err_temp = err;
    if (err_temp == 0)
        return false;
    else {
        /*FIXME fix for memory error with ASAN*/
#ifdef ALCP_COMPILE_OPTIONS_SANITIZE
        printf("Error code: %ld\n", (long)err_temp);
#endif
        return true;
    }
}

EXTERN_C_END
