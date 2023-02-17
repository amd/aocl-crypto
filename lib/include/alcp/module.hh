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

#include <string>

// #include "alcp/cipher.h"
#include "alcp/base.hh"

#include "alcp/module.hh"
#include "algorithm.hh"

namespace alcp {

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

class Module
{
  public:
    ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(Module);

    std::string       getName();
    alc_module_type_t getType();
    // bool isSupported(const alc_cipher_info_p c, alc_error_t& e) const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace alcp
