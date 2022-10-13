/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#ifndef _INCLUDE_MODULE_H_
#define _INCLUDE_MODULE_H_ 2

#include <string>

#include "alcp/cipher.h"

#include "algorithm.hh"
#include "error.hh"

namespace alcp {

typedef enum _alc_module_type
{
    ALC_MODULE_TYPE_NONE = 0,

    ALC_MODULE_TYPE_CIPHER,
    ALC_MODULE_TYPE_DIGEST,
    ALC_MODULE_TYPE_RNG,
    ALC_MODULE_TYPE_MAC,

    ALC_MODULE_TYPE_MAX,
} alc_module_type_t;

typedef struct _alc_module_info
{
    alc_module_type_t type;
    union
    {
        const alc_cipher_info_p cipher;
        // const alc_digest_info_p digest;
        // const alc_mac_info_p mac;
        // const alc_aead_info_p aead;
        // const alc_rng_info_p rng;
    } data;
} alc_module_info_t;

typedef struct _alc_module_data
{

} alc_module_data_t;

class Module
{
  public:
    Module(alc_module_info_t* minfo);
    std::string       getName();
    alc_module_type_t getType();
    bool isSupported(const alc_cipher_info_p c, alc_error_t& e) const;

  private:
    alc_module_info_t m_info;

    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace alcp

#endif /* _INCLUDE_MODULE_H_ */
