/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "cipher/alc_cipher.hh"
#include "config.h"
#include <cipher/cipher.hh>
#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unordered_map>

using namespace alcp::testing;

std::unordered_map<alc_digest_mode_t, Uint64> MODE_SIZE = {
    { ALC_SHA2_224, 28 }, { ALC_SHA2_256, 32 },     { ALC_SHA2_384, 48 },
    { ALC_SHA2_512, 64 }, { ALC_SHA2_512_224, 28 }, { ALC_SHA2_512_224, 32 },
    { ALC_SHA3_224, 28 }, { ALC_SHA3_256, 32 },     { ALC_SHA3_384, 48 },
    { ALC_SHA3_512, 64 }, { ALC_SHAKE_128, 1 },     { ALC_SHAKE_256, 1 }
};

const int ERR_SIZE = 256;
Uint8     err_buf[ERR_SIZE];
void
Check_Error(alc_error_t err)
{
    if (alcp_is_error(err))
        alcp_error_str(err, err_buf, ERR_SIZE);
}