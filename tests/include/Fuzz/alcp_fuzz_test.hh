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
#include "config.h"
#include <cstddef>
#include <cstdint>
#include <dlfcn.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <map>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

std::map<alc_digest_mode_t, alc_digest_len_t> sha2_mode_len_map = {
    { ALC_SHA2_224, ALC_DIGEST_LEN_224 },
    { ALC_SHA2_256, ALC_DIGEST_LEN_256 },
    { ALC_SHA2_384, ALC_DIGEST_LEN_384 },
    { ALC_SHA2_512, ALC_DIGEST_LEN_512 },
    { ALC_SHA3_224, ALC_DIGEST_LEN_224 },
    { ALC_SHA3_256, ALC_DIGEST_LEN_256 },
    { ALC_SHA3_384, ALC_DIGEST_LEN_384 },
    { ALC_SHA3_512, ALC_DIGEST_LEN_512 },
    { ALC_SHAKE_128, ALC_DIGEST_LEN_CUSTOM_SHAKE_128 },
    { ALC_SHAKE_256, ALC_DIGEST_LEN_CUSTOM_SHAKE_256 }
};

std::map<alc_digest_mode_t, std::string> sha2_mode_string_map = {
    { ALC_SHA2_224, "ALC_SHA2_224" },   { ALC_SHA2_256, "ALC_SHA2_256" },
    { ALC_SHA2_384, "ALC_SHA2_384" },   { ALC_SHA2_512, "ALC_SHA2_512" },
    { ALC_SHA3_224, "ALC_SHA3_224" },   { ALC_SHA3_256, "ALC_SHA3_256" },
    { ALC_SHA3_384, "ALC_SHA3_384" },   { ALC_SHA3_512, "ALC_SHA3_512" },
    { ALC_SHAKE_128, "ALC_SHAKE_128" }, { ALC_SHAKE_256, "ALC_SHAKE_256" }
};

/* FIXME: add for all the AES non-AEAD modes */
alc_cipher_mode_t AES_Modes[2] = { ALC_AES_MODE_CFB, ALC_AES_MODE_CBC };
std::map<alc_cipher_mode_t, std::string> aes_mode_string_map = {
    { ALC_AES_MODE_CFB, "AES_CFB" },
    { ALC_AES_MODE_CBC, "AES_CBC" },
};

const int ERR_SIZE = 256;
Uint8     err_buf[ERR_SIZE];
void
Check_Error(alc_error_t err)
{
    if (alcp_is_error(err))
        alcp_error_str(err, err_buf, ERR_SIZE);
}