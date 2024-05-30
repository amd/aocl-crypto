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
#include "alcp/rsa.h"
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

std::map<alc_digest_mode_t, alc_digest_len_t> sha_mode_len_map = {
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

std::map<alc_digest_mode_t, std::string> sha_mode_string_map = {
    { ALC_SHA2_224, "ALC_SHA2_224" },   { ALC_SHA2_256, "ALC_SHA2_256" },
    { ALC_SHA2_384, "ALC_SHA2_384" },   { ALC_SHA2_512, "ALC_SHA2_512" },
    { ALC_SHA3_224, "ALC_SHA3_224" },   { ALC_SHA3_256, "ALC_SHA3_256" },
    { ALC_SHA3_384, "ALC_SHA3_384" },   { ALC_SHA3_512, "ALC_SHA3_512" },
    { ALC_SHAKE_128, "ALC_SHAKE_128" }, { ALC_SHAKE_256, "ALC_SHAKE_256" }
};

alc_cipher_mode_t AES_Modes[5] = {
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
};
std::map<alc_cipher_mode_t, std::string> aes_mode_string_map = {
    { ALC_AES_MODE_CFB, "AES_CFB" },
    { ALC_AES_MODE_CBC, "AES_CBC" },
    { ALC_AES_MODE_OFB, "AES_OFB" },
    { ALC_AES_MODE_CTR, "AES_CTR" },
};

alc_cipher_mode_t AES_AEAD_Modes[2] = { ALC_AES_MODE_GCM };
std::map<alc_cipher_mode_t, std::string> aes_aead_mode_string_map = {
    { ALC_AES_MODE_GCM, "AES_GCM" },
};

alc_digest_info_t dinfo = {
    .dt_type = ALC_DIGEST_TYPE_SHA2,
    .dt_len  = ALC_DIGEST_LEN_256,
    .dt_mode = ALC_SHA2_256,
};
alc_digest_info_t mgf_info = {
    .dt_type = ALC_DIGEST_TYPE_SHA2,
    .dt_len  = ALC_DIGEST_LEN_256,
    .dt_mode = ALC_SHA2_256,
};

const int ERR_SIZE = 256;
Uint8     err_buf[ERR_SIZE];
void
Check_Error(alc_error_t err)
{
    if (alcp_is_error(err))
        alcp_error_str(err, err_buf, ERR_SIZE);
}