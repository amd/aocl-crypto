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

// alc_cipher_mode_t AES_Modes[5] = {
//     ALC_AES_MODE_CFB,
//     ALC_AES_MODE_CBC,
//     ALC_AES_MODE_OFB,
//     ALC_AES_MODE_CTR,
// };
// std::map<alc_cipher_mode_t, std::string> aes_mode_string_map = {
//     { ALC_AES_MODE_CFB, "AES_CFB" },
//     { ALC_AES_MODE_CBC, "AES_CBC" },
//     { ALC_AES_MODE_OFB, "AES_OFB" },
//     { ALC_AES_MODE_CTR, "AES_CTR" },
// };

// alc_cipher_mode_t AES_AEAD_Modes[2] = { ALC_AES_MODE_GCM };
// std::map<alc_cipher_mode_t, std::string> aes_aead_mode_string_map = {
//     { ALC_AES_MODE_GCM, "AES_GCM" },
// };

#define ALCP_TEST_RSA_PADDING_PKCS 1
#define ALCP_TEST_RSA_PADDING_PSS  2

/* Fuzz functions */
int
ALCP_Fuzz_Digest(alc_digest_mode_t mode, const Uint8* buf, size_t len);