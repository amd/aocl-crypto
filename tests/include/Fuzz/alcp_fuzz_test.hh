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
#include <random>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static std::random_device rd;
static std::mt19937       rng{ rd() };

#define ALCP_TEST_RSA_PADDING_PKCS 1
#define ALCP_TEST_RSA_PADDING_PSS  2

#define ALCP_TEST_FUZZ_RSA_ENCRYPT 1
#define ALCP_TEST_FUZZ_RSA_DECRYPT 2
#define ALCP_TEST_FUZZ_RSA_SIGN    3
#define ALCP_TEST_FUZZ_RSA_VERIFY  4

static Uint8 fuzz_modulus[] = {
    0xae, 0xdd, 0x0e, 0x10, 0xa5, 0xcc, 0xc0, 0x86, 0xfd, 0xdb, 0xef, 0x26,
    0xaa, 0x5b, 0x60, 0xa2, 0x67, 0xc7, 0x0e, 0x50, 0x5c, 0x91, 0x32, 0xc1,
    0x95, 0x27, 0x71, 0xee, 0x30, 0xc6, 0x15, 0x93, 0x77, 0xea, 0x34, 0x8c,
    0x35, 0x67, 0x2e, 0x48, 0xb5, 0x96, 0x77, 0x97, 0x0a, 0x49, 0x74, 0x5d,
    0x44, 0x69, 0x3b, 0xee, 0xb9, 0xa4, 0x1d, 0x75, 0x50, 0xfe, 0x89, 0xa9,
    0xd4, 0xfc, 0x66, 0xbb, 0x4e, 0xca, 0x57, 0xf9, 0xaf, 0x06, 0x35, 0x42,
    0x0c, 0x5b, 0x91, 0x13, 0xf9, 0x1f, 0x7b, 0x16, 0x88, 0xc8, 0x0e, 0x3c,
    0xc2, 0x20, 0x73, 0x39, 0x77, 0xf9, 0x01, 0x58, 0xa2, 0x15, 0x0a, 0x17,
    0x7d, 0x83, 0xb3, 0x5c, 0xcc, 0x23, 0x2d, 0xe4, 0x99, 0xb8, 0x14, 0xf4,
    0x60, 0x61, 0x7a, 0x8e, 0x41, 0x5f, 0x1e, 0x15, 0xe3, 0xe6, 0x46, 0x73,
    0xda, 0xd8, 0xa7, 0xe4, 0xab, 0xda, 0x86, 0xdd, 0x34, 0xdf, 0x9c, 0x28,
    0xd2, 0xcd, 0x3d, 0xb2, 0x40, 0x40, 0x4d, 0xf9, 0x24, 0xf3, 0x4c, 0x65,
    0x1a, 0xb7, 0x41, 0x8e, 0xfe, 0x82, 0xc4, 0x55, 0x74, 0xe2, 0x40, 0xa3,
    0xa5, 0x3e, 0x04, 0x3f, 0x1e, 0x48, 0xf0, 0x55, 0x86, 0x2b, 0x75, 0xd0,
    0xaf, 0x05, 0xcf, 0xe0, 0xa6, 0x93, 0x24, 0x94, 0xad, 0x12, 0xd3, 0x1f,
    0xe1, 0x0f, 0x70, 0x86, 0xa5, 0x87, 0xb1, 0x79, 0x53, 0x5e, 0x07, 0x21,
    0x9d, 0x40, 0x63, 0x5d, 0x8c, 0xd0, 0x21, 0xfd, 0x7f, 0xe2, 0xec, 0xbf,
    0x9e, 0x2e, 0x5f, 0x8b, 0x8c, 0x22, 0x0b, 0x2e, 0xf1, 0xda, 0x6d, 0x35,
    0x7d, 0x76, 0x12, 0x8b, 0x7f, 0xf7, 0xc4, 0x7f, 0x45, 0x3b, 0x8c, 0x29,
    0x3f, 0x7e, 0x53, 0x79, 0xc1, 0x33, 0x8e, 0x77, 0xc2, 0xfa, 0xde, 0xc1,
    0xcf, 0xd1, 0x45, 0x8a, 0x6f, 0x7c, 0xf2, 0x3a, 0x57, 0x40, 0x18, 0x3a,
    0x2e, 0x0a, 0xef, 0x67
};

/* Fuzz functions */
int
ALCP_Fuzz_AEAD_Cipher_Decrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len,
                              bool              TestNeglifecycle);
int
ALCP_Fuzz_AEAD_Cipher_Encrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len,
                              bool              TestNeglifecycle);
int
ALCP_Fuzz_Cipher_Encrypt(alc_cipher_mode_t Mode,
                         const Uint8*      buf,
                         size_t            len,
                         bool              TestNeglifecycle);
int
ALCP_Fuzz_Cipher_Decrypt(alc_cipher_mode_t Mode,
                         const Uint8*      buf,
                         size_t            len,
                         bool              TestNeglifecycle);
int
ALCP_Fuzz_Digest(alc_digest_mode_t mode,
                 const Uint8*      buf,
                 size_t            len,
                 bool              TestNegLifeCycle);
int
ALCP_Fuzz_Mac(_alc_mac_type     mac_type,
              alc_digest_mode_t mode,
              const Uint8*      buf,
              size_t            len,
              bool              TestNegLifeCycle);
int
ALCP_Fuzz_Drbg(_alc_drbg_type DrbgType,
               const Uint8*   buf,
               size_t         len,
               bool           TestNeglifecycle);
int
ALCP_Fuzz_Rng(const Uint8* buf, size_t len, bool TestNeglifecycle);
int
ALCP_Fuzz_Rsa_SignVerify(int          PaddingMode,
                         const Uint8* buf,
                         size_t       len,
                         int          SignVerify,
                         bool         TestNegLifeCycle);
int
ALCP_Fuzz_Rsa_DecryptPvtKey(const Uint8* buf,
                            size_t       len,
                            bool         TestNegLifeCycle);
int
ALCP_Fuzz_Rsa_EncryptPubKey(const Uint8* buf,
                            size_t       len,
                            bool         TestNegLifeCycle);
int
ALCP_Fuzz_Rsa_OAEP(const Uint8* buf,
                   size_t       len,
                   int          EncDec,
                   bool         TestNegLifeCycle);

int
ALCP_Fuzz_Rsa_EncryptDecrypt_PKCS(const Uint8* buf, size_t len, int EncDec);

int
ALCP_Fuzz_Ec_x25519(const Uint8* buf, size_t len, bool TestNegLifeCycle);

int
ALCP_Fuzz_Rsa_DigestSign(const Uint8* buf, size_t len, int PaddingMode);