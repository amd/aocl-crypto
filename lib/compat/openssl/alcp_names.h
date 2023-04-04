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

// CBC
#define ALCP_PROV_NAMES_AES_256_CBC "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42"
#define ALCP_PROV_NAMES_AES_192_CBC "AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22"
#define ALCP_PROV_NAMES_AES_128_CBC "AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2"

// ECB
#define ALCP_PROV_NAMES_AES_256_ECB "AES-256-ECB:2.16.840.1.101.3.4.1.41"
#define ALCP_PROV_NAMES_AES_192_ECB "AES-192-ECB:2.16.840.1.101.3.4.1.21"
#define ALCP_PROV_NAMES_AES_128_ECB "AES-128-ECB:2.16.840.1.101.3.4.1.1"

// OFB
#define ALCP_PROV_NAMES_AES_256_OFB "AES-256-OFB:2.16.840.1.101.3.4.1.43"
#define ALCP_PROV_NAMES_AES_192_OFB "AES-192-OFB:2.16.840.1.101.3.4.1.23"
#define ALCP_PROV_NAMES_AES_128_OFB "AES-128-OFB:2.16.840.1.101.3.4.1.3"

// CFB
#define ALCP_PROV_NAMES_AES_256_CFB  "AES-256-CFB:2.16.840.1.101.3.4.1.44"
#define ALCP_PROV_NAMES_AES_192_CFB  "AES-192-CFB:2.16.840.1.101.3.4.1.24"
#define ALCP_PROV_NAMES_AES_128_CFB  "AES-128-CFB:2.16.840.1.101.3.4.1.4"
#define ALCP_PROV_NAMES_AES_256_CFB1 "AES-256-CFB1"
#define ALCP_PROV_NAMES_AES_192_CFB1 "AES-192-CFB1"
#define ALCP_PROV_NAMES_AES_128_CFB1 "AES-128-CFB1"
#define ALCP_PROV_NAMES_AES_256_CFB8 "AES-256-CFB8"
#define ALCP_PROV_NAMES_AES_192_CFB8 "AES-192-CFB8"
#define ALCP_PROV_NAMES_AES_128_CFB8 "AES-128-CFB8"

// CTR
#define ALCP_PROV_NAMES_AES_256_CTR "AES-256-CTR"
#define ALCP_PROV_NAMES_AES_192_CTR "AES-192-CTR"
#define ALCP_PROV_NAMES_AES_128_CTR "AES-128-CTR"

// FIXME: Support needs to be added
// XTS
#define ALCP_PROV_NAMES_AES_256_XTS "AES-256-XTS:1.3.111.2.1619.0.1.2"
#define ALCP_PROV_NAMES_AES_128_XTS "AES-128-XTS:1.3.111.2.1619.0.1.1"

// GCM
#define ALCP_PROV_NAMES_AES_256_GCM                                            \
    "AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46"
#define ALCP_PROV_NAMES_AES_192_GCM                                            \
    "AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26"
#define ALCP_PROV_NAMES_AES_128_GCM                                            \
    "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6"

// CCM
#define ALCP_PROV_NAMES_AES_256_CCM                                            \
    "AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47"
#define ALCP_PROV_NAMES_AES_192_CCM                                            \
    "AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27"
#define ALCP_PROV_NAMES_AES_128_CCM                                            \
    "AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7"

// DIGEST SHA2
#define ALCP_PROV_NAMES_SHA2_224                                               \
    "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define ALCP_PROV_NAMES_SHA2_256                                               \
    "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define ALCP_PROV_NAMES_SHA2_384                                               \
    "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define ALCP_PROV_NAMES_SHA2_512                                               \
    "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"

// Truncated Versions of Digest
#define ALCP_PROV_NAMES_SHA2_512_224                                           \
    "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5"
#define ALCP_PROV_NAMES_SHA2_512_256                                           \
    "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6"

// FIXME: Support needs to be added
// DIGEST SHA3
#define ALCP_PROV_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
#define ALCP_PROV_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
#define ALCP_PROV_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
#define ALCP_PROV_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"

// RNG
#define ALCP_PROV_NAMES_CTR_DRBG  "CTR-DRBG"
#define ALCP_PROV_NAMES_HASH_DRBG "HASH-DRBG"
#define ALCP_PROV_NAMES_HMAC_DRBG "HMAC-DRBG"
#define ALCP_PROV_NAMES_TEST_RAND "TEST-RAND"
#define ALCP_PROV_NAMES_SEED_SRC  "SEED-SRC"
