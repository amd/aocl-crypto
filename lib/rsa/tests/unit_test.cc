/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include <gtest/gtest.h>
#include <string.h>

#include "alcp/base.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha512.hh"
#include "alcp/error.h"
#include "alcp/rsa.hh"
#include "alcp/types.hh"

namespace {

using namespace std;
using namespace alcp;
using namespace rsa;

static const Uint8 Modulus[] = {
    0xef, 0x4f, 0xa2, 0xcd, 0x00, 0xea, 0x99, 0xeb, 0x12, 0xa8, 0x3a, 0x1b,
    0xc5, 0x5d, 0x49, 0x04, 0x18, 0xcd, 0x96, 0x69, 0xc9, 0x28, 0x2c, 0x36,
    0x40, 0x9a, 0x15, 0x40, 0x05, 0x6b, 0x35, 0x6f, 0x89, 0x76, 0xf3, 0xb9,
    0xe3, 0xac, 0x4d, 0x2a, 0xe4, 0xba, 0xd9, 0x6e, 0xb8, 0xa4, 0x05, 0x0b,
    0xc5, 0x8e, 0xdf, 0x15, 0x33, 0xfc, 0x81, 0x2b, 0xb5, 0xf4, 0x3a, 0x0b,
    0x67, 0x2d, 0x7d, 0x7c, 0x41, 0x8c, 0xc0, 0x46, 0x93, 0x7d, 0xe9, 0x95,
    0x90, 0x1e, 0xdd, 0xc0, 0xf4, 0xfc, 0x23, 0x90, 0xbb, 0x14, 0x73, 0x5e,
    0xcc, 0x86, 0x45, 0x6a, 0x9c, 0x15, 0x46, 0x92, 0xf3, 0xac, 0x24, 0x8f,
    0x0c, 0x28, 0x25, 0x17, 0xb1, 0xb8, 0x3f, 0xa5, 0x9c, 0x61, 0xbd, 0x2c,
    0x10, 0x7a, 0x5c, 0x47, 0xe0, 0xa2, 0xf1, 0xf3, 0x24, 0xca, 0x37, 0xc2,
    0x06, 0x78, 0xa4, 0xad, 0x0e, 0xbd, 0x72, 0xeb
};

static const Uint8 P_Modulus[] = {
    0xfa, 0x5e, 0xa7, 0x98, 0x7d, 0x19, 0x66, 0xdf, 0x91, 0xd7, 0xe7,
    0xf6, 0xbe, 0xb7, 0xdf, 0x51, 0x99, 0x61, 0xb8, 0x08, 0xff, 0xcd,
    0xe1, 0xf4, 0x42, 0x0a, 0xc4, 0x01, 0xf8, 0xcb, 0x85, 0xd1, 0x64,
    0xe0, 0x86, 0x66, 0xe3, 0x0b, 0xcc, 0x3b, 0x2f, 0xca, 0xc0, 0x47,
    0x62, 0x8d, 0x4d, 0x0e, 0xf5, 0x81, 0x63, 0xa0, 0x70, 0x78, 0xb3,
    0x69, 0xfa, 0xdd, 0x55, 0xd8, 0x53, 0xf2, 0xb1, 0xd3
};

static const Uint8 Q_Modulus[] = {
    0xf4, 0xb1, 0x51, 0x68, 0x20, 0x7b, 0x71, 0xd9, 0x69, 0x67, 0xe1,
    0x5b, 0xdf, 0x98, 0x76, 0xae, 0x02, 0xc8, 0x76, 0xd9, 0xbd, 0x5a,
    0xf5, 0x8d, 0x95, 0xa1, 0x5e, 0x66, 0xff, 0x67, 0xed, 0x0f, 0xa1,
    0x8f, 0x78, 0xa0, 0x85, 0x6c, 0x6a, 0xae, 0x51, 0xcc, 0xd1, 0xed,
    0x62, 0xb7, 0x9f, 0x7c, 0x75, 0xd3, 0xf7, 0x7a, 0x1a, 0xb7, 0x28,
    0x06, 0x1a, 0x9d, 0x2a, 0x26, 0x05, 0x0b, 0xf3, 0x89
};

static const Uint8 DP_EXP[] = {
    0x57, 0x7a, 0x0e, 0xf0, 0x96, 0x74, 0xf3, 0x9e, 0x95, 0xa4, 0x6c,
    0x25, 0xa8, 0x09, 0x32, 0x7b, 0x9e, 0x2d, 0xa8, 0x51, 0x6c, 0x9f,
    0x10, 0x9d, 0x79, 0x1d, 0xad, 0xd2, 0x4a, 0x8d, 0x41, 0x9a, 0x21,
    0xb6, 0xd8, 0xfe, 0xc5, 0xc1, 0x6f, 0x80, 0x16, 0x78, 0xae, 0xa9,
    0xc2, 0x63, 0x40, 0x53, 0x43, 0xb0, 0x0b, 0x91, 0x18, 0xfa, 0xf3,
    0x24, 0xca, 0x43, 0xdf, 0x24, 0x90, 0x60, 0x31, 0x85
};

static const Uint8 DQ_EXP[] = {
    0x1d, 0x7e, 0xf2, 0x6d, 0x36, 0xdd, 0x2a, 0x90, 0x26, 0xa0, 0x9b,
    0x0d, 0xd4, 0x1a, 0x30, 0xd4, 0x31, 0x09, 0xb1, 0x29, 0xf6, 0x25,
    0x6c, 0xcc, 0x30, 0x69, 0x4f, 0x53, 0xe3, 0x1d, 0xc7, 0xf9, 0xc6,
    0x63, 0xe1, 0x0a, 0x98, 0x8a, 0xc5, 0x21, 0x56, 0x42, 0xf6, 0x5b,
    0x43, 0x37, 0x17, 0x46, 0x8d, 0x7d, 0x8b, 0xab, 0x70, 0x64, 0xfb,
    0xb2, 0x20, 0xab, 0x29, 0x55, 0x83, 0xee, 0x38, 0xe1
};

static const Uint8 Q_ModulusINV[] = {
    0xad, 0xad, 0xc8, 0xfd, 0xd8, 0xc9, 0x60, 0x63, 0xfd, 0xe8, 0xcd,
    0xff, 0xa1, 0x0a, 0x23, 0x2d, 0x0d, 0x1e, 0x3f, 0x53, 0xe4, 0x4d,
    0xea, 0x8c, 0x8f, 0x1f, 0xd9, 0x41, 0xef, 0x87, 0x21, 0x9b, 0x89,
    0xc7, 0x27, 0x1c, 0xb3, 0x7d, 0xa9, 0xe4, 0x66, 0x6d, 0x8e, 0x59,
    0x1c, 0x01, 0xc4, 0x14, 0x7d, 0x69, 0x77, 0xb2, 0xbe, 0xb6, 0xd2,
    0x8c, 0x43, 0xcc, 0xfd, 0x41, 0x43, 0x02, 0x45, 0xde
};

static const Uint8 Modulus_2048[] = {
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

static const Uint8 P_Modulus_2048[] = {
    0xb8, 0xc7, 0x80, 0xd1, 0xa9, 0xf2, 0x33, 0x7a, 0x1e, 0xbb, 0x57, 0xcc,
    0x0e, 0x4e, 0x97, 0xfb, 0x92, 0xde, 0xa1, 0x7c, 0xee, 0xf5, 0xaa, 0x63,
    0xd0, 0xa8, 0x24, 0xa6, 0x99, 0x89, 0xb5, 0x7d, 0xf0, 0x82, 0x1c, 0x7e,
    0xad, 0x35, 0xc6, 0x46, 0xb9, 0xa7, 0x8f, 0xa7, 0x37, 0x25, 0x12, 0x4e,
    0xdf, 0xfd, 0x7a, 0x74, 0x21, 0x42, 0x2a, 0x98, 0x4d, 0x4b, 0x86, 0xd8,
    0xca, 0xfb, 0x0e, 0x02, 0xf8, 0x17, 0x59, 0xa5, 0x38, 0x73, 0xba, 0xcb,
    0x57, 0xf5, 0x26, 0xa3, 0x57, 0x27, 0x3f, 0x6f, 0xce, 0xb7, 0x46, 0x32,
    0xc7, 0x00, 0x5b, 0xbb, 0xa9, 0x38, 0x61, 0xa0, 0xc3, 0x28, 0xb2, 0x34,
    0x3b, 0x57, 0xa7, 0x2a, 0xe6, 0xdb, 0x28, 0x7e, 0xbe, 0x0b, 0x78, 0x1a,
    0x8e, 0xec, 0x81, 0x89, 0x18, 0xda, 0x1c, 0xa1, 0xb2, 0x80, 0x26, 0x3c,
    0x83, 0x3c, 0xd4, 0xfc, 0xbc, 0xfb, 0xed, 0x59
};

static const Uint8 Q_Modulus_2048[] = {
    0xf2, 0x43, 0x24, 0x20, 0xce, 0xbc, 0xb0, 0x3a, 0x9a, 0xf4, 0x08, 0xad,
    0xb2, 0xd2, 0x34, 0x63, 0x37, 0x8a, 0xcb, 0xb9, 0xee, 0xa3, 0x7a, 0x30,
    0x19, 0x88, 0xf3, 0xe1, 0x6b, 0xd1, 0x81, 0xbf, 0xb6, 0xb9, 0x90, 0x88,
    0x9b, 0xcd, 0x82, 0x45, 0xa0, 0x7d, 0x8e, 0x7e, 0xe1, 0x3a, 0xc3, 0x62,
    0x30, 0x90, 0x0d, 0xf2, 0x0b, 0x3c, 0x37, 0x59, 0x28, 0xcd, 0x67, 0x08,
    0xdf, 0x78, 0x13, 0x4b, 0x1d, 0xaa, 0xee, 0x30, 0x00, 0x49, 0x00, 0xe8,
    0x6c, 0x20, 0x6f, 0x96, 0xef, 0x9c, 0x7e, 0x8d, 0x32, 0x11, 0x12, 0x07,
    0xfa, 0x33, 0xf8, 0x1d, 0x1a, 0xb3, 0xe0, 0x0b, 0xc0, 0x71, 0x3c, 0xb5,
    0x72, 0x3c, 0x47, 0x16, 0x04, 0x8b, 0xb4, 0x8c, 0x41, 0xf0, 0x44, 0x24,
    0x29, 0xb7, 0x5a, 0xe3, 0x1b, 0x89, 0xe7, 0x53, 0xa8, 0x33, 0xe0, 0x5e,
    0x14, 0xeb, 0x5b, 0xfc, 0xec, 0x7e, 0x6a, 0xbf
};

static const Uint8 DP_EXP_2048[] = {
    0x54, 0x29, 0xf3, 0x00, 0x0c, 0xf3, 0x98, 0x04, 0xe8, 0xd8, 0x96, 0x5e,
    0x08, 0xaa, 0x3d, 0xc9, 0xc6, 0x15, 0x07, 0xe3, 0x5b, 0x08, 0xa4, 0xea,
    0xc0, 0x10, 0xc6, 0x58, 0xe8, 0x18, 0x74, 0x85, 0x7f, 0xb6, 0x13, 0xfa,
    0x93, 0x34, 0xaa, 0x32, 0x6e, 0xbf, 0xe6, 0xcb, 0xd8, 0x6f, 0x57, 0x4e,
    0x7b, 0xf1, 0xfe, 0x03, 0xc5, 0x5e, 0x58, 0xfe, 0x74, 0x3e, 0x91, 0x96,
    0x4f, 0xa6, 0x58, 0xb4, 0x7b, 0x82, 0x4f, 0x3f, 0xd5, 0x5d, 0xc9, 0x58,
    0x73, 0xa0, 0xe3, 0x4f, 0x85, 0x14, 0x08, 0x6e, 0x09, 0xef, 0x2a, 0xd7,
    0x58, 0x13, 0x4e, 0xb5, 0x44, 0x97, 0xbc, 0xc8, 0x37, 0xfc, 0x62, 0x67,
    0x2e, 0x1c, 0x77, 0xb5, 0x2f, 0xdf, 0xe5, 0x2b, 0x0d, 0xaf, 0x35, 0xae,
    0x8b, 0x29, 0x28, 0xbb, 0x64, 0x89, 0x7c, 0x7f, 0x1e, 0x4a, 0x06, 0xa0,
    0x8b, 0x7a, 0x7a, 0xdc, 0xff, 0xcb, 0x94, 0x49
};

static const Uint8 DQ_EXP_2048[] = {
    0x56, 0xce, 0x7e, 0x14, 0x8f, 0x5f, 0x87, 0x1a, 0x08, 0xc9, 0xe6, 0x8e,
    0x2e, 0xe4, 0x29, 0x47, 0x5f, 0xf0, 0x88, 0xdd, 0x5f, 0xc8, 0x0e, 0x11,
    0x4c, 0x25, 0x09, 0x96, 0x3d, 0x66, 0xfd, 0xc1, 0xef, 0x3c, 0x80, 0xb0,
    0xa2, 0x7b, 0x39, 0xf1, 0xae, 0xf7, 0x2e, 0x67, 0x02, 0x57, 0x67, 0x09,
    0x38, 0xf3, 0x75, 0x3b, 0xc4, 0x90, 0xd8, 0x18, 0x47, 0x89, 0x8a, 0x20,
    0xe0, 0xca, 0x0a, 0xc7, 0xc0, 0xa2, 0xad, 0xe4, 0x5f, 0x45, 0xc9, 0x60,
    0x7e, 0xd6, 0x04, 0x86, 0x25, 0xe7, 0x82, 0x65, 0x1f, 0x8a, 0x84, 0x56,
    0x7d, 0x6d, 0xbf, 0xba, 0xd6, 0x05, 0x9c, 0x03, 0x39, 0xfa, 0x99, 0x51,
    0x3e, 0xd4, 0xa0, 0x78, 0x20, 0x3a, 0xda, 0xff, 0xe2, 0xe4, 0xaf, 0xd5,
    0xf1, 0x68, 0xb4, 0xd5, 0x69, 0xd9, 0xb9, 0x1c, 0xfd, 0xc9, 0x50, 0xdd,
    0x05, 0x4b, 0xec, 0x53, 0x2d, 0x7e, 0x82, 0xcb
};

static const Uint8 Q_ModulusINV_2048[] = {
    0x29, 0x46, 0xdd, 0xbd, 0x16, 0x47, 0x73, 0xb8, 0x80, 0x88, 0x05, 0xe1,
    0x2b, 0x30, 0xb1, 0x58, 0x25, 0x59, 0xe6, 0x18, 0x54, 0xd6, 0x9e, 0xb8,
    0xc5, 0xb6, 0xe4, 0x07, 0xa1, 0xdd, 0x34, 0x82, 0x61, 0x46, 0xb0, 0x8b,
    0x1d, 0x96, 0xd5, 0x1d, 0x6f, 0x0b, 0x5f, 0xfa, 0xa0, 0xaa, 0x1c, 0xed,
    0x40, 0x9a, 0x5a, 0xf5, 0x08, 0x35, 0xa3, 0x61, 0x22, 0x11, 0x34, 0xd3,
    0xcf, 0x9f, 0xea, 0x7b, 0xb5, 0x41, 0x65, 0x16, 0xfb, 0x58, 0x01, 0x0d,
    0x65, 0x1d, 0x39, 0x16, 0x4e, 0x76, 0xbe, 0x12, 0x32, 0x43, 0x72, 0x13,
    0xd0, 0xe8, 0xdc, 0x9d, 0x5a, 0xdb, 0xaa, 0xe4, 0x77, 0x52, 0x89, 0xcf,
    0xf9, 0xb0, 0x78, 0x59, 0xa9, 0x8c, 0x9e, 0x99, 0x96, 0x0c, 0xfd, 0x9d,
    0x12, 0x56, 0xd0, 0x19, 0x81, 0x10, 0x18, 0xf9, 0x4e, 0x54, 0x92, 0x34,
    0x49, 0x41, 0x2e, 0xd9, 0xc0, 0xe6, 0xd2, 0xc8
};

static const Uint64 PublicKeyExponent = 0x10001;

static inline digest::IDigest*
fetch_digest(alc_digest_mode_t mode)
{
    using namespace alcp::digest;
    digest::IDigest* digest = nullptr;
    switch (mode) {
        case ALC_SHA2_256: {
            digest = new Sha256;
            break;
        }
        case ALC_SHA2_224: {
            digest = new Sha224;
            break;
        }
        case ALC_SHA2_384: {
            digest = new Sha384;
            break;
        }
        case ALC_SHA2_512: {
            digest = new Sha512;
            break;
        }
        case ALC_SHA3_224: {
            digest = new digest::Sha3_224;
            break;
        }
        case ALC_SHA3_256: {
            digest = new digest::Sha3_256;
            break;
        }
        case ALC_SHA3_384: {
            digest = new digest::Sha3_384;
            break;
        }
        case ALC_SHA3_512: {
            digest = new digest::Sha3_512;
            break;
        }
        default: {
            digest = nullptr;
            break;
        }
    }
    return digest;
}

TEST(RsaTest, PublicEncryptPrivateDecryptTest)
{
    Rsa rsa_obj;

    Uint64 key_size = KEY_SIZE_1024 / 8;

    auto p_text = std::make_unique<Uint8[]>(key_size);
    auto p_mod  = std::make_unique<Uint8[]>(key_size);
    auto p_enc  = std::make_unique<Uint8[]>(key_size);
    auto p_dec  = std::make_unique<Uint8[]>(key_size);

    std::fill(p_text.get(), p_text.get() + key_size, 0x31);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.encryptPublic(p_text.get(), key_size, p_enc.get());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.setPrivateKey(DP_EXP,
                                DQ_EXP,
                                P_Modulus,
                                Q_Modulus,
                                Q_ModulusINV,
                                Modulus,
                                sizeof(P_Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.decryptPrivate(p_enc.get(), key_size, p_dec.get());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(memcmp(p_dec.get(), p_text.get(), key_size), 0);

    Rsa rsa_obj_2048;

    key_size = KEY_SIZE_2048 / 8;

    p_text = std::make_unique<Uint8[]>(key_size);
    p_mod  = std::make_unique<Uint8[]>(key_size);
    p_enc  = std::make_unique<Uint8[]>(key_size);
    p_dec  = std::make_unique<Uint8[]>(key_size);

    std::fill(p_text.get(), p_text.get() + key_size, 0x31);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.encryptPublic(p_text.get(), key_size, p_enc.get());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.decryptPrivate(p_enc.get(), key_size, p_dec.get());
    ASSERT_EQ(err, ALC_ERROR_NONE);

    EXPECT_EQ(memcmp(p_dec.get(), p_text.get(), key_size), 0);
}

TEST(RsaTest, PubKeyEncryptValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 size = KEY_SIZE_1024 / 8;

    auto p_mod  = std::make_unique<Uint8[]>(size);
    auto p_text = std::make_unique<Uint8[]>(size);
    auto p_enc  = std::make_unique<Uint8[]>(size);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.encryptPublic(p_text.get(), size, p_enc.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    size = KEY_SIZE_2048 / 8;

    p_mod  = std::make_unique<Uint8[]>(size);
    p_text = std::make_unique<Uint8[]>(size);
    p_enc  = std::make_unique<Uint8[]>(size);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.encryptPublic(p_text.get(), size, p_enc.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyEncryptInValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 size   = KEY_SIZE_1024 / 8;
    auto   p_mod  = std::make_unique<Uint8[]>(size);
    auto   p_text = std::make_unique<Uint8[]>(size);
    auto   p_enc  = std::make_unique<Uint8[]>(size);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.encryptPublic(p_text.get(), size + 1, p_enc.get());
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    size   = KEY_SIZE_2048 / 8;
    p_mod  = std::make_unique<Uint8[]>(size);
    p_text = std::make_unique<Uint8[]>(size);
    p_enc  = std::make_unique<Uint8[]>(size);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.encryptPublic(p_text.get(), size + 1, p_enc.get());
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyEncryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 key_size   = KEY_SIZE_1024 / 8;
    auto   p_buff     = std::make_unique<Uint8[]>(key_size);
    auto   p_buff_enc = std::make_unique<Uint8[]>(key_size);

    auto p_modulus = std::make_unique<Uint8[]>(key_size);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.encryptPublic(p_buff.get(), key_size, p_buff_enc.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    key_size   = KEY_SIZE_2048 / 8;
    p_buff     = std::make_unique<Uint8[]>(key_size);
    p_buff_enc = std::make_unique<Uint8[]>(key_size);

    p_modulus = std::make_unique<Uint8[]>(key_size);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.encryptPublic(p_buff.get(), key_size, p_buff_enc.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyEncryptInValidBuffTest)
{
    Rsa rsa_obj;

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.encryptPublic(nullptr, rsa_obj.getKeySize(), nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err =
        rsa_obj_2048.encryptPublic(nullptr, rsa_obj_2048.getKeySize(), nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PrivKeyDecryptValidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = KEY_SIZE_1024 / 8;

    auto p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    alc_error_t err = rsa_obj.setPrivateKey(DP_EXP,
                                            DQ_EXP,
                                            P_Modulus,
                                            Q_Modulus,
                                            Q_ModulusINV,
                                            Modulus,
                                            sizeof(P_Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.decryptPrivate(p_buff_enc.get(), enc_size, p_buff_dec.get());

    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    enc_size = KEY_SIZE_2048 / 8;

    p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.decryptPrivate(
        p_buff_enc.get(), enc_size, p_buff_dec.get());

    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PrivKeyDecryptInvalidSizeTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = KEY_SIZE_1024 / 8 + 1;

    alc_error_t err = rsa_obj.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    enc_size = KEY_SIZE_2048 / 8 + 1;

    err = rsa_obj_2048.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PrivKeyDecryptValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size   = KEY_SIZE_1024 / 8;
    auto   p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    auto   p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    alc_error_t err = rsa_obj.setPrivateKey(DP_EXP,
                                            DQ_EXP,
                                            P_Modulus,
                                            Q_Modulus,
                                            Q_ModulusINV,
                                            Modulus,
                                            sizeof(P_Modulus));

    err = rsa_obj.decryptPrivate(p_buff_enc.get(), enc_size, p_buff_dec.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    enc_size   = KEY_SIZE_2048 / 8;
    p_buff_enc = std::make_unique<Uint8[]>(enc_size);
    p_buff_dec = std::make_unique<Uint8[]>(enc_size);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));

    err = rsa_obj_2048.decryptPrivate(
        p_buff_enc.get(), enc_size, p_buff_dec.get());
    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PrivKeyDecryptInValidBuffTest)
{
    Rsa    rsa_obj;
    Uint64 enc_size = KEY_SIZE_1024 / 8;

    alc_error_t err = rsa_obj.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    enc_size = KEY_SIZE_2048 / 8;
    err      = rsa_obj_2048.decryptPrivate(nullptr, enc_size, nullptr);
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyWithValidModulusTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size = KEY_SIZE_1024 / 8;
    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    auto p_buff     = std::make_unique<Uint8[]>(pub_key.size);
    pub_key.modulus = p_buff.get();
    err             = rsa_obj.getPublickey(pub_key);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    pub_key.size = KEY_SIZE_2048 / 8;
    err          = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    p_buff          = std::make_unique<Uint8[]>(pub_key.size);
    pub_key.modulus = p_buff.get();
    err             = rsa_obj_2048.getPublickey(pub_key);
    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyWithInValidModulusTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size = KEY_SIZE_1024 / 8;
    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    pub_key.modulus = nullptr;
    err             = rsa_obj.getPublickey(pub_key);
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    pub_key.size = KEY_SIZE_2048 / 8;
    err          = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    pub_key.modulus = nullptr;
    err             = rsa_obj_2048.getPublickey(pub_key);
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyWithInvalidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;
    pub_key.size = KEY_SIZE_1024 / 8 + 1;
    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    err = rsa_obj.getPublickey(pub_key);
    EXPECT_NE(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    pub_key.size = KEY_SIZE_2048 / 8 + 1;
    err          = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.getPublickey(pub_key);
    EXPECT_NE(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PubKeyWithValidSizeTest)
{
    Rsa          rsa_obj;
    RsaPublicKey pub_key;

    pub_key.size = KEY_SIZE_1024 / 8;

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    auto p_buff = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_buff.get();
    err             = rsa_obj.getPublickey(pub_key);
    EXPECT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;

    pub_key.size = KEY_SIZE_2048 / 8;

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    p_buff = std::make_unique<Uint8[]>(pub_key.size);

    pub_key.modulus = p_buff.get();
    err             = rsa_obj_2048.getPublickey(pub_key);
    EXPECT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, EncryptOaepPadding)
{
    std::unique_ptr<digest::IDigest> digest_ptr;

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);
    digest_ptr.reset(digest);

    Rsa rsa_obj;
    rsa_obj.setDigest(digest);
    rsa_obj.setMgf(digest);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));

    // text size should be in the range 2 * hash_len + 2
    // to sizeof(Modulus) - 2* hash_len - 2
    const Uint64 text_size = 62; // size - 2 * hash_len - 2;
    const Uint8  Label[]   = { 'h', 'e', 'l', 'l', 'o' };
    Uint8        p_seed[256 / 8];
    Uint8        enc_text[1024 / 8];
    Uint8        text[text_size];

    err = rsa_obj.encryptPublicOaep(
        text, text_size, Label, sizeof(Label), p_seed, enc_text);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));
    rsa_obj_2048.setMgf(static_cast<digest::IDigest*>(digest));

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));

    const Uint64 text_size_2048 = 190; // size - 2 * hash_len - 2;
    Uint8        enc_text_2048[2048 / 8];
    Uint8        text_2048[text_size_2048];
    err = rsa_obj_2048.encryptPublicOaep(
        text_2048, text_size_2048, Label, sizeof(Label), p_seed, enc_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, DecryptOaepPadding)
{
    std::unique_ptr<digest::IDigest> digest_ptr;

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);
    digest_ptr.reset(reinterpret_cast<digest::IDigest*>(digest));

    Rsa rsa_obj;
    rsa_obj.setDigest(digest);
    rsa_obj.setMgf(digest);

    alc_error_t err =
        rsa_obj.setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));

    // text size should be in the range 2 * hash_len + 2
    // to sizeof(Modulus) - 2* hash_len - 2
    Uint64      text_size = 62;
    const Uint8 Label[]   = { 'h', 'e', 'l', 'l', 'o' };
    Uint8       p_seed[256 / 8];
    Uint8       enc_text[1024 / 8];
    Uint8       text[62]; // size - 2 * hash_len - 2;

    err = rsa_obj.encryptPublicOaep(
        text, text_size, Label, sizeof(Label), p_seed, enc_text);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj.setPrivateKey(DP_EXP,
                                DQ_EXP,
                                P_Modulus,
                                Q_Modulus,
                                Q_ModulusINV,
                                Modulus,
                                sizeof(P_Modulus));

    Uint8 text_full[1024 / 8];

    err = rsa_obj.decryptPrivateOaep(
        enc_text, sizeof(enc_text), Label, sizeof(Label), text_full, text_size);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    Rsa rsa_obj_2048;
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));

    rsa_obj_2048.setMgf(static_cast<digest::IDigest*>(digest));

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));

    Uint64 text_size_2048 = 190;
    Uint8  enc_text_2048[2048 / 8];
    Uint8  text_2048[190]; // size - 2 * hash_len - 2;
    Uint8  text_full_2048[2048 / 8];

    err = rsa_obj_2048.encryptPublicOaep(
        text_2048, text_size_2048, Label, sizeof(Label), p_seed, enc_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));

    err = rsa_obj_2048.decryptPrivateOaep(enc_text_2048,
                                          sizeof(enc_text_2048),
                                          Label,
                                          sizeof(Label),
                                          text_full_2048,
                                          text_size);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PssSanity)
{
    Rsa    rsa_obj_2048;
    Uint8  text[2048 / 8];
    Uint64 text_size = 2048 / 8;
    Uint8  salt[20];
    Uint64 salt_size = 20;
    Uint8  signed_buff[2048];

    // null text should fail
    alc_error_t err = rsa_obj_2048.signPrivatePss(
        true, nullptr, text_size, salt, salt_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPss(nullptr, 0, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    // null signed buff should fail
    err = rsa_obj_2048.signPrivatePss(true, text, text_size, salt, 20, nullptr);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPss(text, text_size, nullptr);
    ASSERT_NE(err, ALC_ERROR_NONE);

    // not setting the hash should fail
    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, salt, 20, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPss(text, text_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);

    std::unique_ptr<digest::IDigest> digest_ptr;
    digest_ptr.reset(reinterpret_cast<digest::IDigest*>(digest));
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));

    // not setting the public key / private key should fail
    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, salt, 20, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPss(text, text_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));

    err = rsa_obj_2048.signPrivatePss(
        false, text, 2048 / 8, salt, 20, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // not setting the public key will fail for fault tolerance
    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, salt, 20, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, salt, 20, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPss(text, text_size, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // null salt should fail if the size says otherwise
    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, nullptr, 20, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    // null salt should not fail if the size is 0
    err = rsa_obj_2048.signPrivatePss(
        true, text, 2048 / 8, nullptr, 0, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, PssSignatureVerification)
{
    std::unique_ptr<digest::IDigest> digest_ptr;

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);
    digest_ptr.reset(reinterpret_cast<digest::IDigest*>(digest));

    Rsa rsa_obj_2048;
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));

    alc_error_t err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    Uint64 text_size_2048 = 190;
    Uint8  signed_text_2048[2048 / 8];
    Uint8  text_2048[190];
    Uint8  salt[20];
    Uint64 salt_size = 20;

    err = rsa_obj_2048.signPrivatePss(
        true, text_2048, text_size_2048, salt, salt_size, signed_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.verifyPublicPss(
        text_2048, text_size_2048, signed_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, Pkcsv15Sanity)
{
    Rsa    rsa_obj_2048;
    Uint8  text[2048 / 8];
    Uint64 text_size = 2048 / 8;
    Uint8  signed_buff[2048];

    // null text should fail
    alc_error_t err =
        rsa_obj_2048.signPrivatePkcsv15(true, nullptr, text_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPkcsv15(nullptr, 0, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    // null signed buff should fail
    err = rsa_obj_2048.signPrivatePkcsv15(true, text, text_size, nullptr);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPkcsv15(text, text_size, nullptr);
    ASSERT_NE(err, ALC_ERROR_NONE);

    // not setting the hash should fail
    err = rsa_obj_2048.signPrivatePkcsv15(true, text, 2048 / 8, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPkcsv15(text, text_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);

    std::unique_ptr<digest::IDigest> digest_ptr;
    digest_ptr.reset(reinterpret_cast<digest::IDigest*>(digest));
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));

    // not setting the public key / private key should fail
    err = rsa_obj_2048.signPrivatePkcsv15(true, text, 2048 / 8, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPkcsv15(text, text_size, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));

    err = rsa_obj_2048.signPrivatePkcsv15(false, text, 2048 / 8, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    // not setting the public key will fail for fault tolerance
    err = rsa_obj_2048.signPrivatePkcsv15(true, text, 2048 / 8, signed_buff);
    ASSERT_NE(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.signPrivatePkcsv15(true, text, 2048 / 8, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);
    err = rsa_obj_2048.verifyPublicPkcsv15(text, text_size, signed_buff);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

TEST(RsaTest, Pkcsv15SignatureVerification)
{
    std::unique_ptr<digest::IDigest> digest_ptr;

    digest::IDigest* digest = fetch_digest(ALC_SHA2_256);
    digest_ptr.reset(reinterpret_cast<digest::IDigest*>(digest));

    Rsa rsa_obj_2048;
    rsa_obj_2048.setDigest(static_cast<digest::IDigest*>(digest));

    alc_error_t err = rsa_obj_2048.setPublicKey(
        PublicKeyExponent, Modulus_2048, sizeof(Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.setPrivateKey(DP_EXP_2048,
                                     DQ_EXP_2048,
                                     P_Modulus_2048,
                                     Q_Modulus_2048,
                                     Q_ModulusINV_2048,
                                     Modulus_2048,
                                     sizeof(P_Modulus_2048));
    ASSERT_EQ(err, ALC_ERROR_NONE);

    Uint64 text_size_2048 = 190;
    Uint8  signed_text_2048[2048 / 8];
    Uint8  text_2048[190];

    err = rsa_obj_2048.signPrivatePkcsv15(
        true, text_2048, text_size_2048, signed_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);

    err = rsa_obj_2048.verifyPublicPkcsv15(
        text_2048, text_size_2048, signed_text_2048);
    ASSERT_EQ(err, ALC_ERROR_NONE);
}

} // namespace
