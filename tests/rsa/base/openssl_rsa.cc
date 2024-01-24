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

#include "rsa/openssl_rsa.hh"
#include <cstddef>
#include <cstring>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <ostream>

namespace alcp::testing {

OpenSSLRsaBase::OpenSSLRsaBase() {}

OpenSSLRsaBase::~OpenSSLRsaBase()
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    if (m_pkey_pub != nullptr) {
        EVP_PKEY_free(m_pkey_pub);
        m_pkey_pub = nullptr;
    }
    if (m_pkey_pvt != nullptr) {
        EVP_PKEY_free(m_pkey_pvt);
        m_pkey_pvt = nullptr;
    }
    if (m_params != nullptr) {
        OSSL_PARAM_free(m_params);
        m_params = nullptr;
    }
}

bool
OpenSSLRsaBase::init()
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    /* components for public key */
    /* for 1024 key size */
    const Uint8 Modulus_1024[] = {
        0xf1, 0x88, 0x9d, 0x27, 0x1c, 0x90, 0x54, 0x2b, 0x5e, 0x52, 0x63, 0x63,
        0x4d, 0x83, 0x23, 0x6d, 0x9b, 0x48, 0x6b, 0x6b, 0x9d, 0x87, 0x6d, 0xda,
        0x16, 0xb0, 0x19, 0xcd, 0xf1, 0xdd, 0x10, 0xb4, 0xc5, 0x35, 0xbc, 0xaa,
        0x00, 0x8c, 0x40, 0x41, 0xe1, 0xa0, 0x57, 0x91, 0x49, 0x0f, 0xd9, 0x3c,
        0x89, 0xb4, 0xbc, 0xb2, 0x47, 0xe7, 0x7d, 0x24, 0xb2, 0x2f, 0x9a, 0xb9,
        0x6a, 0xa5, 0x20, 0xe6, 0xd4, 0xde, 0xd3, 0x0e, 0x28, 0xdc, 0xaf, 0x3f,
        0x88, 0x11, 0x4f, 0xa5, 0x02, 0x46, 0x91, 0xe7, 0xf1, 0x93, 0xb2, 0x47,
        0x11, 0x5b, 0x7b, 0xbb, 0xda, 0xe9, 0x47, 0x7f, 0xeb, 0xa5, 0xd7, 0x17,
        0x96, 0x53, 0x09, 0xa6, 0x6a, 0xbe, 0x8e, 0xe4, 0x45, 0xdf, 0xe7, 0x12,
        0x80, 0x78, 0x86, 0x65, 0x47, 0xf9, 0x4a, 0xe5, 0x90, 0xd6, 0xdc, 0x0c,
        0x0d, 0x5a, 0x5a, 0xce, 0x12, 0xca, 0x1b, 0x09
    };

    /* for 2048 keysize */
    const Uint8 Modulus_2048[] = {
        0xae, 0x20, 0xe8, 0x1f, 0x78, 0x01, 0x6c, 0x9a, 0x3e, 0x4a, 0x88, 0xde,
        0x2f, 0x98, 0xfe, 0xe3, 0x24, 0x2e, 0x99, 0x78, 0x27, 0x8e, 0x1a, 0xed,
        0xe7, 0xe1, 0x42, 0x84, 0x1c, 0x4e, 0x7e, 0xf4, 0xdc, 0xc9, 0xcc, 0xf3,
        0xa7, 0x9a, 0xa5, 0x50, 0xda, 0x8b, 0xcd, 0x04, 0x1c, 0x43, 0xf6, 0xbe,
        0x5d, 0x1e, 0x6a, 0x52, 0x16, 0x80, 0xe2, 0x5f, 0x7b, 0x0e, 0x03, 0x6c,
        0x78, 0x53, 0x72, 0xa1, 0x81, 0xc8, 0xc6, 0xb0, 0x79, 0xb7, 0xe0, 0x50,
        0xc3, 0x6e, 0xd0, 0xf9, 0x4b, 0x94, 0x61, 0x86, 0x88, 0xc0, 0x9a, 0x99,
        0xea, 0xbd, 0x8f, 0x54, 0x29, 0xd0, 0x17, 0xd5, 0x8f, 0xaa, 0xa5, 0x9d,
        0xcc, 0x13, 0x7a, 0xfb, 0x5d, 0xc8, 0x96, 0xb7, 0x87, 0xd9, 0x75, 0xf8,
        0xab, 0x2e, 0x3b, 0x92, 0xe2, 0xc8, 0xde, 0x57, 0x0f, 0x94, 0xfe, 0x6a,
        0x85, 0x86, 0x83, 0xa2, 0x0a, 0x59, 0x0a, 0x5e, 0xe5, 0x37, 0xb3, 0x9e,
        0x42, 0x3d, 0x85, 0x00, 0xf6, 0x75, 0x9e, 0x45, 0x7e, 0x3c, 0xbe, 0x11,
        0x61, 0xf5, 0x99, 0x6c, 0x1c, 0xa6, 0x53, 0x3d, 0x02, 0xd7, 0x4e, 0x72,
        0xb5, 0x3e, 0xcf, 0x5a, 0x02, 0xc0, 0x65, 0x5b, 0xda, 0x83, 0xc9, 0x07,
        0x88, 0xd5, 0xd1, 0x62, 0xfe, 0x0a, 0xb1, 0xcf, 0x52, 0x27, 0x70, 0x04,
        0x66, 0xb8, 0x99, 0xd6, 0xdc, 0xe9, 0x27, 0xaf, 0xd9, 0x90, 0x8d, 0xef,
        0x7c, 0x96, 0x6a, 0x09, 0xe7, 0x25, 0x10, 0xb4, 0x3c, 0xcc, 0x6c, 0x5b,
        0xf0, 0x26, 0xdf, 0x49, 0xde, 0x26, 0x1e, 0x81, 0xc2, 0x55, 0x8e, 0xed,
        0xd6, 0x1f, 0x81, 0x34, 0xce, 0x33, 0x53, 0x14, 0xa3, 0x37, 0xc7, 0x7b,
        0x6d, 0xcb, 0x58, 0x27, 0x09, 0xdf, 0x06, 0xdc, 0xed, 0x44, 0x53, 0x76,
        0xb9, 0x3a, 0x2d, 0x0c, 0x9b, 0x3a, 0x9e, 0x3b, 0x28, 0xc5, 0xf9, 0xa1,
        0xe3, 0xf4, 0xb3, 0x01
    };

    const Uint8 PrivateKeyExponent_1024[] = {
        0x05, 0xbc, 0x0c, 0x9f, 0x25, 0x1a, 0x78, 0x25, 0x1f, 0x74, 0x2d, 0x4f,
        0xea, 0x43, 0x36, 0xd0, 0x1f, 0x63, 0xb4, 0xc9, 0x35, 0x50, 0x45, 0xd7,
        0x6b, 0xba, 0x7a, 0xa2, 0x5d, 0x1f, 0xb6, 0x89, 0xd4, 0x34, 0xd6, 0x69,
        0xe2, 0xe1, 0x71, 0x95, 0x1e, 0xda, 0x43, 0xb9, 0xfb, 0x56, 0x18, 0xfe,
        0x4a, 0xf6, 0xb3, 0x94, 0x38, 0x08, 0xd2, 0xfb, 0xd0, 0x0f, 0x39, 0x49,
        0x35, 0xb2, 0xfd, 0xf8, 0xf1, 0x3d, 0x71, 0x10, 0xac, 0x58, 0x2d, 0x0b,
        0xd7, 0x2c, 0xf2, 0x5c, 0x56, 0xd6, 0x04, 0xf2, 0xc2, 0x60, 0x24, 0x83,
        0xba, 0x3d, 0x7d, 0x19, 0xa4, 0xed, 0x2e, 0xa4, 0xca, 0x1c, 0x5f, 0x4f,
        0x14, 0xf2, 0x76, 0x90, 0x53, 0x03, 0x4f, 0x78, 0xc0, 0xb6, 0x8e, 0xbf,
        0x4e, 0xcf, 0x06, 0x66, 0x2b, 0xd0, 0x4b, 0x45, 0x6e, 0x84, 0xea, 0xb5,
        0x52, 0xc9, 0x93, 0x6b, 0xa3, 0xd6, 0xc1, 0x51
    };

    const Uint8 P_Modulus_1024[] = {
        0xfd, 0xf9, 0xc7, 0x69, 0x6c, 0x3b, 0x60, 0x8f, 0xec, 0x27, 0xc7,
        0x50, 0x42, 0x29, 0xf0, 0x81, 0x9b, 0xa9, 0xeb, 0x7b, 0xe7, 0xc1,
        0x58, 0x04, 0x52, 0xc0, 0x07, 0x84, 0x32, 0xd3, 0xf2, 0x72, 0x41,
        0x9c, 0x96, 0x5c, 0x84, 0x14, 0x9e, 0x63, 0xba, 0x0a, 0x98, 0xcd,
        0x56, 0xab, 0x47, 0x0b, 0xd5, 0xa7, 0x43, 0x30, 0x0c, 0xf5, 0x62,
        0xd1, 0x3b, 0xa2, 0x0d, 0x7e, 0xdf, 0x38, 0x9a, 0x4b
    };

    const Uint8 Q_Modulus_1024[] = {
        0xf3, 0x75, 0x72, 0x9d, 0xec, 0x88, 0x12, 0x23, 0x65, 0xd1, 0x96,
        0x98, 0xfe, 0xe6, 0xb3, 0xb2, 0xc9, 0x42, 0xcd, 0x65, 0x5c, 0xbb,
        0xcf, 0x9f, 0x81, 0xc5, 0xf2, 0xa9, 0x55, 0xea, 0x02, 0x59, 0x9b,
        0x88, 0x76, 0xc7, 0x56, 0x99, 0xbc, 0x80, 0x84, 0x0c, 0xac, 0xba,
        0xb4, 0xef, 0x45, 0x13, 0x52, 0xfb, 0xf8, 0x49, 0xf3, 0x5e, 0xf7,
        0xdf, 0xc1, 0x72, 0xd6, 0xa6, 0xd9, 0xac, 0x4b, 0x7b
    };

    const Uint8 DP_EXP_1024[] = {
        0x96, 0x96, 0x25, 0x20, 0x62, 0xe6, 0x09, 0xe9, 0x0b, 0xf2, 0xc2,
        0x00, 0xda, 0x5a, 0x17, 0x9a, 0x21, 0x7b, 0xec, 0x7d, 0xf8, 0xf9,
        0xf0, 0x80, 0x0f, 0xb8, 0x80, 0x3c, 0x68, 0x0e, 0xb7, 0x2f, 0xfb,
        0xab, 0x26, 0x94, 0x10, 0x54, 0x51, 0x5d, 0x7c, 0x0f, 0x90, 0x6e,
        0x1f, 0xb7, 0x4a, 0x56, 0xc0, 0x05, 0x7e, 0x96, 0xdc, 0xf8, 0x19,
        0xf1, 0x49, 0x54, 0x5a, 0x80, 0x21, 0x46, 0x64, 0x65
    };

    const Uint8 DQ_EXP_1024[] = {
        0x54, 0x8e, 0x94, 0x32, 0x79, 0x76, 0x81, 0x26, 0x3e, 0x34, 0xdf,
        0x23, 0x60, 0x54, 0xec, 0x50, 0xca, 0x4a, 0x23, 0x60, 0x73, 0x26,
        0xdf, 0xe3, 0xbc, 0x84, 0xed, 0xd5, 0x16, 0x7b, 0xe2, 0x39, 0x11,
        0x26, 0x02, 0x6b, 0x15, 0x8e, 0xeb, 0xc3, 0x8f, 0x19, 0x7f, 0xdc,
        0x90, 0xff, 0x11, 0x74, 0xb6, 0xbb, 0xc0, 0xee, 0x9e, 0x52, 0x7b,
        0xb1, 0x01, 0x55, 0x4b, 0x6c, 0x43, 0xe9, 0xed, 0x85
    };

    const Uint8 Q_ModulusINV_1024[] = {
        0x65, 0x95, 0xd7, 0x7a, 0xee, 0x82, 0xf7, 0x82, 0x72, 0x34, 0xcb,
        0x91, 0xbf, 0x25, 0x65, 0x47, 0x03, 0x1e, 0x5b, 0xe9, 0x28, 0xc6,
        0x9e, 0xf4, 0xe7, 0x1b, 0x24, 0x95, 0x04, 0x72, 0x30, 0x07, 0x9a,
        0xa7, 0x09, 0x98, 0xb1, 0x1b, 0x57, 0xc3, 0xa8, 0xd1, 0x18, 0x75,
        0xca, 0x5f, 0x02, 0x8d, 0xd7, 0x99, 0x63, 0xdf, 0x34, 0x1f, 0x52,
        0x64, 0x7c, 0x43, 0x17, 0xb7, 0x41, 0x79, 0xc5, 0x42
    };
    /* for 2048 keysize */
    const Uint8 PrivateKeyExponent_2048[] = {
        0x01, 0x93, 0x58, 0xa6, 0x58, 0x3e, 0xa3, 0x0d, 0xee, 0x3c, 0x5c, 0x6a,
        0xae, 0x41, 0x93, 0x24, 0xd9, 0x01, 0xf6, 0xef, 0x88, 0x64, 0x17, 0xc8,
        0x49, 0x4d, 0xd7, 0x7d, 0x3c, 0x88, 0x55, 0x4b, 0xbf, 0xe7, 0xaf, 0x8c,
        0x10, 0xdb, 0x2c, 0x5d, 0xc3, 0xec, 0x79, 0xe9, 0x6c, 0x9c, 0x0c, 0xd2,
        0x82, 0x23, 0x31, 0x51, 0x16, 0xd5, 0x09, 0xb7, 0x55, 0x74, 0xb6, 0x01,
        0x38, 0x41, 0x81, 0x0b, 0x07, 0x12, 0x9b, 0x01, 0xa3, 0xc8, 0x4f, 0x26,
        0x4b, 0xee, 0x67, 0xc3, 0xa9, 0xb4, 0x69, 0x01, 0x7f, 0xa1, 0x46, 0x84,
        0xd8, 0x03, 0xe9, 0x15, 0x18, 0xdf, 0xc2, 0x27, 0x73, 0x8a, 0x56, 0xbf,
        0x4b, 0xc6, 0x6d, 0x59, 0x72, 0xea, 0xca, 0xba, 0x54, 0x67, 0x5a, 0x52,
        0xea, 0xb1, 0x9b, 0x66, 0x63, 0xd8, 0xef, 0x72, 0x18, 0x38, 0xff, 0xe8,
        0x54, 0xd6, 0xf7, 0xbf, 0xf2, 0x9a, 0x05, 0xa6, 0xfc, 0x57, 0xca, 0x73,
        0x38, 0x3f, 0xcc, 0x6b, 0x63, 0x76, 0x88, 0x3a, 0xed, 0x6f, 0x0b, 0xbe,
        0xfb, 0x66, 0x02, 0x3e, 0x72, 0x9d, 0x2b, 0xa2, 0x98, 0xe3, 0xfc, 0x98,
        0xe2, 0x0d, 0x3e, 0x37, 0xb0, 0x21, 0xb7, 0x25, 0xee, 0xb2, 0xaf, 0xc5,
        0xc3, 0x0d, 0xac, 0xe5, 0xca, 0xb1, 0x15, 0xb0, 0x57, 0x14, 0xcd, 0x5d,
        0xd3, 0x0d, 0x32, 0xc5, 0xdd, 0xd4, 0x58, 0xa0, 0xc3, 0x4d, 0xb6, 0x29,
        0x3a, 0x9d, 0x89, 0xac, 0xd0, 0xfc, 0x33, 0xc8, 0x5d, 0x4e, 0x8c, 0x7f,
        0xc1, 0xfe, 0x53, 0xf8, 0x12, 0xe5, 0x06, 0x51, 0x20, 0x01, 0x7c, 0x8b,
        0x4a, 0xf7, 0x72, 0xfa, 0xba, 0x6a, 0x2d, 0xba, 0x75, 0x7d, 0x0e, 0x16,
        0xdb, 0x28, 0x8b, 0x3a, 0x86, 0xe2, 0xa9, 0x51, 0x37, 0x0b, 0x50, 0xfb,
        0x0c, 0x91, 0xb2, 0x29, 0x59, 0x2a, 0x22, 0xa7, 0x16, 0xe3, 0x18, 0x6e,
        0xdd, 0x69, 0x44, 0x15
    };

    const Uint8 P_Modulus_2048[] = {
        0xd5, 0x39, 0x40, 0x4f, 0xf5, 0x22, 0xe1, 0x30, 0x5d, 0x80, 0x69, 0xa6,
        0xd1, 0x19, 0x63, 0xec, 0x92, 0x89, 0x10, 0xd9, 0xe9, 0x0c, 0xa2, 0x05,
        0x13, 0xc6, 0xcf, 0xe9, 0x5c, 0xbc, 0x4b, 0x00, 0x66, 0xa7, 0x93, 0x22,
        0x46, 0x87, 0xc4, 0x4c, 0xc9, 0xde, 0xe0, 0x10, 0x4a, 0x2d, 0xc1, 0x5c,
        0xb2, 0x50, 0x89, 0xac, 0x5b, 0xe3, 0x97, 0xbf, 0xaf, 0xe0, 0x1f, 0x5a,
        0xd9, 0xd7, 0xbb, 0x84, 0x96, 0x2a, 0xb5, 0xeb, 0xeb, 0x5e, 0x33, 0x3d,
        0xd6, 0xfc, 0x05, 0x85, 0xce, 0xb3, 0xd2, 0x6d, 0xbb, 0xbe, 0xfe, 0x8c,
        0x29, 0x2b, 0x50, 0xde, 0xe2, 0x97, 0xf3, 0xed, 0x11, 0x18, 0x74, 0x37,
        0x8f, 0x9d, 0xe4, 0x02, 0xf2, 0xf1, 0x15, 0x2b, 0x80, 0xa9, 0x84, 0x3e,
        0x81, 0xff, 0x48, 0x02, 0xec, 0x86, 0xd2, 0x0a, 0x4c, 0x00, 0x14, 0x6f,
        0x8f, 0x4f, 0xfc, 0x1d, 0x8d, 0xd3, 0xee, 0xd3
    };

    const Uint8 Q_Modulus_2048[] = {
        0xd1, 0x0f, 0xce, 0xd2, 0x88, 0x3d, 0x51, 0xb5, 0xe1, 0xf3, 0x2d, 0xf2,
        0x23, 0xde, 0x33, 0xb5, 0xcc, 0xd6, 0x74, 0x84, 0x04, 0x47, 0x21, 0x21,
        0x42, 0x21, 0x8d, 0x45, 0x49, 0xc7, 0x0a, 0xa3, 0xb6, 0x41, 0xb6, 0x50,
        0xf4, 0xd9, 0xb5, 0xf7, 0x42, 0x71, 0xff, 0xcc, 0x9e, 0xc3, 0x4d, 0xf1,
        0xa4, 0xf5, 0x5b, 0x7f, 0x25, 0x96, 0x7c, 0xaa, 0x8e, 0xf0, 0xa8, 0xe0,
        0xe6, 0x7a, 0x74, 0xc3, 0x7e, 0xe9, 0xa2, 0xb2, 0x34, 0x52, 0x67, 0xcb,
        0x67, 0x94, 0x0c, 0x0b, 0xe1, 0x85, 0x32, 0xad, 0x23, 0x39, 0x45, 0xe2,
        0x76, 0xcb, 0xe4, 0xca, 0x85, 0x8e, 0x7b, 0x80, 0xfc, 0x2c, 0x82, 0x34,
        0x2f, 0xdf, 0x24, 0xb2, 0x38, 0xa1, 0x1c, 0x19, 0x46, 0x36, 0xb7, 0xc5,
        0x8c, 0x48, 0x0e, 0x51, 0x06, 0xa8, 0xad, 0xe0, 0x7e, 0xf0, 0x5d, 0x3b,
        0x9b, 0xf8, 0xa8, 0x7d, 0x10, 0x91, 0x3a, 0x5b
    };

    const Uint8 DP_EXP_2048[] = {
        0x0f, 0x51, 0x41, 0x91, 0x7c, 0xe6, 0xb8, 0x8e, 0xa4, 0xe8, 0xe8, 0xae,
        0x17, 0x2f, 0x5f, 0xc2, 0x4a, 0xf4, 0x95, 0xc5, 0x51, 0xbc, 0x9a, 0x97,
        0x0a, 0xc8, 0xa9, 0x7e, 0xf6, 0x2e, 0x80, 0xa4, 0xd2, 0xbb, 0x0f, 0x12,
        0xd3, 0x46, 0x45, 0x8f, 0xce, 0xa0, 0xb8, 0x2f, 0xf3, 0x64, 0x3e, 0x13,
        0xce, 0xab, 0x82, 0x78, 0x63, 0x51, 0x82, 0x41, 0x3e, 0xfd, 0x36, 0xc3,
        0x6c, 0x0a, 0xd7, 0x69, 0xba, 0xef, 0xee, 0x89, 0xb8, 0x2a, 0xd8, 0x3b,
        0x85, 0x0a, 0x2d, 0xcb, 0x63, 0x02, 0x00, 0x07, 0xea, 0x08, 0xda, 0x78,
        0x6f, 0x2c, 0xb1, 0x6e, 0x91, 0x90, 0xa0, 0xf1, 0x52, 0xdd, 0x12, 0xdc,
        0x3a, 0xf0, 0xf8, 0xc4, 0x4d, 0x77, 0x8c, 0x31, 0xc7, 0xd8, 0x65, 0xab,
        0xa7, 0xe3, 0x12, 0xe5, 0x42, 0xe0, 0x9c, 0x8e, 0x28, 0xcf, 0x88, 0xa8,
        0x4a, 0xff, 0x4f, 0xf9, 0x3f, 0x8b, 0x0e, 0x09
    };

    const Uint8 DQ_EXP_2048[] = {
        0x7b, 0x22, 0xed, 0x75, 0xd1, 0xab, 0x14, 0x5a, 0xa5, 0xd8, 0x3f, 0x02,
        0xb5, 0x1f, 0xa6, 0xa3, 0x79, 0x20, 0x03, 0x86, 0xd2, 0xa2, 0x36, 0xa0,
        0x49, 0x3c, 0x4b, 0xe2, 0x38, 0xbf, 0x54, 0xc3, 0xf2, 0x90, 0xa7, 0xda,
        0xed, 0x2c, 0xe2, 0x61, 0xdd, 0xb0, 0x19, 0xb3, 0xa2, 0xfb, 0x74, 0x08,
        0x55, 0x59, 0xf2, 0xe7, 0x63, 0xf3, 0x4c, 0x40, 0x85, 0x6a, 0xb8, 0x7d,
        0xa7, 0x23, 0x0f, 0x6d, 0x2a, 0x6e, 0x60, 0x56, 0xc8, 0x3c, 0x95, 0x48,
        0x18, 0x1c, 0xfa, 0x2f, 0x71, 0x48, 0xab, 0xfd, 0x90, 0x96, 0xa6, 0x53,
        0xea, 0x16, 0xd4, 0x0e, 0x79, 0x35, 0xe0, 0x06, 0xac, 0x01, 0x67, 0x3b,
        0x67, 0xca, 0xed, 0xe9, 0x4f, 0x33, 0x8d, 0xc2, 0x51, 0x39, 0xdf, 0x6a,
        0x2a, 0xe3, 0x32, 0x13, 0x85, 0x71, 0x8a, 0xe0, 0x84, 0xc3, 0xfc, 0x96,
        0x24, 0x9b, 0x04, 0x5a, 0x8d, 0x8c, 0x8c, 0xab
    };

    const Uint8 Q_ModulusINV_2048[] = {
        0x54, 0x66, 0x50, 0x55, 0x98, 0x22, 0x72, 0x64, 0xa9, 0xa5, 0xb0, 0x6e,
        0x65, 0x82, 0x4f, 0x3a, 0xe7, 0xa0, 0x3d, 0x56, 0x21, 0x9d, 0xca, 0xb7,
        0x5e, 0xd0, 0x59, 0x0a, 0xd1, 0x06, 0x1a, 0x53, 0x2d, 0x42, 0x92, 0xa0,
        0xcf, 0xe1, 0x91, 0x87, 0x2b, 0xd3, 0x02, 0xbf, 0xc7, 0x0b, 0xbc, 0x67,
        0x4b, 0x91, 0xa3, 0x7f, 0x28, 0xe3, 0xe9, 0xe1, 0x87, 0xb0, 0x10, 0x23,
        0x4e, 0xc1, 0x38, 0xb7, 0x7f, 0x2a, 0x0f, 0x89, 0xf1, 0x41, 0x7c, 0xc1,
        0x98, 0x04, 0x10, 0xd7, 0xfe, 0xff, 0x8a, 0xad, 0xd6, 0x36, 0xee, 0xb7,
        0x39, 0x5d, 0xaa, 0xe0, 0x64, 0x61, 0xc0, 0x28, 0x4e, 0x3b, 0x4a, 0x5c,
        0x24, 0xf3, 0x99, 0x7d, 0x6b, 0x6f, 0x2a, 0x2c, 0xbb, 0x85, 0xb3, 0x74,
        0xf5, 0xed, 0x27, 0xb7, 0x96, 0xe5, 0x5f, 0x5c, 0xaa, 0x7b, 0xa2, 0xdd,
        0x3b, 0xb9, 0x80, 0x09, 0x69, 0x62, 0xfd, 0x2b
    };

    unsigned long Exponent = 0x10001;
    int           ret_val;
    BIGNUM *      mod_BN = nullptr, *pvt_exponent_BN = nullptr, *P_BN = nullptr,
           *Q_BN = nullptr, *DP_BN = nullptr, *DQ_BN = nullptr,
           *QINV_BN = nullptr;

    if (m_key_len * 8 == KEY_SIZE_1024) {
        mod_BN          = BN_bin2bn(Modulus_1024, sizeof(Modulus_1024), NULL);
        pvt_exponent_BN = BN_bin2bn(
            PrivateKeyExponent_1024, sizeof(PrivateKeyExponent_1024), NULL);
        P_BN    = BN_bin2bn(P_Modulus_1024, sizeof(P_Modulus_1024), NULL);
        Q_BN    = BN_bin2bn(Q_Modulus_1024, sizeof(Q_Modulus_1024), NULL);
        DP_BN   = BN_bin2bn(DP_EXP_1024, sizeof(DP_EXP_1024), NULL);
        DQ_BN   = BN_bin2bn(DQ_EXP_1024, sizeof(DQ_EXP_1024), NULL);
        QINV_BN = BN_bin2bn(Q_ModulusINV_1024, sizeof(Q_ModulusINV_1024), NULL);
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        mod_BN          = BN_bin2bn(Modulus_2048, sizeof(Modulus_2048), NULL);
        pvt_exponent_BN = BN_bin2bn(
            PrivateKeyExponent_2048, sizeof(PrivateKeyExponent_2048), NULL);
        P_BN    = BN_bin2bn(P_Modulus_2048, sizeof(P_Modulus_2048), NULL);
        Q_BN    = BN_bin2bn(Q_Modulus_2048, sizeof(Q_Modulus_2048), NULL);
        DP_BN   = BN_bin2bn(DP_EXP_2048, sizeof(DP_EXP_2048), NULL);
        DQ_BN   = BN_bin2bn(DQ_EXP_2048, sizeof(DQ_EXP_2048), NULL);
        QINV_BN = BN_bin2bn(Q_ModulusINV_2048, sizeof(Q_ModulusINV_2048), NULL);
    } else {
        std::cout << "Invalid key len value" << std::endl;
        return false;
    }

    /* build the params needed to generate keys */
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();

    /* components for public key */
    OSSL_PARAM_BLD_push_BN(param_bld, "n", mod_BN);
    OSSL_PARAM_BLD_push_ulong(param_bld, "e", Exponent);

    /* components for pvt key */
    OSSL_PARAM_BLD_push_BN(param_bld, "d", pvt_exponent_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor1", P_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor2", Q_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent1", DP_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent2", DQ_BN);
    OSSL_PARAM_BLD_push_BN(param_bld, "rsa-coefficient1", QINV_BN);

    OSSL_PARAM_free(m_params);

    m_params = OSSL_PARAM_BLD_to_param(param_bld);

    OSSL_PARAM_BLD_free(param_bld);

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_fromdata_init failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (1
        != EVP_PKEY_fromdata(m_rsa_handle_keyctx_pub,
                             &m_pkey_pub,
                             EVP_PKEY_PUBLIC_KEY,
                             m_params)) {
        std::cout << "EVP_PKEY_fromdata failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_pkey_pub == nullptr) {
        std::cout << "Null key : Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }

    /* free all these Bignums after use */
    BN_free(mod_BN);
    BN_free(pvt_exponent_BN);
    BN_free(P_BN);
    BN_free(Q_BN);
    BN_free(DP_BN);
    BN_free(DQ_BN);
    BN_free(QINV_BN);

    return true;
}

bool
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    int retval;
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (m_rsa_handle_keyctx_pvt == nullptr) {
        std::cout << "EVP_PKEY_CTX_new_from_name returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1 != EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_fromdata_init failed" << std::endl;
        retval = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (1
        != EVP_PKEY_fromdata(m_rsa_handle_keyctx_pvt,
                             &m_pkey_pvt,
                             OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                             m_params)) {
        std::cout << "EVP_PKEY_fromdata failed" << std::endl;
        retval = ERR_GET_REASON(ERR_get_error());
        return false;
    }
    if (m_pkey_pvt == nullptr) {
        std::cout << "Null key : Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
        return false;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    return true;
}

bool
OpenSSLRsaBase::ValidateKeys()
{
    return true;
}

int
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    int           ret_val = 0;
    size_t        outlen;
    const EVP_MD* digest     = nullptr;
    const char*   digest_str = "";

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey_pub, NULL);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_encrypt_init failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        switch (m_digest_info.dt_len) {
            /* FIXME: add more cases here */
            case ALC_DIGEST_LEN_256:
                digest_str = "sha256";
                break;
            case ALC_DIGEST_LEN_512:
                digest_str = "sha512";
                break;
            default:
                std::cout << "Invalid digest length" << std::endl;
                return 1;
        }
        digest = EVP_get_digestbyname((const char*)digest_str);
        if (digest == nullptr) {
            std::cout << "Digest type is invalid" << std::endl;
            return 1;
        }
        /* set padding mode parameters */
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pub, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pub, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }

    /* call encrypt */
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            NULL,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            data.m_encrypted_data,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    return 0;
}

int
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    int           ret_val = 0;
    size_t        outlen;
    const EVP_MD* digest     = nullptr;
    const char*   digest_str = "";

    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, NULL);
    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        switch (m_digest_info.dt_len) {
            /* FIXME: add more cases here */
            case ALC_DIGEST_LEN_256:
                digest_str = "sha256";
                break;
            case ALC_DIGEST_LEN_512:
                digest_str = "sha512";
                break;
            default:
                std::cout << "Invalid digest length" << std::endl;
                return 1;
        }
        digest = EVP_get_digestbyname(digest_str);
        if (digest == nullptr) {
            std::cout << "Digest type is invalid" << std::endl;
            return 1;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    /* now call decrypt */
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    return 0;
}

/* sign verify */
int
OpenSSLRsaBase::Sign(const alcp_rsa_data_t& data)
{
    return 0;
}
int
OpenSSLRsaBase::Verify(const alcp_rsa_data_t& data)
{
    return 0;
}

bool
OpenSSLRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
