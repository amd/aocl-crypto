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

// #include "cipher/alc_base.hh"
// #include "cipher/base.hh"

#include "capi/cipher/ctx.hh"
#include "cipher/aes_build.hh"
#include "cipher/gtest_base.hh"

using namespace alcp::testing;
using namespace alcp::cipher;

std::string MODE_STR = "XTS";

#define ALC_MODE ALC_AES_MODE_XTS

static const uint8_t valid_key[] = { 0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06,
                                     0xac, 0x35, 0x3b, 0x2c, 0x34, 0x38,
                                     0x76, 0x08, 0x17, 0x62 };

static const uint8_t valid_tweak_key[] = { 0x09, 0x09, 0x23, 0x02, 0x6e, 0x91,
                                           0x77, 0x18, 0x15, 0xf2, 0x9d, 0xab,
                                           0x01, 0x93, 0x2f, 0x2f };

static const uint8_t valid_iv[] = { 0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda,
                                    0x59, 0xc6, 0x6e, 0x4b, 0x92, 0x01,
                                    0x3e, 0x76, 0x8a, 0xd5 };

const uint8_t cipherText[] = {
    0xa8, 0xac, 0xf5, 0x7a, 0x6f, 0x86, 0x59, 0xe9, 0xba, 0x38, 0x2a, 0x4d,
    0x16, 0xba, 0xf1, 0x2a, 0x67, 0xd5, 0x43, 0x75, 0x63, 0xfd, 0x63, 0x29,
    0xd9, 0xa8, 0x87, 0xa8, 0x1,  0x4a, 0x10, 0x57, 0x63, 0xe2, 0xfd, 0xa1,
    0xc6, 0x9f, 0x7d, 0xb6, 0x8,  0x54, 0x1d, 0x7f, 0x11, 0xbc, 0xeb, 0xa9,
    0x95, 0x53, 0xa7, 0x8b, 0xc0, 0xae, 0xac, 0x5f, 0xa8, 0xf7, 0x42, 0x6f,
    0xc6, 0x92, 0xa8, 0x4b, 0xe8, 0x46, 0xed, 0xae, 0xa0, 0xdd, 0x67, 0x70,
    0xde, 0xc3, 0xc9, 0x80, 0x90, 0xc8, 0x9c, 0x96, 0xdf, 0x54, 0xee, 0x7b,
    0x81, 0x8e, 0x70, 0xf7, 0x4c, 0x8b, 0x4d, 0x1,  0xd2, 0xf1, 0x53, 0x5f,
    0x64, 0xc1, 0xd,  0x82, 0x79, 0x86, 0xe3, 0x14, 0xbe, 0xae, 0xe4, 0x4,
    0xa,  0x3b, 0x23, 0x63, 0x28, 0xc,  0x3b, 0xd7, 0x43, 0x75, 0xfa, 0xda,
    0x4c, 0x80, 0x7a, 0x96, 0x1d, 0x69, 0xdc, 0x33, 0x77, 0x70, 0xb9, 0x52,
    0x17, 0x13, 0x10, 0x4f, 0x8,  0xbc, 0x6,  0x0,  0x95, 0x19, 0xea, 0xc,
    0x53, 0x28, 0x8a, 0xf5, 0xf,  0xa6, 0x2,  0x48, 0x1b, 0xde, 0x99, 0x84,
    0x93, 0x71, 0xeb, 0x69, 0x2d, 0x38, 0x44, 0x9a, 0xba, 0x1a, 0x35, 0xae,
    0xeb, 0x71, 0x16, 0xba, 0xe1, 0x1,  0x7c, 0x57, 0xfc, 0xfa, 0xd3, 0x5f,
    0xd6, 0xb9, 0x64, 0x68, 0x70, 0xcf, 0x6d, 0xa3, 0xd4, 0x10, 0x40, 0x10,
    0x39, 0x80, 0xa9, 0x38, 0x30, 0x13, 0xf6, 0x8a, 0x54, 0x10, 0x2d, 0xcd,
    0x44, 0x42, 0xec, 0x9,  0xb1, 0x4f, 0xd1, 0xf3, 0xf5, 0x25, 0xfa, 0x12,
    0x33, 0xa6, 0x6d, 0x44, 0x48, 0xf9, 0x66, 0x54, 0x14, 0x1d, 0x7d, 0x91,
    0x43, 0x0,  0x98, 0xa7, 0xd6, 0xda, 0x2e, 0x25, 0x7e, 0x50, 0xeb, 0xd6,
    0x7e, 0xdb, 0x39, 0xa8, 0x61, 0xf1, 0x1a, 0xda, 0xf6, 0x2a, 0x42, 0x86,
    0x3a, 0xbc, 0x57, 0x5c, 0xbb, 0x8d, 0xed, 0x4e, 0xa5, 0xc4, 0x9f, 0x88,
    0x37, 0x8,  0xcb, 0x13, 0x1f, 0xff, 0x91, 0xcd, 0x1a, 0xbb, 0x9d, 0x9,
    0x13, 0x95, 0xc,  0x29, 0x94, 0x55, 0xde, 0xb3, 0x34, 0xca, 0x8,  0x38,
    0xe5, 0x62, 0x9f, 0x1d, 0x29, 0x66, 0x55, 0x89, 0x82, 0x5c, 0xc,  0xc5,
    0xf2, 0xb3, 0xfb, 0x6a, 0xd7, 0x3b, 0x1c, 0xb6, 0x1f, 0xae, 0x39, 0xa6,
    0xbb, 0x4,  0x2b, 0x99, 0x33, 0x6b, 0xdb, 0xda, 0x3a, 0xb6, 0x54, 0xa0,
    0xf8, 0x4d, 0xba, 0xfc, 0x3f, 0xd0, 0x2d, 0x7f, 0x2c, 0xe9, 0x62, 0x76,
    0xb0, 0x7d, 0x5a, 0xc8, 0xb6, 0xe4, 0xcf, 0xa,  0x8d, 0x4a, 0xee, 0xbc,
    0x62, 0xf8, 0x31, 0x5d, 0xe0, 0xe0, 0x36, 0x71, 0x8f, 0x27, 0x61, 0xed,
    0x76, 0x51, 0x56, 0xcf, 0xa2, 0x5f, 0x6e, 0xba, 0x2e, 0x3f, 0xe4, 0x33,
    0xa1, 0xdb, 0x71, 0xb6, 0xdd, 0x38, 0xd1, 0xdd, 0x8c, 0x45, 0xc3, 0x93,
    0x4d, 0xe0, 0x3c, 0x8a, 0x49, 0xb7, 0x8d, 0xa4, 0x5,  0xe9, 0x85, 0x9,
    0xed, 0x87, 0x2f, 0xc4, 0xa7, 0x3d, 0xc5, 0xa4, 0x42, 0x6e, 0xca, 0x59,
    0x4,  0x39, 0x8,  0x71, 0x55, 0x4b, 0xad, 0x6d, 0x3d, 0x47, 0xf6, 0x72,
    0x10, 0xcb, 0xa5, 0xde, 0xac, 0x9f, 0x71, 0x32, 0xd9, 0x2a, 0xa3, 0x29,
    0xd,  0xf8, 0x2,  0x5a,
};

const uint8_t plainText[] = {
    0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68, 0x20,
    0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65, 0x73, 0x20,
    0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x73,
    0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6f, 0x72,
    0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e, 0x64, 0x20,
    0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x61, 0x6e,
    0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x72, 0x65,
    0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x20, 0x73,
    0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x2e,
    0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76, 0x65, 0x72,
    0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x77,
    0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x64,
    0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6c, 0x6f,
    0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x20,
    0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65,
    0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20,
    0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x69, 0x6e,
    0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70, 0x68,
    0x73, 0x2e, 0x41, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61, 0x70,
    0x68, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x72, 0x69, 0x65,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63,
    0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x72, 0x65, 0x20,
    0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 0x6e,
    0x64, 0x20, 0x63, 0x6f, 0x68, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20,
    0x61, 0x6e, 0x64, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
    0x72, 0x65, 0x6c, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61,
    0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x70, 0x69,
    0x63, 0x2e, 0x20, 0x41, 0x6c, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x65, 0x76,
    0x65, 0x72, 0x79, 0x20, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6f, 0x66,
    0x20, 0x77, 0x72, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x79, 0x6f, 0x75,
    0x20, 0x64, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20,
    0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20,
    0x61, 0x20, 0x66, 0x65, 0x77, 0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e,
    0x63, 0x65, 0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62,
    0x65, 0x20, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x20,
    0x69, 0x6e, 0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x61, 0x67, 0x72, 0x61,
    0x70, 0x68, 0x73, 0x2e
};

bool
validateArrays(const uint8_t* tweakKey, const uint8_t* encKey, uint32_t len)
{

    for (uint32_t i = 0; i < len / 8; i++) {
        if (tweakKey[i] != encKey[i]) {
            return false;
        }
    }
    return true;
}

TEST(XTS_ERROR_TEST, dublicate_key_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(1));

    //  FIXME: pedantic is forcing to be initialized in another way, find a
    //  better solution.

#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_key,
        .len  = sizeof(valid_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_key;
    kinfo.len  = sizeof(valid_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    EXPECT_TRUE(err == ALC_ERROR_DUPLICATE_KEY);
    // FIXME: Dellocate ctx variable
}

TEST(XTS_ERROR_TEST, invalid_key_size_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx           = malloc(sizeof(1));
    const uint8_t        invalid_key[] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd,
    };

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(valid_tweak_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = invalid_key;
    cinfo.ci_key_info.len                  = sizeof(invalid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    EXPECT_TRUE(err == ALC_ERROR_INVALID_ARG);
    // FIXME: Dellocate ctx variable
}

TEST(XTS_ERROR_TEST, valid_request_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(1));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(sample_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    EXPECT_TRUE(err == ALC_ERROR_NONE);
    // FIXME: Dellocate ctx variable
}

TEST(XTS_ERROR_TEST, invalid_plain_text_len_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(Context));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(sample_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    const uint8_t pt[]    = { 0x7, 0x7, 0x8, 0xa, 0xe, 0x8, 0xb,
                           0x4, 0x3, 0xc, 0xb, 0x9, 0x8 };
    Uint64        pt_size = 8;
    Uint8*        dest    = (Uint8*)malloc(100);
    // auto ctx = static_cast<Context*>(handler.ch_context);

    err = alcp_cipher_encrypt(
        &handler, pt, dest, pt_size, cinfo.ci_algo_info.ai_iv);

    // FIXME: Dellocate ctx variable

    EXPECT_TRUE(err == ALC_ERROR_INVALID_DATA);
}

TEST(XTS_ERROR_TEST, valid_encrypt_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(Context));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(sample_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    Uint64 pt_size = 437;
    Uint8* dest    = (Uint8*)malloc(437);
    // auto ctx = static_cast<Context*>(handler.ch_context);

    err = alcp_cipher_encrypt(
        &handler, plainText, dest, pt_size, cinfo.ci_algo_info.ai_iv);

    // FIXME: Dellocate ctx variable

    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_TRUE(validateArrays(cipherText, dest, 16));
}

TEST(XTS_ERROR_TEST, valid_decrypt_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(Context));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(valid_tweak_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,
        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = valid_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    Uint64 ct_size = 437;
    Uint8* dest    = (Uint8*)malloc(437);
    // auto ctx = static_cast<Context*>(handler.ch_context);

    err = alcp_cipher_decrypt(
        &handler, cipherText, dest, ct_size, cinfo.ci_algo_info.ai_iv);

    // FIXME: Dellocate ctx variable
    EXPECT_TRUE(err == ALC_ERROR_NONE);
    EXPECT_TRUE(validateArrays(plainText, dest, 16));
}

TEST(XTS_ERROR_TEST, valid_encrypt_decrypt_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(Context));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(valid_tweak_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = valid_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
    alc_cipher_handle_t handler;

    handler.ch_context = ctx;

    err = alcp_cipher_request(&cinfo, &handler);

    for (int i = 16; i < 512 * 20; i++) {

        RngBase rb;

        Uint8* plainText = (Uint8*)malloc(i);
        rb.setRandomBytes(plainText, i);
        Uint64 ct_size = i;
        Uint8* dest    = (Uint8*)malloc(i);
        // auto ctx = static_cast<Context*>(handler.ch_context);

        err = alcp_cipher_encrypt(
            &handler, plainText, dest, ct_size, cinfo.ci_algo_info.ai_iv);

        Uint8* pt = (Uint8*)malloc(i);

        err = alcp_cipher_decrypt(
            &handler, dest, pt, ct_size, cinfo.ci_algo_info.ai_iv);

        // FIXME: Dellocate ctx variable
        EXPECT_TRUE(err == ALC_ERROR_NONE);
        EXPECT_TRUE(validateArrays(plainText, pt, i));
    }
}

TEST(XTS_ERROR_TEST, invalid_cipher_text_len_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    alc_cipher_context_p ctx = malloc(sizeof(Context));

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = valid_tweak_key,
        .len  = sizeof(sample_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = valid_tweak_key;
    kinfo.len  = sizeof(valid_tweak_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = valid_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = valid_key;
    cinfo.ci_key_info.len                  = sizeof(valid_key) * 8;

#else
    alc_cipher_info_t cinfo = {
        .ci_type = ALC_CIPHER_TYPE_AES,

        .ci_algo_info = {
            .ai_mode = ALC_AES_MODE_XTS,
            .ai_iv   = sample_iv,
            .ai_xts = {
                .xi_tweak_key = &kinfo,
            }
        },
            /* No padding, Not Implemented yet*/
        //.pad     = ALC_CIPHER_PADDING_NONE, 
        .ci_key_info     = {
            .type    = ALC_KEY_TYPE_SYMMETRIC,
            .fmt     = ALC_KEY_FMT_RAW,
            .key     = valid_key,
            .len     = sizeof(valid_key) * 8,
        },
    };
#endif
#if 1
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;
#else
    alc_cipher_handle_t handler;
    handler.ch_context = ctx;
#endif

    err = alcp_cipher_request(&cinfo, &handler);

    const uint8_t ct[]    = { 0x77, 0x8a, 0xe8, 0xb4, 0x3c };
    Uint64        ct_size = 5;
    Uint8*        dest    = (Uint8*)malloc(5);
    // auto ctx = static_cast<Context*>(handler.ch_context);

    err = alcp_cipher_encrypt(
        &handler, ct, dest, ct_size, cinfo.ci_algo_info.ai_iv);

    // FIXME: Dellocate ctx variable

    EXPECT_TRUE(err == ALC_ERROR_INVALID_DATA);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    parseArgs(argc, argv);
    auto default_printer =
        listeners.Release(listeners.default_result_printer());

    ConfigurableEventListener* listener =
        new ConfigurableEventListener(default_printer);

    listener->showEnvironment    = true;
    listener->showTestCases      = true;
    listener->showTestNames      = true;
    listener->showSuccesses      = true;
    listener->showInlineFailures = true;
    listeners.Append(listener);
    return RUN_ALL_TESTS();
}
