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

static const uint8_t sample_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static const uint8_t sample_tweak_key[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};

static const uint8_t sample_iv[] = {
    0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};

TEST(XTS_ERROR_TEST, dublicate_key_test)
{

    alc_error_t err;
    // const int   err_size = 256;
    // uint8_t     err_buf[err_size];
    Context* ctx = new Context();

//  FIXME: pedantic is forcing to be initialized in another way, find a better
//  solution.
#if 1
    alc_key_info_t kinfo;
#else
    alc_key_info_t kinfo = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .key  = sample_tweak_key,
        .len  = sizeof(sample_key) * 8,
    };
#endif
    kinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    kinfo.fmt  = ALC_KEY_FMT_RAW;
    kinfo.key  = sample_tweak_key;
    kinfo.len  = sizeof(sample_key) * 8;

#if 1
    alc_cipher_info_t cinfo;
    cinfo.ci_type                          = ALC_CIPHER_TYPE_AES;
    cinfo.ci_algo_info.ai_mode             = ALC_AES_MODE_XTS;
    cinfo.ci_algo_info.ai_iv               = sample_iv;
    cinfo.ci_algo_info.ai_xts.xi_tweak_key = &kinfo;
    cinfo.ci_key_info.type                 = ALC_KEY_TYPE_SYMMETRIC;
    cinfo.ci_key_info.fmt                  = ALC_KEY_FMT_RAW;
    cinfo.ci_key_info.key                  = sample_key;
    cinfo.ci_key_info.len                  = sizeof(sample_key) * 8;

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
            .key     = sample_key,
            .len     = sizeof(sample_key) * 8,
        },
    };
#endif
    err = AesBuilder::Build(cinfo.ci_algo_info, cinfo.ci_key_info, *ctx);
    EXPECT_TRUE(err == ALC_ERROR_DUPLICATE_KEY);
    // FIXME: Dellocate ctx variable
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
