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
#include "digest/alc_base.hh"
#include "digest/base.hh"
#include "digest/gtest_base.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>

/* SHA2 cross tests */
TEST(DIGEST_SHA2, CROSS_224)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_224;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_224;
    Digest_Cross(224, info);
}
TEST(DIGEST_SHA2, CROSS_256)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_256;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_256;
    Digest_Cross(256, info);
}
TEST(DIGEST_SHA2, CROSS_384)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_384;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_384;
    Digest_Cross(384, info);
}
TEST(DIGEST_SHA2, CROSS_512)
{
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.dt_len          = ALC_DIGEST_LEN_512;
    Digest_Cross(512, info);
}

/* SHA3 cross tests */
/* NOTE: IPPCP doesnt support SHA3 as of now,
 SHA3 tests will be skipped for IPPCP */
TEST(DIGEST_SHA3, CROSS_224)
{
    if (useipp)
        GTEST_SKIP();
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_224;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_224;
    Digest_Cross(224, info);
}
TEST(DIGEST_SHA3, CROSS_256)
{
    if (useipp)
        GTEST_SKIP();
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_256;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_256;
    Digest_Cross(256, info);
}
TEST(DIGEST_SHA3, CROSS_384)
{
    if (useipp)
        GTEST_SKIP();
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_384;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_384;
    Digest_Cross(384, info);
}
TEST(DIGEST_SHA3, CROSS_512)
{
    if (useipp)
        GTEST_SKIP();
    alc_digest_info_t info;
    info.dt_mode.dm_sha2 = ALC_SHA2_512;
    info.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.dt_len          = ALC_DIGEST_LEN_512;
    Digest_Cross(512, info);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    testing::TestEventListeners& listeners =
        testing::UnitTest::GetInstance()->listeners();
    parseArgs(argc, argv);
#ifndef USE_IPP
    if (useipp)
        printErrors("IPP is not avaiable");
#endif
#ifndef USE_OSSL
    if (useossl)
        printErrors("OpenSSL is not avaiable");
#endif
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