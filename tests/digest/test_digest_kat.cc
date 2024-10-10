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

/* C/C++ Headers */
#include <iostream>
#include <string.h>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "digest/gtest_base_digest.hh"

TEST(DIGEST_SHA3, KAT_SHAKE128_CTX_COPY)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHAKE_128, true, false);
}

TEST(DIGEST_SHA3, KAT_SHAKE128_CTX_COPY_SQUEEZE)
{
    /* This functionality is supported only from Openssl 3.3.0 onwards */
#if OPENSSL_API_LEVEL < 30300
    if (useossl)
        GTEST_SKIP() << "Openssl supports Shake Squeeze test only from v3.3.0 "
                        "onwards, skipping this";
#endif
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_KAT(ALC_SHAKE_128, true, true);
}

/* SHAKE128/256 tests (IPP doesnt have these) */
TEST(DIGEST_SHA3, KAT_SHAKE128)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";

    Digest_KAT(ALC_SHAKE_128, false, false);
}
TEST(DIGEST_SHA3, KAT_SHAKE256)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHAKE_256, false, false);
}

/* SHA2 tests */
TEST(DIGEST_SHA2, KAT_224)
{
    Digest_KAT(ALC_SHA2_224, false, false);
}
TEST(DIGEST_SHA2, KAT_224_CTX_COPY)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have ctx copy feature yet";
    Digest_KAT(ALC_SHA2_224, true, false);
}

TEST(DIGEST_SHA2, KAT_256)
{
    Digest_KAT(ALC_SHA2_256, false, false);
}
TEST(DIGEST_SHA2, KAT_384)
{
    Digest_KAT(ALC_SHA2_384, false, false);
}
TEST(DIGEST_SHA2, KAT_512)
{
    Digest_KAT(ALC_SHA2_512, false, false);
}
/* sha512 truncated variants- 224,256*/
TEST(DIGEST_SHA2, KAT_512_224)
{
    Digest_KAT(ALC_SHA2_512_224, false, false);
}
TEST(DIGEST_SHA2, KAT_512_256)
{
    Digest_KAT(ALC_SHA2_512_256, false, false);
}

/* SHA3 tests */
/* NOTE: SHA3 tests will be skipped for IPPCP
 IPPCP doesnt have SHA3 as of now */
TEST(DIGEST_SHA3, KAT_224)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHA3_224, false, false);
}
TEST(DIGEST_SHA3, KAT_224_CTX_COPY)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHA3_224, true, false);
}

TEST(DIGEST_SHA3, KAT_256)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHA3_256, false, false);
}
TEST(DIGEST_SHA3, KAT_384)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHA3_384, false, false);
}
TEST(DIGEST_SHA3, KAT_512)
{
    if (useipp)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    Digest_KAT(ALC_SHA3_512, false, false);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parseArgs(argc, argv);
#ifndef USE_IPP
    if (useipp)
        std::cout << RED << "IPP is not available, defaulting to ALCP" << RESET
                  << std::endl;
#endif
#ifndef USE_OSSL
    if (useossl) {
        std::cout << RED << "OpenSSL is not available, defaulting to ALCP"
                  << RESET << std::endl;
    }
#endif

    return RUN_ALL_TESTS();
}
