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
#include "hmac/alc_hmac.hh"
#include "hmac/gtest_base_hmac.hh"
#include "hmac/hmac.hh"

/* All tests to be added here */
TEST(HMAC_SHA3, KAT_224)
{
    if (useipp)
        GTEST_SKIP();
    Hmac_KAT(ALC_SHA3_224);
}
TEST(HMAC_SHA3, KAT_256)
{
    if (useipp)
        GTEST_SKIP();
    Hmac_KAT(ALC_SHA3_256);
}
TEST(HMAC_SHA3, KAT_384)
{
    if (useipp)
        GTEST_SKIP();
    Hmac_KAT(ALC_SHA3_384);
}
TEST(HMAC_SHA3, KAT_512)
{
    if (useipp)
        GTEST_SKIP();
    Hmac_KAT(ALC_SHA3_512);
}
/* HMAC SHA2 tests */
TEST(HMAC_SHA2, KAT_224)
{
    Hmac_KAT(ALC_SHA2_224);
}
TEST(HMAC_SHA2, KAT_256)
{
    Hmac_KAT(ALC_SHA2_256);
}
TEST(HMAC_SHA2, KAT_384)
{
    Hmac_KAT(ALC_SHA2_384);
}
TEST(HMAC_SHA2, KAT_512)
{
    Hmac_KAT(ALC_SHA2_512);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parseArgs(argc, argv);
#ifndef USE_IPP
    if (useipp)
        std::cout << RED << "IPP is not avaiable, defaulting to ALCP" << RESET
                  << std::endl;
#endif

#ifndef USE_OSSL
    if (useossl) {
        std::cout << RED << "OpenSSL is not avaiable, defaulting to ALCP"
                  << RESET << std::endl;
    }
#endif
    return RUN_ALL_TESTS();
}
