/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "rsa/alc_rsa.hh"
#include "rsa/gtest_base_rsa.hh"
#include "rsa/rsa.hh"
#include "string.h"
#include <iostream>

/* All tests to be added here */
TEST(RSA_No_Padding_1024_SHA2_256, KAT)
{
    if (useipp)
        GTEST_SKIP() << "IPP is not supported yet";
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    Rsa_KAT(ALCP_TEST_RSA_NO_PADDING, 1024, "SHA2", 256, dinfo, mgfinfo);
}
TEST(RSA_No_Padding_2048_SHA2_256, KAT)
{
    if (useipp)
        GTEST_SKIP() << "IPP is not supported yet";
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    Rsa_KAT(ALCP_TEST_RSA_NO_PADDING, 2048, "SHA2", 256, dinfo, mgfinfo);
}
TEST(RSA_Padding_1024_SHA2_256, KAT)
{
    if (useipp)
        GTEST_SKIP() << "IPP is not supported yet";
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    Rsa_KAT(ALCP_TEST_RSA_PADDING, 1024, "SHA2", 256, dinfo, mgfinfo);
}
TEST(RSA_Padding_2048_SHA2_256, KAT)
{
    if (useipp)
        GTEST_SKIP() << "IPP is not supported yet";
    alc_digest_info_t dinfo, mgfinfo;
    dinfo.dt_mode.dm_sha2 = ALC_SHA2_256;
    dinfo.dt_len          = ALC_DIGEST_LEN_256;
    dinfo.dt_type         = ALC_DIGEST_TYPE_SHA2;
    mgfinfo               = dinfo;
    Rsa_KAT(ALCP_TEST_RSA_PADDING, 2048, "SHA2", 256, dinfo, mgfinfo);
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
