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

#include "ecdh/alc_ecdh_base.hh"
#include "ecdh/ecdh_base.hh"
#include "ecdh/gtest_base_ecdh.hh"
#include "string.h"
#include <alcp/alcp.h>
#include <iostream>

/* All tests to be added here */
TEST(ecdh, KAT_x25519)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_KAT(info);
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
