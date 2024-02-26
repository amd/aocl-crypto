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
#include "hmac/alc_hmac.hh"
#include "hmac/gtest_base_hmac.hh"
#include "hmac/hmac.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>

/* Add tests here */
TEST(HMAC_SHA2, CROSS_224)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_224;
    Hmac_Cross(224, "SHA2", info);
}
TEST(HMAC_SHA2, CROSS_256)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_256;
    Hmac_Cross(256, "SHA2", info);
}
TEST(HMAC_SHA2, CROSS_384)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_384;
    Hmac_Cross(384, "SHA2", info);
}
TEST(HMAC_SHA2, CROSS_512)
{
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA2;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha2 = ALC_SHA2_512;
    Hmac_Cross(512, "SHA2", info);
}
TEST(HMAC_SHA3, CROSS_224)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_224;
    Hmac_Cross(224, "SHA3", info);
}
TEST(HMAC_SHA3, CROSS_256)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_256;
    Hmac_Cross(256, "SHA3", info);
}
TEST(HMAC_SHA3, CROSS_384)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_384;
    Hmac_Cross(384, "SHA3", info);
}
TEST(HMAC_SHA3, CROSS_512)
{
    if (useipp || oa_override)
        GTEST_SKIP() << "IPP doesnt have SHA3 implemented yet";
    alc_mac_info_t info;
    info.mi_algoinfo.hmac.hmac_digest.dt_type         = ALC_DIGEST_TYPE_SHA3;
    info.mi_algoinfo.hmac.hmac_digest.dt_mode.dm_sha3 = ALC_SHA3_512;
    Hmac_Cross(512, "SHA3", info);
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parseArgs(argc, argv);
#ifndef USE_IPP
    if (useipp)
        printErrors("IPP is not avaiable");
#endif
#ifndef USE_OSSL
    if (useossl)
        printErrors("OpenSSL is not avaiable");
#endif

    return RUN_ALL_TESTS();
}