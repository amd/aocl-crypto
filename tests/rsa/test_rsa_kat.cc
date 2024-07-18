/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/alcp.h"
#include "rsa/alc_rsa.hh"
#include "rsa/gtest_base_rsa.hh"
#include "rsa/rsa.hh"
#include "string.h"
#include <iostream>

alc_digest_info_t dinfo_256{}, dinfo_384{}, dinfo_512{}, mgfinfo_256{},
    mgfinfo_512{};

/* padding mode */
TEST(RSA_SignVerify_PSS_2048, KAT_SHA2_256)
{
    dinfo_256.dt_mode = ALC_SHA2_256;
    dinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256       = dinfo_256;
    Rsa_KAT(
        "SignVerify", ALCP_TEST_RSA_PADDING_PSS, 2048, dinfo_256, mgfinfo_256);
}
TEST(RSA_SignVerify_PKCS_2048, KAT_SHA2_256)
{
    dinfo_256.dt_mode = ALC_SHA2_256;
    dinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256       = dinfo_256;
    Rsa_KAT(
        "SignVerify", ALCP_TEST_RSA_PADDING_PKCS, 2048, dinfo_256, mgfinfo_256);
}

/* All tests to be added here */
/* non padded mode */
TEST(RSA_EncryptDecrypt_No_Padding_1024, KAT)
{
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_NO_PADDING,
            1024,
            dinfo_256,
            mgfinfo_256);
}
TEST(RSA_EncryptDecrypt_No_Padding_2048, KAT)
{
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_NO_PADDING,
            2048,
            dinfo_256,
            mgfinfo_256);
}
TEST(RSA_EncryptDecrypt_PKCS_2048, KAT)
{
    dinfo_256.dt_mode = ALC_SHA2_256;
    dinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256       = dinfo_256;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_PKCS,
            2048,
            dinfo_256,
            mgfinfo_256);
}

/* padding mode */
TEST(RSA_EncryptDecrypt_OAEP_1024, KAT_SHA2_256_MGF_256)
{
    dinfo_256.dt_mode = ALC_SHA2_256;
    dinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256       = dinfo_256;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_OAEP,
            1024,
            dinfo_256,
            mgfinfo_256);
}
TEST(RSA_EncryptDecrypt_OAEP_2048, KAT_SHA2_256_MGF_256)
{
    dinfo_256.dt_mode = ALC_SHA2_256;
    dinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256       = dinfo_256;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_OAEP,
            2048,
            dinfo_256,
            mgfinfo_256);
}
TEST(RSA_EncryptDecrypt_OAEP_2048, KAT_SHA2_512_MGF_256)
{
    if (useipp)
        GTEST_SKIP()
            << "IPP doesnt support using different types of Digest and Mgf "
               "schemes, skipping this test";
    dinfo_512.dt_mode   = ALC_SHA2_512;
    dinfo_512.dt_len    = ALC_DIGEST_LEN_512;
    dinfo_512.dt_type   = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_256.dt_mode = ALC_SHA2_256;
    mgfinfo_256.dt_len  = ALC_DIGEST_LEN_256;
    mgfinfo_256.dt_type = ALC_DIGEST_TYPE_SHA2;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_OAEP,
            2048,
            dinfo_512,
            mgfinfo_256);
}
TEST(RSA_EncryptDecrypt_OAEP_2048, KAT_SHA2_256_MGF_512)
{
    if (useipp)
        GTEST_SKIP()
            << "IPP doesnt support using different types of Digest and Mgf "
               "schemes, skipping this test";
    dinfo_256.dt_mode   = ALC_SHA2_256;
    dinfo_256.dt_len    = ALC_DIGEST_LEN_256;
    dinfo_256.dt_type   = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_512.dt_mode = ALC_SHA2_512;
    mgfinfo_512.dt_len  = ALC_DIGEST_LEN_512;
    mgfinfo_512.dt_type = ALC_DIGEST_TYPE_SHA2;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_OAEP,
            2048,
            dinfo_256,
            mgfinfo_512);
}
TEST(RSA_EncryptDecrypt_OAEP_2048, KAT_SHA2_512_MGF_512)
{
    dinfo_512.dt_mode = ALC_SHA2_512;
    dinfo_512.dt_len  = ALC_DIGEST_LEN_512;
    dinfo_512.dt_type = ALC_DIGEST_TYPE_SHA2;
    mgfinfo_512       = dinfo_512;
    Rsa_KAT("EncryptDecrypt",
            ALCP_TEST_RSA_PADDING_OAEP,
            2048,
            dinfo_512,
            mgfinfo_512);
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
