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

#pragma once
#include "alc_base.hh"
#include "base.hh"
#include "gtest_base.hh"
#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_base.hh"
#endif
#include "string.h"
#include <alcp/alcp.h>
#include <iostream>

using namespace alcp::bench;

/* Add all the KAT tests here */
TEST(DIGEST_SHA2, KAT_224)
{
    alc_error_t          error;
    DataSet              ds = DataSet("dataset_SHA_224.csv");
    std::vector<uint8_t> digest(28, 0);
    AlcpDigestBase adb(ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    DigestBase*    db;
    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    if (useipp == true)
        db = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_224, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224);
    if (useossl == true)
        db = &odb;
#endif
    while (ds.readMsgDigest()) {
        error = db->digest_function(&(ds.getMessage()[0]),
                                    ds.getMessage().size(),
                                    &(digest[0]),
                                    digest.size());
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(
            ArraysMatch(digest,         // output
                        ds.getDigest(), // expected, from the KAT test data
                        ds,
                        std::string("SHA2_224_KAT")));
    }
}

/* SHA256 */
TEST(DIGEST_SHA2, KAT_256)
{
    alc_error_t          error;
    DataSet              ds = DataSet("dataset_SHA_256.csv");
    std::vector<uint8_t> digest(32, 0);
    AlcpDigestBase adb(ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    DigestBase*    db;
    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    if (useipp == true)
        db = &idb;
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256);
    if (useossl == true)
        db = &odb;
#endif
    while (ds.readMsgDigest()) {
        error = db->digest_function(&(ds.getMessage()[0]),
                                    ds.getMessage().size(),
                                    &(digest[0]),
                                    digest.size());
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(
            ArraysMatch(digest,         // output
                        ds.getDigest(), // expected, from the KAT test data
                        ds,
                        std::string("SHA2_256_KAT")));
    }
}

/* SHA384 */
TEST(DIGEST_SHA2, KAT_384)
{
    alc_error_t          error;
    DataSet              ds = DataSet("dataset_SHA_384.csv");
    std::vector<uint8_t> digest(48, 0);
    AlcpDigestBase adb(ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    DigestBase*    db;
    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    if (useipp == true)
        db = &idb;
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384);
    if (useossl == true)
        db = &odb;
#endif
    while (ds.readMsgDigest()) {
        error = db->digest_function(&(ds.getMessage()[0]),
                                    ds.getMessage().size(),
                                    &(digest[0]),
                                    digest.size());
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(
            ArraysMatch(digest,         // output
                        ds.getDigest(), // expected, from the KAT test data
                        ds,
                        std::string("SHA2_384_KAT")));
    }
}

/* SHA512 */
TEST(DIGEST_SHA2, KAT_512)
{
    alc_error_t          error;
    DataSet              ds = DataSet("dataset_SHA_512.csv");
    std::vector<uint8_t> digest(64, 0);
    AlcpDigestBase adb(ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    DigestBase*    db;
    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    if (useipp == true)
        db = &idb;
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(
        ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512);
    if (useossl == true)
        db = &odb;
#endif
    while (ds.readMsgDigest()) {
        error = db->digest_function(&(ds.getMessage()[0]),
                                    ds.getMessage().size(),
                                    &(digest[0]),
                                    digest.size());
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(
            ArraysMatch(digest,         // output
                        ds.getDigest(), // expected, from the KAT test data
                        ds,
                        std::string("SHA2_512_KAT")));
    }
}
