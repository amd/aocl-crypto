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
#include "alc_base.hh"
#include "base.hh"
#include "gtest_base.hh"
#include "rng_base.hh"
#include "string.h"
#include <alcp/alcp.h>
#include <iostream>

#ifdef USE_IPP
#include "ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "openssl_base.hh"
#endif

#define MAX_LOOP   160000
#define INC_LOOP   16
#define START_LOOP 16

using namespace alcp::testing;

ExecRecPlay* fr;

/* Add all the KAT tests here */
TEST(DIGEST_SHA2, CROSS_224)
{
    alc_error_t            error;
    std::vector<uint8_t>   data;
    std::vector<uint8_t>   digestAlcp(28, 0);
    std::vector<uint8_t>   digestExt(28, 0);
    const alc_sha2_mode_t  alc_mode       = ALC_SHA2_224;
    const alc_digest_len_t alc_digest_len = ALC_DIGEST_LEN_224;
    AlcpDigestBase         adb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string("SHA2_224"), true);
        fr->fastForward(SHA2_224);
    } else
        fr = new ExecRecPlay(std::string("SHA2_224"), false);
#ifdef USE_IPP
    IPPDigestBase idb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if (useipp == true)
        extDb = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    // TODO: Improve the incementor and start condition of forloop
    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rng.genRandomBytes(i);
                fr->setRecEvent(data, SHA2_224);
            } catch (const char* error) {
                printErrors(error);
                exit(-1);
            }
        } else {
            fr->nextLog();
            fr->getValues(&data);
        }

        error = db->digest_function(
            &(data[0]), data.size(), &(digestAlcp[0]), digestAlcp.size());
        error = extDb->digest_function(
            &(data[0]), data.size(), &(digestExt[0]), digestExt.size());
        db->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        extDb->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
        if (!bbxreplay) {
            fr->dumpBlackBox();
            fr->endRecEvent();
            fr->dumpLog();
        }
    }
    delete fr;
}

TEST(DIGEST_SHA2, CROSS_256)
{
    alc_error_t            error;
    std::vector<uint8_t>   data;
    std::vector<uint8_t>   digestAlcp(32, 0);
    std::vector<uint8_t>   digestExt(32, 0);
    const alc_sha2_mode_t  alc_mode       = ALC_SHA2_256;
    const alc_digest_len_t alc_digest_len = ALC_DIGEST_LEN_256;
    AlcpDigestBase         adb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string("SHA2_256"), true);
        fr->fastForward(SHA2_256);
    } else
        fr = new ExecRecPlay(std::string("SHA2_256"), false);
#ifdef USE_IPP
    IPPDigestBase idb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if (useipp == true)
        extDb = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    // TODO: Improve the incementor and start condition of forloop
    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rng.genRandomBytes(i);
                fr->setRecEvent(data, SHA2_256);
            } catch (const char* error) {
                printErrors(error);
                exit(-1);
            }
        } else {
            fr->nextLog();
            fr->getValues(&data);
        }

        error = db->digest_function(
            &(data[0]), data.size(), &(digestAlcp[0]), digestAlcp.size());
        error = extDb->digest_function(
            &(data[0]), data.size(), &(digestExt[0]), digestExt.size());
        db->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        extDb->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
        if (!bbxreplay) {
            fr->dumpBlackBox();
            fr->endRecEvent();
            fr->dumpLog();
        }
    }
    delete fr;
}

TEST(DIGEST_SHA2, CROSS_384)
{
    alc_error_t            error;
    std::vector<uint8_t>   data;
    std::vector<uint8_t>   digestAlcp(48, 0);
    std::vector<uint8_t>   digestExt(48, 0);
    const alc_sha2_mode_t  alc_mode       = ALC_SHA2_384;
    const alc_digest_len_t alc_digest_len = ALC_DIGEST_LEN_384;
    AlcpDigestBase         adb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string("SHA2_384"), true);
        fr->fastForward(SHA2_384);
    } else
        fr = new ExecRecPlay(std::string("SHA2_384"), false);
#ifdef USE_IPP
    IPPDigestBase idb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if (useipp == true)
        extDb = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    // TODO: Improve the incementor and start condition of forloop
    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rng.genRandomBytes(i);
                fr->setRecEvent(data, SHA2_384);
            } catch (const char* error) {
                printErrors(error);
                exit(-1);
            }
        } else {
            fr->nextLog();
            fr->getValues(&data);
        }

        error = db->digest_function(
            &(data[0]), data.size(), &(digestAlcp[0]), digestAlcp.size());
        error = extDb->digest_function(
            &(data[0]), data.size(), &(digestExt[0]), digestExt.size());
        db->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        extDb->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
        if (!bbxreplay) {
            fr->dumpBlackBox();
            fr->endRecEvent();
            fr->dumpLog();
        }
    }
    delete fr;
}

TEST(DIGEST_SHA2, CROSS_512)
{
    alc_error_t            error;
    std::vector<uint8_t>   data;
    std::vector<uint8_t>   digestAlcp(64, 0);
    std::vector<uint8_t>   digestExt(64, 0);
    const alc_sha2_mode_t  alc_mode       = ALC_SHA2_512;
    const alc_digest_len_t alc_digest_len = ALC_DIGEST_LEN_512;
    AlcpDigestBase         adb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(std::string("SHA2_512"), true);
        fr->fastForward(SHA2_512);
    } else
        fr = new ExecRecPlay(std::string("SHA2_512"), false);
#ifdef USE_IPP
    IPPDigestBase idb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if (useipp == true)
        extDb = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif

    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    // TODO: Improve the incementor and start condition of forloop
    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rng.genRandomBytes(i);
                fr->setRecEvent(data, SHA2_512);
            } catch (const char* error) {
                printErrors(error);
                exit(-1);
            }
        } else {
            fr->nextLog();
            fr->getValues(&data);
        }
        try {
            data = rng.genRandomBytes(i);
        } catch (const char* error) {
            printErrors(error);
            exit(-1);
        }
        error = db->digest_function(
            &(data[0]), data.size(), &(digestAlcp[0]), digestAlcp.size());
        error = extDb->digest_function(
            &(data[0]), data.size(), &(digestExt[0]), digestExt.size());
        db->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        extDb->init(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
        if (!bbxreplay) {
            fr->dumpBlackBox();
            fr->endRecEvent();
            fr->dumpLog();
        }
    }
    delete fr;
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