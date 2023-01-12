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
#ifndef __GTEST_BASE_HH
#define __GTEST_BASE_HH 2

#include "digest/alc_base.hh"
#include "digest/base.hh"
#include "digest/gtest_base.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>
#include <vector>

#ifdef USE_IPP
#include "digest/ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "digest/openssl_base.hh"
#endif

/*FIXME: increase MAX LOOP*/
#define MAX_LOOP   16000
#define INC_LOOP   1
#define START_LOOP 1

record_t
GetSHA2Record(int HashSize)
{
    switch (HashSize) {
        case 224:
            return SHA2_224;
        case 256:
            return SHA2_256;
        case 384:
            return SHA2_384;
        case 512:
            return SHA2_512;
        default:
            return SHA2_224;
    }
}

/* FIXME: duplicate? */
record_t
GetSHA3Record(int HashSize)
{
    switch (HashSize) {
        case 224:
            return SHA3_224;
        case 256:
            return SHA3_256;
        case 384:
            return SHA3_384;
        case 512:
            return SHA3_512;
        default:
            return SHA3_224;
    }
}

/* to read csv file */
std::string
GetDigestStr(_alc_digest_type digest_type)
{
    std::string sDigestType;
    switch (digest_type) {
        case ALC_DIGEST_TYPE_SHA2:
            return "SHA";
        case ALC_DIGEST_TYPE_SHA3:
            return "SHA3";
        default:
            return "";
    }
}

ExecRecPlay* fr;
void
Digest_KAT(int HashSize, alc_digest_info_t info)
{
    alc_error_t        error;
    alcp_digest_data_t data;
    std::vector<Uint8> digest(HashSize / 8, 0);
    AlcpDigestBase     adb(info);
    DigestBase*        db;
    db = &adb;

    std::string TestDataFile = "";
    if (info.dt_len == ALC_DIGEST_LEN_CUSTOM)
        TestDataFile = "dataset_" + GetDigestStr(info.dt_type) + "_SHAKE_"
                       + std::to_string(HashSize) + ".csv";
    else
        TestDataFile = "dataset_" + GetDigestStr(info.dt_type) + "_"
                       + std::to_string(HashSize) + ".csv";

    DataSet ds = DataSet(TestDataFile);

    if (useipp && (GetDigestStr(info.dt_type).compare("SHA3") == 0)) {
        printf("IPPCP doesnt support SHA3 for now, skipping this test\n");
        return;
    }

#ifdef USE_OSSL
    OpenSSLDigestBase odb(info);
    if (useossl == true)
        db = &odb;
#endif
#ifdef USE_IPP
    IPPDigestBase idb(info);
    if (useipp == true)
        db = &idb;
#endif

    /* for SHAKE variant */
    if (info.dt_len == ALC_DIGEST_LEN_CUSTOM) {
        while (ds.readMsgDigestLen()) {
            auto msg          = ds.getMessage();
            data.m_msg        = &(msg[0]);
            data.m_msg_len    = ds.getMessage().size();
            data.m_digest_len = ds.getDigestLen();
            std::vector<Uint8> digest_(data.m_digest_len, 0);
            data.m_digest = &(digest_[0]);

            if (!db->init(info, data.m_digest_len)) {
                printf("Error: Digest base init failed\n");
                return;
            }
            error = db->digest_function(data);
            if (alcp_is_error(error)) {
                printf("Error: Digest function failed\n");
                return;
            }
            EXPECT_TRUE(
                ArraysMatch(digest_,        // output
                            ds.getDigest(), // expected, from the KAT test data
                            ds,
                            std::string(GetDigestStr(info.dt_type) + "_"
                                        + std::to_string(HashSize) + "_KAT")));
        }
    } else {
        while (ds.readMsgDigest()) {
            auto msg          = ds.getMessage();
            data.m_msg        = &(msg[0]);
            data.m_msg_len    = ds.getMessage().size();
            data.m_digest_len = digest.size();
            data.m_digest     = &(digest[0]);

            if (!db->init(info, data.m_digest_len)) {
                printf("Error: Digest base init failed\n");
                return;
            }
            error = db->digest_function(data);
            if (alcp_is_error(error)) {
                printf("Error: Digest function failed\n");
                return;
            }

            /*conv m_digest into a vector */
            std::vector<uint8_t> digest_vector(std::begin(digest),
                                               std::end(digest));

            EXPECT_TRUE(
                ArraysMatch(digest_vector,  // output
                            ds.getDigest(), // expected, from the KAT test data
                            ds,
                            std::string(GetDigestStr(info.dt_type) + "_"
                                        + std::to_string(HashSize) + "_KAT")));
        }
    }
}

/* Digest Cross tests */
void
Digest_Cross(int HashSize, alc_digest_info_t info)
{
    alc_error_t        error;
    std::vector<Uint8> data;
    std::vector<Uint8> digestAlcp(HashSize / 8, 0);
    std::vector<Uint8> digestExt(HashSize / 8, 0);
    AlcpDigestBase     adb(info);
    RngBase            rb;
    DigestBase*        db;
    DigestBase*        extDb = nullptr;
    db                       = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(
            GetDigestStr(info.dt_type) + "_" + std::to_string(HashSize), true);
        /* FIXME: we need a generic getsharecord */
        fr->fastForward(GetSHA3Record(HashSize));
    } else
        fr = new ExecRecPlay(
            GetDigestStr(info.dt_type) + "_" + std::to_string(HashSize), false);

#ifdef USE_OSSL
    OpenSSLDigestBase odb(info);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
#ifdef USE_IPP
    IPPDigestBase idb(info);
    if (useipp == true)
        extDb = &idb;
#endif
    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rb.genRandomBytes(i);
                /* FIXME: we need a generic getsharecord */
                fr->setRecEvent(data, GetSHA2Record(HashSize));
            } catch (const char* error) {
                printErrors(error);
                exit(-1);
            }
        } else {
            fr->nextLog();
            fr->getValues(&data);
        }

        alcp_digest_data_t data_alc, data_ext;

        /* generate test data vectors */
        std::vector<Uint8> msg(i, 0);
        msg = rb.genRandomBytes(i);

        /* load test data */
        data_alc.m_msg        = &(msg[0]);
        data_alc.m_msg_len    = msg.size();
        data_alc.m_digest     = &(digestAlcp[0]);
        data_alc.m_digest_len = digestAlcp.size();

        data_ext.m_msg        = &(msg[0]);
        data_ext.m_msg_len    = msg.size();
        data_ext.m_digest     = &(digestExt[0]);
        data_ext.m_digest_len = digestExt.size();

        if (!db->init(info, digestAlcp.size())) {
            printf("Error: Digest base init failed\n");
            return;
        }
        error = db->digest_function(data_alc);
        if (alcp_is_error(error)) {
            printf("Error: Digest function failed\n");
            return;
        }

        if (!extDb->init(info, digestExt.size())) {
            printf("Error: Ext Digest base init failed\n");
            return;
        }
        error = extDb->digest_function(data_ext);
        if (alcp_is_error(error)) {
            printf("Error: Ext Digest function failed\n");
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

#endif