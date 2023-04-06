/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

/* C/C++ Headers */
#include <iostream>
#include <string.h>
#include <vector>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "digest/gtest_base.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#ifdef USE_IPP
#include "digest/ipp_digest.hh"
#endif
#ifdef USE_OSSL
#include "digest/openssl_digest.hh"
#endif

#define MAX_LOOP   16000
#define INC_LOOP   1
#define START_LOOP 1

/* print test data */
inline void
PrintDigestTestData(alcp_digest_data_t data, std::string mode)
{
    std::cout << "MSG: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " MsgLen: " << data.m_msg_len << std::endl;
    std::cout << "Digest: "
              << parseBytesToHexStr(data.m_digest, data.m_digest_len)
              << " DigestLen(bytes): " << data.m_digest_len << std::endl;
    return;
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

void
Digest_KAT(alc_digest_info_t info)
{
    alcp_digest_data_t data;
    std::vector<Uint8> digest(info.dt_len / 8, 0);
    AlcpDigestBase     adb(info);
    DigestBase*        db;
    db = &adb;

    std::string TestDataFile       = "";
    std::string SHA3_SHAKE_Len_Str = "";
    /* for truncated sha512 (224,256)*/
    if (info.dt_type == ALC_DIGEST_TYPE_SHA2
        && info.dt_mode.dm_sha2 == ALC_SHA2_512
        && info.dt_len != ALC_DIGEST_LEN_512) {
        TestDataFile = "dataset_" + GetDigestStr(info.dt_type) + "_512_"
                       + std::to_string(info.dt_len) + ".csv";
    }
    /* for SHA3 shake tests (128,256)*/
    else if (info.dt_len == ALC_DIGEST_LEN_CUSTOM) {
        if (info.dt_mode.dm_sha3 == ALC_SHAKE_128) {
            SHA3_SHAKE_Len_Str = "128";
        } else if (info.dt_mode.dm_sha3 == ALC_SHAKE_256) {
            SHA3_SHAKE_Len_Str = "256";
        }
        TestDataFile = "dataset_" + GetDigestStr(info.dt_type) + "_SHAKE_"
                       + SHA3_SHAKE_Len_Str + ".csv";
    }
    /* for normal SHA2, SHA3 (224,256,384,512 bit) */
    else {
        TestDataFile = "dataset_" + GetDigestStr(info.dt_type) + "_"
                       + std::to_string(info.dt_len) + ".csv";
    }

    Csv csv(TestDataFile);

    if (useipp && (GetDigestStr(info.dt_type).compare("SHA3") == 0)) {
        std::cout << "IPPCP doesnt support SHA3 for now, skipping this test"
                  << std::endl;
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
        while (csv.readNext()) {
            auto msg          = csv.getVect("MESSAGE");
            data.m_msg        = &(msg[0]);
            data.m_msg_len    = csv.getVect("MESSAGE").size();
            data.m_digest_len = csv.getVect("DIGEST").size();
            std::vector<Uint8> digest_(data.m_digest_len, 0);
            data.m_digest = &(digest_[0]);

            if (!db->init(info, data.m_digest_len)) {
                std::cout << "Error: Digest base init failed" << std::endl;
                FAIL();
            }
            if (!db->digest_function(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }
            EXPECT_TRUE(ArraysMatch(
                digest_,               // output
                csv.getVect("DIGEST"), // expected, from the KAT test data
                csv,
                std::string(GetDigestStr(info.dt_type) + "_"
                            + SHA3_SHAKE_Len_Str + "_KAT")));
        }
    } else {
        while (csv.readNext()) {
            auto msg          = csv.getVect("MESSAGE");
            data.m_msg        = &(msg[0]);
            data.m_msg_len    = csv.getVect("MESSAGE").size();
            data.m_digest_len = csv.getVect("DIGEST").size();
            data.m_digest     = &(digest[0]);

            if (!db->init(info, data.m_digest_len)) {
                std::cout << "Error: Digest base init failed" << std::endl;
                FAIL();
            }
            if (!db->digest_function(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }

            /*conv m_digest into a vector */
            std::vector<Uint8> digest_vector(std::begin(digest),
                                             std::end(digest));

            EXPECT_TRUE(ArraysMatch(
                digest_vector,         // output
                csv.getVect("DIGEST"), // expected, from the KAT test data
                csv,
                std::string(GetDigestStr(info.dt_type) + "_"
                            + std::to_string(info.dt_len) + "_KAT")));
        }
    }
}

/* Digest Cross tests */
void
Digest_Cross(int HashSize, alc_digest_info_t info)
{
    std::vector<Uint8> digestAlcp(HashSize / 8, 0);
    std::vector<Uint8> digestExt(HashSize / 8, 0);
    AlcpDigestBase     adb(info);
    RngBase            rb;
    DigestBase*        db;
    DigestBase*        extDb = nullptr;
    db                       = &adb;

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
        /* do cross tests between ipp and openssl */
#if defined(USE_IPP) && defined(USE_OSSL)
    if (oa_override) {
        extDb = &odb;
        db    = &idb;
        std::cout << "Setting IPP as main Lib and OpenSSL as ext lib"
                  << std::endl;
    }
#endif

    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    /* generate test data vector, and use it chunk by chunk in the loop */
    std::vector<Uint8>                 msg_full = rb.genRandomBytes(MAX_LOOP);
    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        alcp_digest_data_t data_alc, data_ext;

        msg_full = ShuffleVector(msg_full, rng);
        pos1     = msg_full.end() - i;
        pos2     = msg_full.end();
        std::vector<Uint8> msg(pos1, pos2);

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
            std::cout << "Error: Digest base init failed" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintDigestTestData(data_alc, GetDigestStr(info.dt_type));
        if (!db->digest_function(data_alc)) {
            std::cout << "Error: Digest function failed" << std::endl;
            FAIL();
        }

        if (!extDb->init(info, digestExt.size())) {
            std::cout << "Error: Ext Digest base init failed" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintDigestTestData(data_ext, GetDigestStr(info.dt_type));
        if (!extDb->digest_function(data_ext)) {
            std::cout << "Error: Ext Digest function failed" << std::endl;
            FAIL();
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
    }
}

#endif