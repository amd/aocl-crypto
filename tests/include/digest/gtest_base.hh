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

#define MAX_LOOP   160000
#define INC_LOOP   16
#define START_LOOP 16

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
GetDigestStr(_alc_digest_type digest_type) {
    std::string sDigestType;
    switch (digest_type)
    {
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
SHA_KATTest(int HashSize, _alc_digest_type digest_type, _alc_digest_len digest_len)
{
    alc_error_t error;
    std::vector<Uint8> digest(HashSize / 8, 0);
    AlcpDigestBase adb(digest_type, digest_len);
    DigestBase* db;
    db = &adb;

    /* to find csv file name as per digest type */
    std::string TestDataFile = "dataset_" + GetDigestStr(digest_type) + "_" + std::to_string(HashSize) + ".csv";
    DataSet ds = DataSet(TestDataFile);

#ifdef USE_IPP
    IPPDigestBase idb(digest_type, digest_len);
    if (useipp == true)
        db = &idb;
#endif
#ifdef USE_OSSL
    OpenSSLDigestBase odb(digest_type, digest_len);
    if (useossl == true)
        db = &odb;
#endif
    while (ds.readMsgDigest()) {
        error = db->digest_function(&(ds.getMessage()[0]),
                                    ds.getMessage().size(),
                                    &(digest[0]),
                                    digest.size());
        db->init(digest_type, digest_len);
        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }
        EXPECT_TRUE(ArraysMatch(
            digest,         // output
            ds.getDigest(), // expected, from the KAT test data
            ds,
            std::string(GetDigestStr(digest_type) + "_" + std::to_string(HashSize) + "_KAT")));
    }
}

/* SHA3 Cross tests */
void
SHA_CrossTest(int HashSize, _alc_digest_type digest_type, _alc_digest_len digest_len)
{
    alc_error_t            error;
    std::vector<Uint8>     data;
    std::vector<Uint8>     digestAlcp(HashSize / 8, 0);
    std::vector<Uint8>     digestExt(HashSize / 8, 0);
    AlcpDigestBase         adb(digest_type, digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay(GetDigestStr(digest_type) + "_" + std::to_string(HashSize), true);
        /* FIXME: we need a generic getsharecord */
        fr->fastForward(GetSHA3Record(HashSize));
    } else
        fr = new ExecRecPlay(GetDigestStr(digest_type) + "_" + std::to_string(HashSize), false);

    if (useipp && (GetDigestStr(digest_type).compare("SHA3") == 0)) {
        printf ("IPPCP doesnt support SHA3 for now, skipping this test\n");
        return;
    }

#ifdef USE_OSSL
    OpenSSLDigestBase odb(digest_type, digest_len);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        if (!bbxreplay) {
            fr->startRecEvent();
            try {
                data = rng.genRandomBytes(i);
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

        error = db->digest_function(
            &(data[0]), data.size(), &(digestAlcp[0]), digestAlcp.size());
        error = extDb->digest_function(
            &(data[0]), data.size(), &(digestExt[0]), digestExt.size());
        db->init(digest_type, digest_len);
        extDb->init(digest_type, digest_len);
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

#endif