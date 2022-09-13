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

#include "gtest_common.hh"
#include <vector>
#include "digest/alc_base.hh"
#include "digest/base.hh"
#include "digest/gtest_base.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>

#ifdef USE_IPP
#include "digest/ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "digest/openssl_base.hh"
#endif

#define MAX_LOOP   160000
#define INC_LOOP   16
#define START_LOOP 16

enum _alc_sha2_mode
GetSHA2Mode(int HashSize)
{
    switch (HashSize) {
        case 224:
            return ALC_SHA2_224;
        case 256:
            return ALC_SHA2_256;
        case 384:
            return ALC_SHA2_384;
        case 512:
            return ALC_SHA2_512;
        default:
            return ALC_SHA2_224;
    }
}

enum _alc_digest_len
GetSHA2Len(int HashSize)
{
    switch (HashSize) {
        case 224:
            return ALC_DIGEST_LEN_224;
        case 256:
            return ALC_DIGEST_LEN_256;
        case 384:
            return ALC_DIGEST_LEN_384;
        case 512:
            return ALC_DIGEST_LEN_512;
        default:
            return ALC_DIGEST_LEN_128;
    }
}

record_t
GetSHA2Record(int HashSize)
{
    switch (HashSize)
    {
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

ExecRecPlay* fr;
void SHA2_CrossTest(int HashSize)
{
    alc_error_t            error;
    std::vector<uint8_t>   data;
    std::vector<uint8_t>   digestAlcp(HashSize/8, 0);
    std::vector<uint8_t>   digestExt(HashSize/8, 0);
    const alc_sha2_mode_t  alc_mode       = GetSHA2Mode(HashSize);
    const alc_digest_len_t alc_digest_len = GetSHA2Len(HashSize);
    AlcpDigestBase         adb(alc_mode, ALC_DIGEST_TYPE_SHA2, alc_digest_len);
    RngBase                rng;
    DigestBase*            db;
    DigestBase*            extDb = nullptr;
    db                           = &adb;
    if (bbxreplay) {
        fr = new ExecRecPlay("SHA2_" + std::to_string(HashSize), true);
        fr->fastForward(GetSHA2Record(HashSize));
    } else
        fr = new ExecRecPlay("SHA2_" + std::to_string(HashSize), false);
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

#endif