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
#include "hmac/alc_base.hh"
#include "hmac/base.hh"
//#include "hmac/gtest_base.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
// #ifdef USE_IPP
// #include "digest/ipp_base.hh"
// #endif
#ifdef USE_OSSL
#include "hmac/openssl_base.hh"
#endif

#define MAX_LOOP   160000
#define INC_LOOP   16
#define START_LOOP 16

void
Hmac_KAT(int HashSize, std::string HmacType, alc_mac_info_t info)
{
    alc_error_t        error;
    alcp_hmac_data_t   data;
    std::vector<Uint8> hmac(HashSize / 8, 0);

    /* Initialize info params based on test type */
    info.mi_type = ALC_MAC_HMAC;
    info.mi_algoinfo.hmac.hmac_digest.dt_len =
        static_cast<enum _alc_digest_len>(HashSize);

    AlcpHmacBase ahb(info);
    HmacBase*    hb;
    hb = &ahb;

    std::string TestDataFile = std::string("dataset_HMAC_" + HmacType + "_"
                                           + std::to_string(HashSize) + ".csv");
    DataSet     ds           = DataSet(TestDataFile);

#ifdef USE_OSSL
    useossl = true;
    OpenSSLHmacBase ohb(info);
    if (useossl == true)
        hb = &ohb;
#endif
    // #ifdef USE_IPP
    //     IPPDigestBase idb(info);
    //     if (useipp == true)
    //         db = &idb;
    // #endif

    while (ds.readMsgKeyHmac()) {
        auto msg = ds.getMessage();
        auto key = ds.getKey();

        data.m_msg  = &(msg[0]);
        data.m_key  = &(key[0]);
        data.m_hmac = &(hmac[0]);

        data.m_msg_len  = ds.getMessage().size();
        data.m_hmac_len = hmac.size();
        data.m_key_len  = key.size();

        hb->init(info, key);
        error = hb->Hmac_function(data);

        if (alcp_is_error(error)) {
            printf("Error");
            return;
        }

        /*conv m_digest into a vector */
        std::vector<uint8_t> hmac_vector(std::begin(hmac), std::end(hmac));

        EXPECT_TRUE(
            ArraysMatch(hmac_vector,  // Actual output
                        ds.getHmac(), // expected output, from the csv test data
                        ds,
                        std::string("HMAC_" + HmacType + "_"
                                    + std::to_string(HashSize) + "_KAT")));
    }
}

/* Digest Cross tests */
// void
// Digest_Cross(int HashSize, alc_digest_info_t info)
// {
//     alc_error_t        error;
//     std::vector<Uint8> data;
//     alcp_digest_data_t test_data, test_data_ext;
//     std::vector<Uint8> digestAlcp(HashSize / 8, 0);
//     std::vector<Uint8> digestExt(HashSize / 8, 0);
//     AlcpDigestBase     adb(info);
//     RngBase            rng;
//     DigestBase*        db;
//     DigestBase*        extDb = nullptr;
//     db                       = &adb;
//     if (bbxreplay) {
//         fr = new ExecRecPlay(
//             GetDigestStr(info.dt_type) + "_" +
//             std::to_string(HashSize), true);
//         /* FIXME: we need a generic getsharecord */
//         fr->fastForward(GetSHA3Record(HashSize));
//     } else
//         fr = new ExecRecPlay(
//             GetDigestStr(info.dt_type) + "_" +
//             std::to_string(HashSize), false);

// #ifdef USE_OSSL
//     OpenSSLDigestBase odb(info);
//     if ((useossl == true) || (extDb == nullptr)) // Select
//     OpenSSL by default
//         extDb = &odb;
// #endif
// #ifdef USE_IPP
//     IPPDigestBase idb(info);
//     if (useipp == true)
//         extDb = &idb;
// #endif
//     if (extDb == nullptr) {
//         printErrors("No external lib selected!");
//         exit(-1);
//     }

//     for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
//         if (!bbxreplay) {
//             fr->startRecEvent();
//             try {
//                 data = rng.genRandomBytes(i);
//                 /* FIXME: we need a generic getsharecord */
//                 fr->setRecEvent(data, GetSHA2Record(HashSize));
//             } catch (const char* error) {
//                 printErrors(error);
//                 exit(-1);
//             }
//         } else {
//             fr->nextLog();
//             fr->getValues(&data);
//         }

//         db->init(info, digestAlcp.size());

//         test_data.m_msg        = &(data[0]);
//         test_data.m_digest     = &(digestAlcp[0]);
//         test_data.m_digest_len = digestAlcp.size();
//         test_data.m_msg_len    = data.size();

//         error = db->digest_function(test_data);

//         extDb->init(info, digestExt.size());

//         test_data_ext.m_msg        = &(data[0]);
//         test_data_ext.m_digest     = &(digestExt[0]);
//         test_data_ext.m_digest_len = digestExt.size();
//         test_data_ext.m_msg_len    = data.size();

//         error = extDb->digest_function(test_data_ext);

//         if (alcp_is_error(error)) {
//             printf("Error");
//             return;
//         }
//         EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
//         // if (!bbxreplay) {
//         //     fr->dumpBlackBox();
//         //     fr->endRecEvent();
//         //     fr->dumpLog();
//         // }
//     }
//     delete fr;
// }

#endif