/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

/* C/C++ Headers */
#include <iostream>
#include <string.h>
#include <vector>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "gtest_common.hh"
#include "hmac/alc_hmac.hh"
#include "hmac/hmac.hh"
#include "rng_base.hh"
using namespace alcp::testing;
#ifdef USE_IPP
#include "hmac/ipp_hmac.hh"
#endif
#ifdef USE_OSSL
#include "hmac/openssl_hmac.hh"
#endif

/* FIXME: recheck these values */
#define MAX_LOOP      1600
#define INC_LOOP      1
#define START_LOOP    1
#define KEY_LEN_START 1
#define KEY_LEN_MAX   1600
#define KEY_LEN_INC   32

/* print params verbosely */
inline void
PrintHmacTestData(std::vector<Uint8> key, alcp_hmac_data_t data)
{
    std::cout << "KEY: " << parseBytesToHexStr(&key[0], key.size())
              << " KeyLen: " << key.size() << std::endl;
    std::cout << "MSG: " << parseBytesToHexStr(data.in.m_msg, data.in.m_msg_len)
              << " MsgLen: " << data.in.m_msg_len << std::endl;
    std::cout << "HMAC: "
              << parseBytesToHexStr(data.out.m_hmac, data.out.m_hmac_len)
              << " HmacLen(bytes): " << data.out.m_hmac_len << std::endl;
    return;
}

/* get Mac digest len from SHA type*/
std::map<alc_digest_mode_t, int> DigestTypeToLenMap = {
    { ALC_MD5, 128 },      { ALC_SHA1, 160 },         { ALC_SHA2_224, 224 },
    { ALC_SHA2_256, 256 }, { ALC_SHA2_384, 384 },     { ALC_SHA2_512, 512 },
    { ALC_SHA3_224, 224 }, { ALC_SHA3_256, 256 },     { ALC_SHA3_384, 384 },
    { ALC_SHA3_512, 512 }, { ALC_SHA2_512_224, 224 }, { ALC_SHA2_512_256, 256 }
};
/* get SHA2 type string to pass into the KAT test function */
std::string
DigestTypeToStr(alc_digest_mode_t DigestType)
{
    switch (DigestType) {
        case ALC_SHA2_224:
        case ALC_SHA2_256:
        case ALC_SHA2_384:
        case ALC_SHA2_512:
            return "SHA2";
            break;
        case ALC_SHA3_224:
        case ALC_SHA3_256:
        case ALC_SHA3_384:
        case ALC_SHA3_512:
            return "SHA3";
            break;
        default:
            return "";
            break;
    }
}

void
Hmac_KAT(alc_digest_mode_t HmacDigestMode)
{
    alcp_hmac_data_t data{};

    std::string        HmacType = DigestTypeToStr(HmacDigestMode);
    int                HmacSize = DigestTypeToLenMap[HmacDigestMode];
    std::vector<Uint8> hmac(HmacSize / 8, 0);

    /* Initialize info params based on test type */
    alc_mac_info_t info{ { HmacDigestMode } };

    AlcpHmacBase ahb;
    HmacBase*    hb;
    hb = &ahb;

    std::string TestDataFile = std::string("dataset_HMAC_" + HmacType + "_"
                                           + std::to_string(HmacSize) + ".csv");
    Csv         csv          = Csv(std::move(TestDataFile));

    /* check if file is valid */
    if (!csv.m_file_exists) {
        FAIL();
    }
#ifdef USE_OSSL
    OpenSSLHmacBase ohb;
    if (useossl == true)
        hb = &ohb;
#endif
#ifdef USE_IPP
    IPPHmacBase ihb;
    if (useipp == true)
        hb = &ihb;
#endif

    while (csv.readNext()) {
        auto msg = csv.getVect("CIPHERTEXT");
        auto key = csv.getVect("KEY");

        data.in.m_msg   = &(msg[0]);
        data.in.m_key   = &(key[0]);
        data.out.m_hmac = &(hmac[0]);

        data.in.m_msg_len   = csv.getVect("CIPHERTEXT").size();
        data.out.m_hmac_len = hmac.size();
        data.in.m_key_len   = key.size();

        if (!hb->Init(info, key)) {
            std::cout << "Error in hmac init function" << std::endl;
            FAIL();
        }
        if (!hb->MacUpdate(data)) {
            std::cout << "Error in Hmac mac_update" << std::endl;
            FAIL();
        }
        if (!hb->MacFinalize(data)) {
            std::cout << "Error in Hmac mac_finalize" << std::endl;
            FAIL();
        }
        if (!hb->MacReset()) {
            std::cout << "Error in Hmac mac_reset" << std::endl;
            FAIL();
        }

        /*conv m_digest into a vector */
        std::vector<Uint8> hmac_vector(std::begin(hmac), std::end(hmac));

        EXPECT_TRUE(ArraysMatch(
            hmac_vector,         // Actual output
            csv.getVect("HMAC"), // expected output, from the csv test data
            csv,
            std::string("HMAC_" + HmacType + "_" + std::to_string(HmacSize)
                        + "_KAT")));
    }
}

/* Hmac Cross tests */
void
Hmac_Cross(alc_digest_mode_t HmacDigestMode)
{
    std::vector<Uint8> data;
    int                HmacSize = DigestTypeToLenMap[HmacDigestMode];

    std::vector<Uint8> HmacAlcp(HmacSize / 8, 0);
    std::vector<Uint8> HmacExt(HmacSize / 8, 0);

    /* Initialize info params based on test type */
    alc_mac_info_t info{ { HmacDigestMode } };

    AlcpHmacBase ahb;
    RngBase      rb;
    HmacBase*    hb;
    HmacBase*    extHb = nullptr;
    hb                 = &ahb;

#ifdef USE_OSSL
    OpenSSLHmacBase ohb;
    if ((useossl == true) || (extHb == nullptr))
        extHb = &ohb;
#endif
#ifdef USE_IPP
    IPPHmacBase ihb;
    if (useipp == true)
        extHb = &ihb;
#endif

/* do cross tests between ipp and openssl */
#if defined(USE_IPP) && defined(USE_OSSL)
    if (oa_override) {
        extHb = &ohb;
        hb    = &ihb;
        std::cout << "Setting IPP as main Lib and OpenSSL as ext lib"
                  << std::endl;
    }
#endif
    if (extHb == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }

    /* generate message key data, use it chunk by chunk in the loop */
    std::vector<Uint8> msg_full = rb.genRandomBytes(MAX_LOOP);
    std::vector<Uint8> key_full = rb.genRandomBytes(KEY_LEN_MAX);

    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    for (int j = KEY_LEN_START; j < KEY_LEN_MAX; j += KEY_LEN_INC) {
        for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
            alcp_hmac_data_t data_alc{}, data_ext{};

            /* generate msg data from msg_full */
            msg_full = ShuffleVector(msg_full, rng);
            pos1     = msg_full.end() - i - 1;
            pos2     = msg_full.end();
            std::vector<Uint8> msg(pos1, pos2);

            /* generate random key value*/
            key_full = ShuffleVector(key_full, rng);
            pos1     = key_full.end() - j - 1;
            pos2     = key_full.end();
            std::vector<Uint8> key(pos1, pos2);

            /* misalign if buffers are aligned */
            if (is_aligned(&(msg[0]))) {
                data_alc.in.m_msg = &(msg[1]);
                data_ext.in.m_msg = &(msg[1]);
            } else {
                data_alc.in.m_msg = &(msg[0]);
                data_ext.in.m_msg = &(msg[0]);
            }
            /* misalign if buffers are aligned */
            if (is_aligned(&(key[0]))) {
                data_alc.in.m_key = &(key[1]);
                data_ext.in.m_key = &(key[1]);
            } else {
                data_alc.in.m_key = &(key[0]);
                data_ext.in.m_key = &(key[0]);
            }

            data_alc.in.m_msg_len = data_ext.in.m_msg_len = msg.size() - 1;
            data_alc.in.m_key_len = data_ext.in.m_key_len = key.size() - 1;

            /* load test data */
            data_alc.out.m_hmac     = &(HmacAlcp[0]);
            data_alc.out.m_hmac_len = HmacAlcp.size();

            /* load ext test data */
            data_ext.out.m_hmac     = &(HmacExt[0]);
            data_ext.out.m_hmac_len = HmacExt.size();
            data_ext.in             = data_alc.in;

            /* run test with main lib */
            if (verbose > 1)
                PrintHmacTestData(key, data_alc);
            if (!hb->Init(info, key)) {
                printf("Error in hmac init\n");
                FAIL();
            }
            if (!hb->MacUpdate(data_alc)) {
                std::cout << "Error in hmac mac_update" << std::endl;
                FAIL();
            }
            if (!hb->MacFinalize(data_alc)) {
                std::cout << "Error in hmac mac_finalize" << std::endl;
                FAIL();
            }
            /* run test with ext lib */
            if (verbose > 1)
                PrintHmacTestData(key, data_ext);
            if (!extHb->Init(info, key)) {
                printf("Error in hmac ext init function\n");
                FAIL();
            }
            if (!extHb->MacUpdate(data_ext)) {
                std::cout << "Error in hmac (ext lib) mac_update" << std::endl;
                FAIL();
            }
            if (!extHb->MacFinalize(data_ext)) {
                std::cout << "Error in hmac (ext lib) mac_finalize"
                          << std::endl;
                FAIL();
            }
            EXPECT_TRUE(ArraysMatch(HmacAlcp, HmacExt, i));
        }
    }
}
