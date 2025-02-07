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
#include <iterator>
#include <string.h>
#include <vector>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "cmac/alc_cmac.hh"
#include "cmac/cmac.hh"
#include "csv.hh"
#include "gtest_common.hh"
#include "rng_base.hh"

using namespace alcp::testing;
#ifdef USE_IPP
#include "cmac/ipp_cmac.hh"
#endif
#ifdef USE_OSSL
#include "cmac/openssl_cmac.hh"
#endif

#define MAX_LOOP    1600
#define KEY_LEN_MAX 1600
#define INC_LOOP    1
#define START_LOOP  1

/* print params verbosely */
inline void
PrintCmacTestData(std::vector<Uint8> key, alcp_cmac_data_t data)
{
    std::cout << "KEY: " << parseBytesToHexStr(&key[0], key.size())
              << " KeyLen: " << key.size() << std::endl;
    std::cout << "MSG: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " MsgLen: " << data.m_msg_len << std::endl;
    std::cout << "CMAC: " << parseBytesToHexStr(data.m_cmac, data.m_cmac_len)
              << " CmacLen(bytes): " << data.m_cmac_len << std::endl;
    return;
}

void
Cmac_KAT(int KeySize, std::string CmacType, alc_mac_info_t info)
{
    alcp_cmac_data_t data     = {};
    const int        CmacSize = 16;

    AlcpCmacBase acb;
    CmacBase*    cb;
    cb = &acb;

    std::string TestDataFile = std::string("dataset_CMAC_" + CmacType + "_"
                                           + std::to_string(KeySize) + ".csv");
    Csv         csv          = Csv(std::move(TestDataFile));

    /* check if file is valid */
    if (!csv.m_file_exists) {
        FAIL();
    }

#ifdef USE_OSSL
    OpenSSLCmacBase ocb;
    if (useossl == true)
        cb = &ocb;
#endif
#ifdef USE_IPP
    IPPCmacBase icb;
    if (useipp == true)
        cb = &icb;
#endif

    while (csv.readNext()) {

        std::vector<Uint8> cmac(CmacSize, 0);

        auto msg = csv.getVect("MESSAGE");
        auto key = csv.getVect("KEY");

        data.m_key  = getPtr(key);
        data.m_cmac = getPtr(cmac);
        data.m_msg  = getPtr(msg);

        data.m_msg_len  = msg.size();
        data.m_cmac_len = cmac.size();
        data.m_key_len  = key.size();

        if (!cb->Init(info, key)) {
            std::cout << "Error in cmac init function" << std::endl;
            FAIL();
        }

        if (!cb->MacUpdate(data)) {
            std::cout << "Error in cmac mac_update" << std::endl;
            FAIL();
        }

        if (!cb->MacFinalize(data)) {
            std::cout << "Error in cmac mac_finalize" << std::endl;
            FAIL();
        }

        if (!cb->MacReset()) {
            std::cout << "Error in cmac reset function" << std::endl;
            FAIL();
        }

        /*conv cmac output into a vector */
        /* we need only the no of bytes needed, from the output */
        std::vector<Uint8> cmac_vector(
            std::begin(cmac), std::begin(cmac) + csv.getVect("CMAC").size());

        EXPECT_TRUE(ArraysMatch(
            cmac_vector,         // Actual output
            csv.getVect("CMAC"), // expected output, from the csv test data
            csv,
            std::string("CMAC_" + CmacType + "_" + std::to_string(KeySize)
                        + "_KAT")));
    }
}

/* Cmac Cross tests */
void
Cmac_Cross(int KeySize, std::string CmacType, alc_mac_info_t info)
{
    std::vector<Uint8> data = {};

    int                CmacSize = 128;
    std::vector<Uint8> CmacAlcp(CmacSize / 8, 0);
    std::vector<Uint8> CmacExt(CmacSize / 8, 0);

    AlcpCmacBase acb;
    RngBase      rb;
    CmacBase*    cb;
    CmacBase*    extCb = nullptr;
    cb                 = &acb;

#ifdef USE_OSSL
    OpenSSLCmacBase ocb;
    if ((useossl == true) || (extCb == nullptr))
        extCb = &ocb;
#endif
#ifdef USE_IPP
    IPPCmacBase icb;
    if (useipp == true)
        extCb = &icb;
#endif

    /* do cross tests between ipp and openssl */
#if defined(USE_IPP) && defined(USE_OSSL)
    if (oa_override) {
        extCb = &ocb;
        cb    = &icb;
        std::cout << "Setting IPP as main Lib and OpenSSL as ext lib"
                  << std::endl;
    }
#endif

    if (extCb == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }

    /* generate random msg,key value */
    std::vector<Uint8>                 msg_full = rb.genRandomBytes(MAX_LOOP);
    std::vector<Uint8>                 key_full = rb.genRandomBytes(KeySize);
    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        alcp_cmac_data_t data_alc, data_ext;

        /* generate msg data from msg_full */
        msg_full = ShuffleVector(msg_full, rng);
        pos1     = msg_full.end() - i - 1;
        pos2     = msg_full.end();
        std::vector<Uint8> msg(pos1, pos2);

        /* generate random key value*/
        key_full = ShuffleVector(key_full, rng);
        pos1     = key_full.begin();
        pos2     = key_full.begin() + (KeySize / 8);
        std::vector<Uint8> key(pos1, pos2);

        /* misalign if buffers are aligned */
        if (is_aligned(&(msg[0]))) {
            data_alc.m_msg = &(msg[1]);
            data_ext.m_msg = &(msg[1]);
        } else {
            data_alc.m_msg = &(msg[0]);
            data_ext.m_msg = &(msg[0]);
        }
        if (is_aligned(&(key[0]))) {
            data_alc.m_key = &(key[1]);
            data_ext.m_key = &(key[1]);
        } else {
            data_alc.m_key = &(key[0]);
            data_ext.m_key = &(key[0]);
        }
        data_alc.m_msg_len = data_ext.m_msg_len = msg.size() - 1;
        data_alc.m_key_len = data_ext.m_key_len = key.size();

        /* load test data */
        data_alc.m_cmac     = &(CmacAlcp[0]);
        data_alc.m_cmac_len = CmacAlcp.size();
        data_alc.m_key      = &(key[0]);

        /* load ext test data */
        data_ext.m_cmac     = &(CmacExt[0]);
        data_ext.m_cmac_len = CmacExt.size();
        data_ext.m_key      = &(key[0]);

        /* run test with main lib */
        if (verbose > 1)
            PrintCmacTestData(key, data_alc);
        if (!cb->Init(info, key)) {
            std::cout << "Error in cmac init function" << std::endl;
            FAIL();
        }
        if (!cb->MacUpdate(data_alc)) {
            std::cout << "Error in cmac mac_update" << std::endl;
            FAIL();
        }
        if (!cb->MacFinalize(data_alc)) {
            std::cout << "Error in cmac mac_finalize" << std::endl;
            FAIL();
        }
        if (!cb->MacReset()) {
            std::cout << "Error in cmac reset function" << std::endl;
            FAIL();
        }

        /* run test with ext lib */
        if (verbose > 1)
            PrintCmacTestData(key, data_ext);
        if (!extCb->Init(info, key)) {
            printf("Error in cmac ext init function\n");
            FAIL();
        }
        if (!extCb->MacUpdate(data_ext)) {
            std::cout << "Error in cmac mac_update" << std::endl;
            FAIL();
        }
        if (!extCb->MacFinalize(data_ext)) {
            std::cout << "Error in cmac mac_finalize" << std::endl;
            FAIL();
        }
        if (!extCb->MacReset()) {
            std::cout << "Error in cmac mac_reset" << std::endl;
            FAIL();
        }
        EXPECT_TRUE(ArraysMatch(CmacAlcp, CmacExt, i));
    }
    UNREF(CmacType);
}
