/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "cmac/alc_cmac_base.hh"
#include "cmac/cmac_base.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
#ifdef USE_IPP
#include "cmac/ipp_cmac_base.hh"
#endif
#ifdef USE_OSSL
#include "cmac/openssl_cmac_base.hh"
#endif

#define MAX_LOOP      1600
#define INC_LOOP      1
#define START_LOOP    1
#define KEY_LEN_START 1
#define KEY_LEN_MAX   1600
#define KEY_LEN_INC   32

/* print params verbosely */
inline void
PrintCmacTestData(std::vector<Uint8> key,
                  alcp_cmac_data_t   data,
                  std::string        mode)
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
    alc_error_t      error;
    alcp_cmac_data_t data;

    info.mi_type                                         = ALC_MAC_CMAC;
    info.mi_algoinfo.cmac.cmac_cipher.ci_algo_info.ai_iv = NULL;

    AlcpCmacBase acb(info);
    CmacBase*    cb;
    cb = &acb;

    std::string TestDataFile = std::string("dataset_CMAC_" + CmacType + "_"
                                           + std::to_string(KeySize) + ".csv");
    DataSet     ds           = DataSet(TestDataFile);

#ifdef USE_OSSL
    OpenSSLCmacBase ocb(info);
    if (useossl == true)
        cb = &ocb;
#endif
#ifdef USE_IPP
    IPPCmacBase icb(info);
    if (useipp == true)
        cb = &icb;
#endif

    while (ds.readMsgKeyCmac()) {
        std::vector<Uint8> cmac(ds.getCmac().size(), 0);

        auto msg = ds.getMessage();
        auto key = ds.getKey();

        data.m_msg  = &(msg[0]);
        data.m_key  = &(key[0]);
        data.m_cmac = &(cmac[0]);

        data.m_msg_len  = ds.getMessage().size();
        data.m_cmac_len = cmac.size();
        data.m_key_len  = key.size();

        if (!cb->init(info, key)) {
            std::cout << "Error in cmac init function" << std::endl;
            FAIL();
        }

        if (!cb->Cmac_function(data)) {
            std::cout << "Error in cmac function" << std::endl;
            FAIL();
        }

        if (!cb->reset()) {
            std::cout << "Error in cmac reset function" << std::endl;
            FAIL();
        }

        /*conv m_digest into a vector */
        std::vector<uint8_t> cmac_vector(std::begin(cmac), std::end(cmac));

        EXPECT_TRUE(
            ArraysMatch(cmac_vector,  // Actual output
                        ds.getCmac(), // expected output, from the csv test data
                        ds,
                        std::string("CMAC_" + CmacType + "_"
                                    + std::to_string(KeySize) + "_KAT")));
    }
}

/* Cmac Cross tests */
void
Cmac_Cross(int CmacSize, std::string CmacType, alc_mac_info_t info)
{
    alc_error_t        error;
    std::vector<Uint8> data;
    int                KeySize;
    std::vector<Uint8> CmacAlcp(CmacSize / 8, 0);
    std::vector<Uint8> CmacExt(CmacSize / 8, 0);

    /* Initialize info params based on test type */
    info.mi_type                              = ALC_MAC_CMAC;
    info.mi_algoinfo.cmac.cmac_cipher.ci_type = ALC_CIPHER_TYPE_AES;

    AlcpCmacBase acb(info);
    RngBase      rb;
    CmacBase*    cb;
    CmacBase*    extCb = nullptr;
    cb                 = &acb;

#ifdef USE_OSSL
    OpenSSLCmacBase ocb(info);
    if ((useossl == true) || (extCb == nullptr))
        extCb = &ocb;
#endif
#ifdef USE_IPP
    IPPCmacBase icb(info);
    if (useipp == true)
        extCb = &icb;
#endif
    if (extCb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    /* FIXME: generate a vector using getRandomBytes() once, split it and feed
     * it into the loop. Avoid calling genRandomBytes() each time in the loop */
    for (int j = KEY_LEN_START; j < KEY_LEN_MAX; j += KEY_LEN_INC) {
        for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
            alcp_cmac_data_t data_alc, data_ext;

            /* generate test data vectors */
            std::vector<Uint8> msg(i, 0);
            /* generate random key value */
            KeySize = j;
            std::vector<Uint8> key(KeySize, 0);
            msg = rb.genRandomBytes(i);
            key = rb.genRandomBytes(KeySize);

            /* load test data */
            data_alc.m_msg      = &(msg[0]);
            data_alc.m_msg_len  = msg.size();
            data_alc.m_cmac     = &(CmacAlcp[0]);
            data_alc.m_cmac_len = CmacAlcp.size();
            data_alc.m_key      = &(key[0]);
            data_alc.m_key_len  = key.size();

            /* load ext test data */
            data_ext.m_msg      = &(msg[0]);
            data_ext.m_msg_len  = msg.size();
            data_ext.m_cmac     = &(CmacExt[0]);
            data_ext.m_cmac_len = CmacExt.size();
            data_ext.m_key      = &(key[0]);
            data_ext.m_key_len  = key.size();

            /* run test with main lib */
            if (verbose > 1)
                PrintCmacTestData(key, data_alc, CmacType);
            if (!cb->init(info, key)) {
                printf("Error in cmac init\n");
                FAIL();
            }
            error = cb->Cmac_function(data_alc);

            if (alcp_is_error(error)) {
                printf("Error in cmac function\n");
                FAIL();
            }

            /* run test with ext lib */
            if (verbose > 1)
                PrintCmacTestData(key, data_ext, CmacType);
            if (!extCb->init(info, key)) {
                printf("Error in cmac ext init function\n");
                FAIL();
            }
            error = extCb->Cmac_function(data_ext);
            if (alcp_is_error(error)) {
                printf("Error in cmac (ext lib) function\n");
                FAIL();
            }
            EXPECT_TRUE(ArraysMatch(CmacAlcp, CmacExt, i));
        }
    }
}

#endif