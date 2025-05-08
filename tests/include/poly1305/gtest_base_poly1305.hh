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

/* Test Headers */
#include "gtest_common.hh"
#include "poly1305/alc_poly1305.hh"
#include "poly1305/poly1305.hh"
#include "rng_base.hh"

/* ALCP Headers */
#include "alcp/alcp.h"

#ifdef USE_OSSL
#include "poly1305/openssl_poly1305.hh"
#endif

#define MAX_LOOP   16000
#define INC_LOOP   16
#define START_LOOP 16

/* key len is fixed now */
#define KEY_LEN 32

/* print params verbosely */
inline void
PrintmacTestData(std::vector<Uint8>   key,
                 alcp_poly1305_data_t data,
                 std::string          mode)
{
    std::cout << "LIB: " << mode << std::endl;
    std::cout << "KEY: " << parseBytesToHexStr(data.m_key, data.m_key_len)
              << " KeyLen: " << key.size() << std::endl;
    std::cout << "MSG: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " MsgLen: " << data.m_msg_len << std::endl;
    std::cout << "MAC: " << parseBytesToHexStr(data.m_mac, data.m_mac_len)
              << " macLen(bytes): " << data.m_mac_len << std::endl;
    return;
}

/* cross test function */
void
Poly_Cross()
{
    const int   macSize    = 16;
    std::string LibStrMain = "ALCP", LibStrExt = "";

    AlcpPoly1305Base apb;
    RngBase          rb;
    Poly1305Base *   pb_main, *pb_ext = nullptr;

    pb_main = &apb;

#ifdef USE_OSSL
    OpenSSLPoly1305Base opb;
    if ((useossl == true) || (pb_ext == nullptr)) {
        pb_ext    = &opb;
        LibStrExt = "OpenSSL";
    }
#endif

    if (pb_ext == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }
    /* generate message key data, use it chunk by chunk in the loop */
    std::vector<Uint8> msg_full = rb.genRandomBytes(MAX_LOOP);
    std::vector<Uint8> key_full = rb.genRandomBytes(KEY_LEN);

    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        alcp_poly1305_data_t data_main = {}, data_ext = {};
        std::vector<Uint8>   MacMainLib(macSize, 0);
        std::vector<Uint8>   MacExtLib(macSize, 0);

        /* generate msg data from msg_full */
        msg_full = ShuffleVector(msg_full, rng);
        pos1     = msg_full.end() - i - 1;
        pos2     = msg_full.end();
        std::vector<Uint8> msg(pos1, pos2);

        /* generate random key value*/
        key_full = ShuffleVector(key_full, rng);

        /* misalign if buffers are aligned */
        if (is_aligned(&(msg[0]))) {
            data_main.m_msg = &(msg[1]);
            data_ext.m_msg  = &(msg[1]);
        } else {
            data_main.m_msg = &(msg[0]);
            data_ext.m_msg  = &(msg[0]);
        }

        /* load test data */
        data_main.m_mac     = &(MacMainLib[0]);
        data_main.m_mac_len = MacMainLib.size();
        data_main.m_key     = &(key_full[0]);

        /* load ext test data */
        data_ext.m_mac     = &(MacExtLib[0]);
        data_ext.m_mac_len = MacExtLib.size();
        data_ext.m_key     = &(key_full[0]);

        data_main.m_key_len = data_ext.m_key_len = key_full.size();
        data_main.m_msg_len = data_ext.m_msg_len = msg.size() - 1;

        /* run test with main lib */
        if (!pb_main->Init(key_full)) {
            printf("Error in mac init\n");
            FAIL();
        }
        if (!pb_main->MacUpdate(data_main)) {
            std::cout << "Error in mac_update" << std::endl;
            FAIL();
        }
        if (!pb_main->MacFinalize(data_main)) {
            std::cout << "Error in mac_finalize" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintmacTestData(key_full, data_main, LibStrMain);

        /* run test with ext lib */
        if (!pb_ext->Init(key_full)) {
            printf("Error in mac ext init function\n");
            FAIL();
        }
        if (!pb_ext->MacUpdate(data_ext)) {
            std::cout << "Error in mac_update (ext lib)" << std::endl;
            FAIL();
        }
        if (!pb_ext->MacFinalize(data_ext)) {
            std::cout << "Error in mac_finalize (ext lib)" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintmacTestData(key_full, data_ext, LibStrExt);

        /* now check if the macs match */
        EXPECT_TRUE(ArraysMatch(MacMainLib, MacExtLib, macSize));
    }
    return;
}

void
Poly_Kat()
{
    alcp_poly1305_data_t data    = {};
    const int            macSize = 16;
    std::string          LibStr  = "ALCP";

    AlcpPoly1305Base apb;
    Poly1305Base*    pb;
    pb = &apb;

    std::string TestDataFile = std::string("dataset_poly1305.csv");
    Csv         csv          = Csv(TestDataFile);

    /* check if file is valid */
    if (!csv.m_file_exists) {
        std::cout << "Error! csv file " << TestDataFile << " doesnt exist !"
                  << std::endl;
        FAIL();
    }

#ifdef USE_OSSL
    OpenSSLPoly1305Base opb;
    if (useossl == true) {
        pb     = &opb;
        LibStr = "OpenSSL";
    }
#endif

    while (csv.readNext()) {
        std::vector<Uint8> mac(macSize, 0);

        auto msg = csv.getVect("MESSAGE");
        auto key = csv.getVect("KEY");

        data.m_msg = &(msg[0]);
        data.m_key = &(key[0]);
        data.m_mac = &(mac[0]);

        data.m_msg_len = msg.size();
        data.m_mac_len = mac.size();
        data.m_key_len = key.size();

        if (!pb->Init(key)) {
            std::cout << "Error in mac init" << std::endl;
            FAIL();
        }

        if (!pb->MacUpdate(data)) {
            std::cout << "Error in mac_update" << std::endl;
            FAIL();
        }

        if (!pb->MacFinalize(data)) {
            std::cout << "Error in mac_finalize" << std::endl;
            FAIL();
        }

        if (!pb->MacReset()) {
            std::cout << "Error in mac_reset" << std::endl;
            FAIL();
        }

        if (verbose > 1)
            PrintmacTestData(std::move(key), data, LibStr);

        /*conv mac output into a vector */
        /* we need only the no of bytes needed, from the output */
        std::vector<Uint8> mac_vector(
            std::begin(mac), std::begin(mac) + csv.getVect("MAC").size());
        EXPECT_TRUE(ArraysMatch(
            mac_vector,         // Actual output
            csv.getVect("MAC"), // expected output, from the csv test data
            csv,
            LibStr));
    }
}