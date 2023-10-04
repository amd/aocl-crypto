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

/* C/C++ Headers */
#include <iostream>
#include <iterator>
#include <string.h>
#include <vector>

/* Test Headers */
#include "gtest_common.hh"
#include "poly1305/alc_poly1305.hh"
#include "poly1305/poly1305.hh"

/* ALCP Headers */
#include "alcp/alcp.h"

#ifdef USE_OSSL
#include "poly1305/openssl_poly1305.hh"
#endif

#define MAX_LOOP    1600
#define KEY_LEN_MAX 1600
#define INC_LOOP    1
#define START_LOOP  1

/* print params verbosely */
inline void
PrintmacTestData(std::vector<Uint8>   key,
                 alcp_poly1305_data_t data,
                 std::string          mode)
{
    std::cout << "KEY: " << parseBytesToHexStr(&key[0], key.size())
              << " KeyLen: " << key.size() << std::endl;
    std::cout << "MSG: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " MsgLen: " << data.m_msg_len << std::endl;
    std::cout << "MAC: " << parseBytesToHexStr(data.m_mac, data.m_mac_len)
              << " macLen(bytes): " << data.m_mac_len << std::endl;
    return;
}

void
Poly_Kat(alc_mac_info_t info)
{
    alcp_poly1305_data_t data    = {};
    const int            macSize = 16;

    info.mi_type = ALC_MAC_POLY1305;

    AlcpPoly1305Base acb(info);
    Poly1305Base*    cb;
    cb = &acb;

    std::string TestDataFile = std::string("dataset_poly1305.csv");
    Csv         csv          = Csv(TestDataFile);

    /* check if file is valid */
    if (!csv.m_file_exists) {
        FAIL();
    }

#ifdef USE_OSSL
    OpenSSLPoly1305Base ocb(info);
    if (useossl == true)
        cb = &ocb;
#endif
#ifdef USE_IPP
    IPPmacBase icb(info);
    if (useipp == true)
        cb = &icb;
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

        if (!cb->init(info, key)) {
            std::cout << "Error in mac init function" << std::endl;
            FAIL();
        }

        if (!cb->mac(data)) {
            std::cout << "Error in mac function" << std::endl;
            FAIL();
        }

        if (!cb->reset()) {
            std::cout << "Error in mac reset function" << std::endl;
            FAIL();
        }

        /*conv mac output into a vector */
        /* we need only the no of bytes needed, from the output */
        std::vector<Uint8> mac_vector(
            std::begin(mac), std::begin(mac) + csv.getVect("MAC").size());
        EXPECT_TRUE(ArraysMatch(
            mac_vector,         // Actual output
            csv.getVect("MAC"), // expected output, from the csv test data
            csv,
            "POLY1305"));
    }
}