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

#include "ecdh/alc_ecdh_base.hh"
#include "ecdh/ecdh_base.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
#ifdef USE_IPP
#include "ecdh/ipp_ecdh.hh"
#endif
#ifdef USE_OSSL
#include "ecdh/openssl_ecdh.hh"
#endif

/* print params verbosely */
inline void
PrintEcdhTestData(alcp_ecdh_data_t data)
{
    std::cout << "Peer1 PvtKey: "
              << parseBytesToHexStr(data.m_Peer1_PvtKey, data.m_Peer1_PvtKeyLen)
              << " Len : " << data.m_Peer1_PvtKeyLen << std::endl;
    std::cout << "Peer2 PvtKey: "
              << parseBytesToHexStr(data.m_Peer2_PvtKey, data.m_Peer2_PvtKeyLen)
              << " Len : " << data.m_Peer2_PvtKeyLen << std::endl;
    std::cout << "Peer1 PubKey: "
              << parseBytesToHexStr(data.m_Peer1_PubKey, data.m_Peer1_PubKeyLen)
              << " Len : " << data.m_Peer1_PubKeyLen << std::endl;
    std::cout << "Peer2 PubKey: "
              << parseBytesToHexStr(data.m_Peer2_PubKey, data.m_Peer2_PubKeyLen)
              << " Len : " << data.m_Peer2_PubKeyLen << std::endl;
    std::cout << "Peer1 SecretKey: "
              << parseBytesToHexStr(data.m_Peer1_SecretKey,
                                    data.m_Peer1_SecretKeyLen)
              << " Len : " << data.m_Peer1_SecretKeyLen << std::endl;
    std::cout << "Peer2 SecretKey: "
              << parseBytesToHexStr(data.m_Peer2_SecretKey,
                                    data.m_Peer2_SecretKeyLen)
              << " Len : " << data.m_Peer2_SecretKeyLen << std::endl;

    return;
}

void
ecdh_KAT(alc_ec_info_t info)
{
    alc_error_t      error;
    alcp_ecdh_data_t data;

    AlcpEcdhBase aeb(info);
    EcdhBase*    eb;

    eb = &aeb;
    /* TODO , initialize classes for OpenSSL, IPP here */

    std::string TestDataFile = std::string("dataset_ECDH.csv");
    DataSet     ds           = DataSet(TestDataFile);

    while (ds.readEcdhTestData()) {
        std::vector<Uint8> Peer1_PubKey(ds.getPeer1PubKey().size(), 0);
        std::vector<Uint8> Peer2_PubKey(ds.getPeer2PubKey().size(), 0);
        std::vector<Uint8> Peer1_SecretKey(ds.getPeer1SecretKey().size(), 0);
        std::vector<Uint8> Peer2_SecretKey(ds.getPeer2SecretKey().size(), 0);

        /* input data to be loaded */
        data.m_Peer1_PvtKey    = &(ds.getPeer1PvtKey()[0]);
        data.m_Peer2_PvtKey    = &(ds.getPeer2PvtKey()[0]);
        data.m_Peer1_PvtKeyLen = ds.getPeer1PvtKey().size();
        data.m_Peer2_PvtKeyLen = ds.getPeer2PvtKey().size();

        data.m_Peer1_PubKey    = &(Peer1_PubKey[0]);
        data.m_Peer2_PubKey    = &(Peer2_PubKey[0]);
        data.m_Peer1_PubKeyLen = ds.getPeer1PubKey().size();
        data.m_Peer2_PubKeyLen = ds.getPeer2PubKey().size();

        data.m_Peer1_SecretKey    = &(Peer1_SecretKey[0]);
        data.m_Peer2_SecretKey    = &(Peer2_SecretKey[0]);
        data.m_Peer1_SecretKeyLen = ds.getPeer1SecretKey().size();
        data.m_Peer2_SecretKeyLen = ds.getPeer2SecretKey().size();

        if (!eb->init(info)) {
            std::cout << "Error in ECDH init" << std::endl;
            FAIL();
        }
        if (!eb->GeneratePublicKey(data)) {
            std::cout << "Error in ECDH Generate public key" << std::endl;
            FAIL();
        }
        EXPECT_TRUE(
            ArraysMatch(Peer1_PubKey, Peer2_PubKey, ds, std::string("ECDH")));

        if (!eb->ComputeSecretKey(data)) {
            std::cout << "Error in ECDH Compute Secret key" << std::endl;
            FAIL();
        }

        if (verbose > 1)
            PrintEcdhTestData(data);

        /* now check both Peers' secret keys match or not */
        EXPECT_TRUE(ArraysMatch(
            Peer1_SecretKey, Peer2_SecretKey, ds, std::string("ECDH")));
    }
}

/* ecdh Cross tests */
void
ecdh_Cross()
{
    return;
}

#endif