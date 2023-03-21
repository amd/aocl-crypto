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

#include "alcp/alcp.h"
#include "ecdh/alc_ecdh_base.hh"
#include "ecdh/ecdh_base.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
#ifdef USE_IPP
#include "ecdh/ipp_ecdh_base.hh"
#endif
#ifdef USE_OSSL
#include "ecdh/openssl_ecdh_base.hh"
#endif

#define ECDH_KEYSIZE 32
#define MAX_LOOP     1600
#define KEY_LEN_MAX  1600
#define INC_LOOP     1
#define START_LOOP   1

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

#ifdef USE_OSSL
    OpenSSLEcdhBase oeb(info);
    if (useossl == true)
        eb = &oeb;
#endif

#ifdef USE_IPP
    IPPEcdhBase ieb(info);
    if (useipp == true)
        eb = &ieb;
#endif

    std::string TestDataFile = std::string("dataset_ECDH.csv");
    DataSet     ds           = DataSet(TestDataFile);

    while (ds.readEcdhTestData()) {
        std::vector<Uint8> Peer1_PubKey(32, 0);
        std::vector<Uint8> Peer2_PubKey(32, 0);
        std::vector<Uint8> Peer1_SecretKey(32, 0);
        std::vector<Uint8> Peer2_SecretKey(32, 0);

        /* input data to be loaded */
        std::vector<Uint8> _Peer1PvtKeyData = ds.getPeer1PvtKey();
        std::vector<Uint8> _Peer2PvtKeyData = ds.getPeer2PvtKey();

        data.m_Peer1_PvtKey    = &(_Peer1PvtKeyData[0]);
        data.m_Peer2_PvtKey    = &(_Peer2PvtKeyData[0]);
        data.m_Peer1_PvtKeyLen = ds.getPeer1PvtKey().size();
        data.m_Peer2_PvtKeyLen = ds.getPeer2PvtKey().size();

        data.m_Peer1_PubKey    = &(Peer1_PubKey[0]);
        data.m_Peer2_PubKey    = &(Peer2_PubKey[0]);
        data.m_Peer1_PubKeyLen = 32;
        data.m_Peer2_PubKeyLen = 32;

        data.m_Peer1_SecretKey    = &(Peer1_SecretKey[0]);
        data.m_Peer2_SecretKey    = &(Peer2_SecretKey[0]);
        data.m_Peer1_SecretKeyLen = 32;
        data.m_Peer2_SecretKeyLen = 32;

        if (verbose > 1)
            PrintEcdhTestData(data);

        if (!eb->init(info, data)) {
            std::cout << "Error in ECDH init" << std::endl;
            FAIL();
        }
        if (!eb->GeneratePublicKey(data)) {
            std::cout << "Error in ECDH Generate public key" << std::endl;
            FAIL();
        }

        /*TODO: x25519 pub key len should always be 32 bytes !*/
        EXPECT_TRUE(data.m_Peer1_PubKeyLen == ECDH_KEYSIZE);
        EXPECT_TRUE(data.m_Peer2_PubKeyLen == ECDH_KEYSIZE);

        if (!eb->ComputeSecretKey(data)) {
            std::cout << "Error in ECDH Compute Secret key" << std::endl;
            FAIL();
        }

        /* now check both Peers' secret keys match or not */
        EXPECT_TRUE(ArraysMatch(
            Peer1_SecretKey, Peer2_SecretKey, ds, std::string("ECDH")));

        /*TODO: x25519 shared secret key len should always be 32 bytes !*/
        EXPECT_TRUE(data.m_Peer1_SecretKeyLen == ECDH_KEYSIZE);
        EXPECT_TRUE(data.m_Peer2_SecretKeyLen == ECDH_KEYSIZE);
    }
}

/* ecdh Cross tests */
void
ecdh_Cross(alc_ec_info_t info)
{
    alc_error_t        error      = {};
    std::vector<Uint8> data       = {};
    std::string        LibStrMain = "", LibStrExt = "";

    /*TODO, Keysize in bytes. might change for other curves */
    int                KeySize = ECDH_KEYSIZE;
    std::vector<Uint8> AlcpPeer1PubKey(KeySize, 0), AlcpPeer2PubKey(KeySize, 0),
        AlcpPeer1SharedSecretKey(KeySize, 0),
        AlcpPeer2SharedSecretKey(KeySize, 0);

    std::vector<Uint8> ExtPeer1PubKey(KeySize, 0), ExtPeer2PubKey(KeySize, 0),
        ExtPeer1SharedSecretKey(KeySize, 0),
        ExtPeer2SharedSecretKey(KeySize, 0);

    alcp_ecdh_data_t data_alc, data_ext;

    AlcpEcdhBase aeb(info);
    EcdhBase *   Eb, *ExtEb = nullptr;
    RngBase      rb;

    Eb         = &aeb;
    LibStrMain = "ALCP";

#ifdef USE_IPP
    IPPEcdhBase ieb(info);
    if (useipp == true) {
        ExtEb     = &ieb;
        LibStrExt = "IPP";
    }
#endif

#ifdef USE_OSSL
    OpenSSLEcdhBase oeb(info);
    /* Select by default openssl for cross testing if nothing provided*/
    if ((useossl == true) || (ExtEb == nullptr)) {
        ExtEb     = &oeb;
        LibStrExt = "OpenSSL";
    }
#endif
    if (ExtEb == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }

    /* generate random bytes, use it in the loop */
    std::vector<Uint8> peer1_pvtkey_full = rb.genRandomBytes(KeySize);
    std::vector<Uint8> peer2_pvtkey_full = rb.genRandomBytes(KeySize);

    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    /* FIX this loop */
    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        peer1_pvtkey_full = ShuffleVector(peer1_pvtkey_full, rng);
        pos1              = peer1_pvtkey_full.begin();
        pos2              = peer1_pvtkey_full.begin() + KeySize;
        std::vector<Uint8> Peer1PvtKey(pos1, pos2);

        peer2_pvtkey_full = ShuffleVector(peer2_pvtkey_full, rng);
        pos1              = peer2_pvtkey_full.begin();
        pos2              = peer2_pvtkey_full.begin() + KeySize;
        std::vector<Uint8> Peer2PvtKey(pos1, pos2);

        /* now load this pvtkey pair into both alc, ext data */
        data_alc.m_Peer1_PvtKey       = &(Peer1PvtKey[0]);
        data_alc.m_Peer2_PvtKey       = &(Peer2PvtKey[0]);
        data_alc.m_Peer1_PvtKeyLen    = KeySize;
        data_alc.m_Peer2_PvtKeyLen    = KeySize;
        data_alc.m_Peer1_PubKey       = &(AlcpPeer1PubKey[0]);
        data_alc.m_Peer2_PubKey       = &(AlcpPeer2PubKey[0]);
        data_alc.m_Peer1_PubKeyLen    = KeySize;
        data_alc.m_Peer2_PubKeyLen    = KeySize;
        data_alc.m_Peer1_SecretKey    = &(AlcpPeer1SharedSecretKey[0]);
        data_alc.m_Peer2_SecretKey    = &(AlcpPeer2SharedSecretKey[0]);
        data_alc.m_Peer1_SecretKeyLen = 32;
        data_alc.m_Peer2_SecretKeyLen = 32;

        data_ext.m_Peer1_PvtKey       = &(Peer1PvtKey[0]);
        data_ext.m_Peer2_PvtKey       = &(Peer2PvtKey[0]);
        data_ext.m_Peer1_PvtKeyLen    = KeySize;
        data_ext.m_Peer2_PvtKeyLen    = KeySize;
        data_ext.m_Peer1_PubKey       = &(ExtPeer1PubKey[0]);
        data_ext.m_Peer2_PubKey       = &(ExtPeer2PubKey[0]);
        data_ext.m_Peer1_PubKeyLen    = KeySize;
        data_ext.m_Peer2_PubKeyLen    = KeySize;
        data_ext.m_Peer1_SecretKey    = &(ExtPeer1SharedSecretKey[0]);
        data_ext.m_Peer2_SecretKey    = &(ExtPeer2SharedSecretKey[0]);
        data_ext.m_Peer1_SecretKeyLen = 32;
        data_ext.m_Peer2_SecretKeyLen = 32;

        /* for main lib */
        if (!Eb->init(info, data_alc)) {
            std::cout << "Error in ECDH init: " << LibStrMain << std::endl;
            FAIL();
        }
        if (!Eb->GeneratePublicKey(data_alc)) {
            std::cout << "Error in ECDH Generate public key: " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (!Eb->ComputeSecretKey(data_alc)) {
            std::cout << "Error in ECDH Compute Secret key: " << LibStrMain
                      << std::endl;
            FAIL();
        }
        /* compare peer secret keys */
        EXPECT_TRUE(
            ArraysMatch(AlcpPeer1SharedSecretKey, AlcpPeer2SharedSecretKey));

        /* for ext lib */
        if (!ExtEb->init(info, data_ext)) {
            std::cout << "Error in ECDH init: Ext lib:" << LibStrExt
                      << std::endl;
            FAIL();
        }
        if (!ExtEb->GeneratePublicKey(data_ext)) {
            std::cout << "Error in ECDH Generate public key:" << LibStrExt
                      << std::endl;
            FAIL();
        }
        if (!ExtEb->ComputeSecretKey(data_ext)) {
            std::cout << "Error in ECDH Compute Secret key:" << LibStrExt
                      << std::endl;
            FAIL();
        }
        /* compare peer secret keys */
        EXPECT_TRUE(
            ArraysMatch(ExtPeer1SharedSecretKey, ExtPeer2SharedSecretKey));

        /*TODO: x25519 pub key len should always be 32 bytes !*/

        /* cross compare the keys between main and ext libs */
        EXPECT_TRUE(ArraysMatch(AlcpPeer1PubKey, ExtPeer1PubKey));
        EXPECT_TRUE(ArraysMatch(AlcpPeer2PubKey, ExtPeer2PubKey));
        EXPECT_TRUE(
            ArraysMatch(AlcpPeer1SharedSecretKey, ExtPeer1SharedSecretKey));
        EXPECT_TRUE(
            ArraysMatch(AlcpPeer2SharedSecretKey, ExtPeer2SharedSecretKey));

        if (verbose > 1) {
            std::cout << "ALC Test data" << std::endl;
            PrintEcdhTestData(data_alc);
            std::cout << "Ext Test data" << std::endl;
            PrintEcdhTestData(data_ext);
        }
    }

    return;
}

#endif