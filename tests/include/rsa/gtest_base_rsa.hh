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
#include "csv.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#include "rsa/alc_rsa.hh"
#include "rsa/rsa.hh"
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
#ifdef USE_IPP
#include "rsa/ipp_rsa.hh"
#endif
#ifdef USE_OSSL
#include "rsa/openssl_rsa.hh"
#endif

#define MAX_LOOP    1600
#define KEY_LEN_MAX 1600
#define INC_LOOP    1
#define START_LOOP  1

/* print params verbosely */
inline void
PrintRsaTestData(alcp_rsa_data_t data)
{
    std::cout << "InputData: "
              << parseBytesToHexStr(data.m_peer_text, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    std::cout << "EncryptedData: "
              << parseBytesToHexStr(data.m_peer_text_encrypted, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    std::cout << "DecryptedData: "
              << parseBytesToHexStr(data.m_peer_text_decrypted, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    return;
}

/* to bypass some invalid input cases */
bool
SkipTest(int ret_val, std::string LibStr)
{
    /* openssl returns 132 error code for invalid inputs
      and alcp returns 1 */
    if ((LibStr.compare("OpenSSL") == 0) && ret_val == 132) {
        std::cout << "Invalid case: Skipping this test" << std::endl;
        return true;
    } else if ((LibStr.compare("ALCP") == 0) && ret_val == 1) {
        std::cout << "Invalid case: Skipping this test" << std::endl;
        return true;
    } else
        return false;
}

void
Rsa_KAT()
{
    alcp_rsa_data_t data_peer;

    AlcpRsaBase arb_peer;
    std::string LibStr = "ALCP";
    RsaBase*    rb_peer;
    RngBase     rngb;

    rb_peer = &arb_peer;

#ifdef USE_OSSL
    OpenSSLRsaBase orb_peer;
    if (useossl == true) {
        rb_peer = &orb_peer;
        LibStr  = "OpenSSL";
    }
#endif

#ifdef USE_IPP
    IPPRsaBase irb_peer;
    if (useipp == true) {
        rb_peer = &irb_peer;
        LibStr  = "IPP";
    }
#endif

    std::string TestDataFile = std::string("dataset_RSA.csv");
    Csv         csv          = Csv(TestDataFile);

    int KeySize = 128;

    while (csv.readNext()) {
        /* input text to be loaded */
        std::vector<Uint8> input_data = csv.getVect("INPUT");
        std::vector<Uint8> encrypted_data(KeySize, 0);
        std::vector<Uint8> decrypted_data(KeySize, 0);
        std::vector<Uint8> Peer_PubKeyKeyMod(KeySize, 0);

        data_peer.m_peer_text           = &(input_data[0]);
        data_peer.m_pub_key_mod         = &(Peer_PubKeyKeyMod[0]);
        data_peer.m_peer_text_encrypted = &(encrypted_data[0]);
        data_peer.m_peer_text_decrypted = &(decrypted_data[0]);
        data_peer.m_msg_len             = input_data.size();

        int ret_val = 0;
        if (!rb_peer->init()) {
            std::cout << "Error in RSA init" << std::endl;
            FAIL();
        }
        if (!rb_peer->GetPublicKey(data_peer)) {
            std::cout << "Error in RSA get pubkey peer" << std::endl;
            FAIL();
        }

        ret_val = rb_peer->EncryptPubKey(data_peer);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStr))
            continue;
        if (ret_val != 0) {
            std::cout << "Error in RSA EncryptPubKey:" << ret_val << std::endl;
            FAIL();
        }

        ret_val = rb_peer->DecryptPvtKey(data_peer);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStr))
            continue;
        if (ret_val != 0) {
            std::cout << "Error in RSA DecryptPvtKey:" << ret_val << std::endl;
            FAIL();
        }
        /* check if dec val is same as input */
        EXPECT_TRUE(
            ArraysMatch(decrypted_data, input_data, csv, std::string("RSA")));

        if (verbose > 1) {
            PrintRsaTestData(data_peer);
        }
    }
    return;
}

/* RSA Cross tests */
void
Rsa_Cross()
{
    alcp_rsa_data_t data_peer_main, data_peer_ext;

    AlcpRsaBase arb_peer;
    RsaBase *   rb_peer_main, *rb_peer_ext;
    RngBase     rngb;

    rb_peer_main           = &arb_peer;
    std::string LibStrMain = "ALCP", LibStrExt = "";

#ifdef USE_OSSL
    OpenSSLRsaBase orb_peer;
    if (useossl == true || rb_peer_ext == nullptr) {
        rb_peer_ext = &orb_peer;
        LibStrExt   = "OpenSSL";
    }
#endif

#ifdef USE_IPP
    IPPRsaBase irb_peer;
    if (useipp == true) {
        rb_peer_ext = &irb_peer;
        LibStrExt   = "IPP";
    }
#endif

    int KeySize  = 128;
    int loop_max = 1600, loop_start = 1;
    int ret_val = 0;
    if (rb_peer_ext == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }
    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    std::vector<Uint8> input_data = rngb.genRandomBytes(KeySize);
    for (int i = loop_start; i < loop_max; i++) {
        input_data = ShuffleVector(input_data, rng);
        std::vector<Uint8> encrypted_data_main(KeySize, 0);
        std::vector<Uint8> decrypted_data_main(KeySize, 0);
        std::vector<Uint8> Peer_PubKeyKeyMod_main(KeySize, 0);

        std::vector<Uint8> encrypted_data_ext(KeySize, 0);
        std::vector<Uint8> decrypted_data_ext(KeySize, 0);
        std::vector<Uint8> Peer_PubKeyKeyMod_ext(KeySize, 0);

        data_peer_main.m_peer_text           = &(input_data[0]);
        data_peer_main.m_pub_key_mod         = &(Peer_PubKeyKeyMod_main[0]);
        data_peer_main.m_peer_text_encrypted = &(encrypted_data_main[0]);
        data_peer_main.m_peer_text_decrypted = &(decrypted_data_main[0]);
        data_peer_main.m_msg_len             = input_data.size();

        data_peer_ext.m_peer_text           = &(input_data[0]);
        data_peer_ext.m_pub_key_mod         = &(Peer_PubKeyKeyMod_ext[0]);
        data_peer_ext.m_peer_text_encrypted = &(encrypted_data_ext[0]);
        data_peer_ext.m_peer_text_decrypted = &(decrypted_data_ext[0]);
        data_peer_ext.m_msg_len             = input_data.size();

        if (!rb_peer_main->init()) {
            std::cout << "Error in RSA init for " << LibStrMain << std::endl;
            FAIL();
        }
        if (!rb_peer_main->GetPublicKey(data_peer_main)) {
            std::cout << "Error in RSA get pubkey peer for " << LibStrMain
                      << std::endl;
            FAIL();
        }

        ret_val = rb_peer_main->EncryptPubKey(data_peer_main);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrMain))
            continue;
        if (ret_val != 0) {
            std::cout << "EncryptPubKey failed for " << LibStrMain << std::endl;
            FAIL();
        }

        ret_val = rb_peer_main->DecryptPvtKey(data_peer_main);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrMain))
            continue;
        if (ret_val != 0) {
            std::cout << "DecryptPvtKey failed for " << LibStrMain << std::endl;
            FAIL();
        }
        /* check if decrypted output is same as input */
        EXPECT_TRUE(ArraysMatch(decrypted_data_main, input_data, i));

        /* For Ext lib */
        if (!rb_peer_ext->init()) {
            std::cout << "Error in RSA init for " << LibStrExt << std::endl;
            FAIL();
        }
        if (!rb_peer_ext->GetPublicKey(data_peer_ext)) {
            std::cout << "Error in RSA get pubkey peer for " << LibStrExt
                      << std::endl;
            FAIL();
        }
        ret_val = rb_peer_ext->EncryptPubKey(data_peer_ext);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrExt))
            continue;
        if (ret_val != 0) {
            std::cout << "EncryptPubKey failed for " << LibStrExt << std::endl;
            FAIL();
        }
        ret_val = rb_peer_ext->DecryptPvtKey(data_peer_ext);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrExt))
            continue;
        if (ret_val != 0) {
            std::cout << "DecryptPvtKey failed for " << LibStrExt << std::endl;
            FAIL();
        }

        /* compare decrypted output for ext lib vs original input */
        EXPECT_TRUE(ArraysMatch(decrypted_data_ext, input_data, i));
        /* compare decrypted outputs for both libs */
        EXPECT_TRUE(ArraysMatch(decrypted_data_ext, decrypted_data_main, i));
        if (verbose > 1) {
            PrintRsaTestData(data_peer_main);
            PrintRsaTestData(data_peer_ext);
        }
    }
    return;
}

#endif