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
    std::cout << "InputData: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    std::cout << "EncryptedData: "
              << parseBytesToHexStr(data.m_encrypted_data, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    std::cout << "DecryptedData: "
              << parseBytesToHexStr(data.m_decrypted_data, data.m_msg_len)
              << " Len : " << data.m_msg_len << std::endl;
    return;
}

/* to bypass some invalid input cases */
bool
SkipTest(int ret_val, std::string LibStr)
{
    /* for invalid
      inputs, openssl returns RSA_R_DATA_TOO_LARGE_FOR_MODULUS and
      alcp returns ALC_ERROR_NOT_PERMITTED */
    if ((LibStr.compare("OpenSSL") == 0)
        && ret_val == RSA_R_DATA_TOO_LARGE_FOR_MODULUS) {
        if (verbose > 1)
            std::cout << "Invalid case: Skipping this test" << std::endl;
        return true;
    } else if ((LibStr.compare("ALCP") == 0)
               && ret_val == ALC_ERROR_NOT_PERMITTED) {
        if (verbose > 1)
            std::cout << "Invalid case: Skipping this test" << std::endl;
        return true;
    } else
        return false;
}

void
Rsa_KAT()
{
    alcp_rsa_data_t data;

    AlcpRsaBase arb;
    std::string LibStr = "ALCP";
    RsaBase*    rb;
    RngBase     rngb;

    rb = &arb;

#ifdef USE_OSSL
    OpenSSLRsaBase orb;
    if (useossl == true) {
        rb     = &orb;
        LibStr = "OpenSSL";
    }
#endif

#ifdef USE_IPP
    IPPRsaBase irb;
    if (useipp == true) {
        rb     = &irb;
        LibStr = "IPP";
    }
#endif

    std::string TestDataFile = std::string("dataset_RSA.csv");
    Csv         csv          = Csv(TestDataFile);

    int KeySize = 128;

    while (csv.readNext()) {
        /* input text to be loaded */
        std::vector<Uint8> input_data = csv.getVect("INPUT");
        std::vector<Uint8> encrypted_data(KeySize, 0);
        std::vector<Uint8> decrypted_data(input_data.size(), 0);
        std::vector<Uint8> PubKeyKeyMod(KeySize, 0);

        data.m_msg            = &(input_data[0]);
        data.m_pub_key_mod    = &(PubKeyKeyMod[0]);
        data.m_encrypted_data = &(encrypted_data[0]);
        data.m_decrypted_data = &(decrypted_data[0]);
        data.m_msg_len        = input_data.size();

        int ret_val = 0;
        if (!rb->init()) {
            std::cout << "Error in RSA init" << std::endl;
            FAIL();
        }
        if (!rb->GetPublicKey(data)) {
            std::cout << "Error in RSA get pubkey" << std::endl;
            FAIL();
        }

        ret_val = rb->EncryptPubKey(data);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStr))
            continue;
        if (ret_val != 0) {
            std::cout << "Error in RSA EncryptPubKey:" << ret_val << std::endl;
            FAIL();
        }

        ret_val = rb->DecryptPvtKey(data);
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
            PrintRsaTestData(data);
        }
    }
    return;
}

/* RSA Cross tests */
void
Rsa_Cross()
{
    alcp_rsa_data_t data_main, data_ext;

    AlcpRsaBase arb;
    RsaBase *   rb_main, *rb_ext;
    RngBase     rngb;

    rb_main                = &arb;
    std::string LibStrMain = "ALCP", LibStrExt = "";

#ifdef USE_OSSL
    OpenSSLRsaBase orb;
    if (useossl == true || rb_ext == nullptr) {
        rb_ext    = &orb;
        LibStrExt = "OpenSSL";
    }
#endif

#ifdef USE_IPP
    IPPRsaBase irb;
    if (useipp == true) {
        rb_ext    = &irb;
        LibStrExt = "IPP";
    }
#endif

    int KeySize  = 128;
    int loop_max = 1600, loop_start = 1;
    int ret_val = 0;
    if (rb_ext == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }
    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    std::vector<Uint8> input_data = rngb.genRandomBytes(KeySize);
    for (int i = loop_start; i < loop_max; i++) {
        input_data = ShuffleVector(input_data, rng);
        std::vector<Uint8> encrypted_data_main(KeySize);
        std::vector<Uint8> decrypted_data_main(KeySize);
        std::vector<Uint8> PubKeyKeyMod_main(KeySize);

        std::vector<Uint8> encrypted_data_ext(KeySize);
        std::vector<Uint8> decrypted_data_ext(KeySize);
        std::vector<Uint8> PubKeyKeyMod_ext(KeySize);

        data_main.m_msg            = &(input_data[0]);
        data_main.m_pub_key_mod    = &(PubKeyKeyMod_main[0]);
        data_main.m_encrypted_data = &(encrypted_data_main[0]);
        data_main.m_decrypted_data = &(decrypted_data_main[0]);
        data_main.m_msg_len        = input_data.size();

        data_ext.m_msg            = &(input_data[0]);
        data_ext.m_pub_key_mod    = &(PubKeyKeyMod_ext[0]);
        data_ext.m_encrypted_data = &(encrypted_data_ext[0]);
        data_ext.m_decrypted_data = &(decrypted_data_ext[0]);
        data_ext.m_msg_len        = input_data.size();

        if (!rb_main->init()) {
            std::cout << "Error in RSA init for " << LibStrMain << std::endl;
            FAIL();
        }
        if (!rb_main->GetPublicKey(data_main)) {
            std::cout << "Error in RSA get pubkey for " << LibStrMain
                      << std::endl;
            FAIL();
        }

        ret_val = rb_main->EncryptPubKey(data_main);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrMain))
            continue;
        if (ret_val != 0) {
            std::cout << "EncryptPubKey failed for " << LibStrMain << std::endl;
            FAIL();
        }

        ret_val = rb_main->DecryptPvtKey(data_main);
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
        if (!rb_ext->init()) {
            std::cout << "Error in RSA init for " << LibStrExt << std::endl;
            FAIL();
        }
        if (!rb_ext->GetPublicKey(data_ext)) {
            std::cout << "Error in RSA get pubkey for " << LibStrExt
                      << std::endl;
            FAIL();
        }
        ret_val = rb_ext->EncryptPubKey(data_ext);
        /* FIXME: the below are to handle invalid inputs at this stage */
        if (SkipTest(ret_val, LibStrExt))
            continue;
        if (ret_val != 0) {
            std::cout << "EncryptPubKey failed for " << LibStrExt << std::endl;
            FAIL();
        }
        ret_val = rb_ext->DecryptPvtKey(data_ext);
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
            PrintRsaTestData(data_main);
            PrintRsaTestData(data_ext);
        }
    }
    return;
}

#endif