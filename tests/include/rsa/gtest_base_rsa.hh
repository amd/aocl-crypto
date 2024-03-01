/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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
    if (data.m_msg)
        std::cout << "InputData: "
                  << parseBytesToHexStr(data.m_msg, data.m_msg_len)
                  << " Len : " << data.m_msg_len << std::endl;
    if (data.m_encrypted_data)
        std::cout << "EncryptedData: "
                  << parseBytesToHexStr(data.m_encrypted_data, data.m_msg_len)
                  << " Len : " << data.m_msg_len << std::endl;
    if (data.m_decrypted_data)
        std::cout << "DecryptedData: "
                  << parseBytesToHexStr(data.m_decrypted_data, data.m_msg_len)
                  << " Len : " << data.m_msg_len << std::endl;
    /* for sign verify tests */
    /* FIXME: signature len for now is 256, parameterize this !*/
    if (data.m_signature)
        std::cout << "Signature: " << parseBytesToHexStr(data.m_signature, 256)
                  << " Len : " << 256 << std::endl;
    return;
}

/* get padding mode name */

/* to bypass some invalid input cases */
bool
SkipTest(int ret_val, std::string LibStr)
{
    /* for invalid
      inputs, openssl returns RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
      alcp returns ALC_ERROR_NOT_PERMITTED, IPP returns -11 */
    if ((LibStr.compare("ALCP") == 0) && ret_val == ALC_ERROR_NOT_PERMITTED) {
        if (verbose > 1)
            std::cout << LibStr << ": Invalid case: Skipping this test"
                      << std::endl;
        return true;
    }
#if USE_OSSL
    if ((LibStr.compare("OpenSSL") == 0)
        && ret_val == RSA_R_DATA_TOO_LARGE_FOR_MODULUS) {
        if (verbose > 1)
            std::cout << LibStr << ": Invalid case: Skipping this test"
                      << std::endl;
        return true;
    }
#endif

#if USE_IPP
    if ((LibStr.compare("IPP") == 0) && ret_val == -11) {
        if (verbose > 1)
            std::cout << LibStr << ": Invalid case: Skipping this test"
                      << std::endl;
        return true;
    }
#endif

    return false;
}

/*FIXME: unify these two KAT functions at some point*/
/* sign and verify tests */
/* will accept only PSS/PKCS Padding modes*/

void
Rsa_SignVerifyCross(int                     padding_mode,
                    int                     KeySize,
                    const alc_digest_info_t dinfo,
                    const alc_digest_info_t mgfinfo)
{
    alcp_rsa_data_t   data_main{}, data_ext{};
    int               ret_val_main = 0, ret_val_ext = 0;
    AlcpRsaBase       arb;
    alc_drbg_handle_t handle{};
    alc_drbg_info_t   drbg_info{};
    alc_error_t       err = ALC_ERROR_NONE;

    // FIXME: Better use unique pointer here
    RsaBase *rb_main = {}, *rb_ext = {};
    RngBase  rngb;

    rb_main                = &arb;
    std::string LibStrMain = "ALCP", LibStrExt = "";

    /* Keysize is in bits */
    KeySize           = KeySize / 8;
    int InputSize_Max = 2048;

#ifdef USE_OSSL
    OpenSSLRsaBase orb;
    if (useipp == false && useossl == false) {
        printErrors("Defaulting to OpenSSL");
        useossl = true;
    }
    if (useossl) {
        rb_ext    = &orb;
        LibStrExt = "OpenSSL";
    }
#else
    if ((useipp == false && useossl == false) || useossl == true) {
        printErrors("No Lib Selected. OpenSSL also not available");
        FAIL() << "OpenSSL not available, cannot proceed with defaults!";
    }
#endif
#ifdef USE_IPP
    IPPRsaBase irb;
    if (useipp == true) {
        rb_ext    = &irb;
        LibStrExt = "IPP";
    }
#else
    if (useipp == true) {
        printErrors("IPP selected, but not available.");
        FAIL() << "IPP Missing at compile time!";
    }
#endif

    if (rb_ext == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    rb_main->m_padding_mode = rb_ext->m_padding_mode = padding_mode;
    rb_main->m_digest_info = rb_ext->m_digest_info = dinfo;
    rb_main->m_mgf_info = rb_ext->m_mgf_info = mgfinfo;
    rb_main->m_hash_len = rb_ext->m_hash_len = dinfo.dt_len / 8;

    /* use ctr-drbg to randomize the input buffer */
    /* TO DO: maybe parameterize the DRBG type, and params in future? */
    drbg_info.di_algoinfo.ctr_drbg.di_keysize              = 128;
    drbg_info.di_algoinfo.ctr_drbg.use_derivation_function = true;
    drbg_info.di_type                                      = ALC_DRBG_CTR;
    drbg_info.max_entropy_len = drbg_info.max_nonce_len = 16;
    drbg_info.di_rng_sourceinfo.custom_rng              = false;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_distrib =
        ALC_RNG_DISTRIB_UNIFORM;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_source =
        ALC_RNG_SOURCE_ARCH;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_type =
        ALC_RNG_TYPE_DISCRETE;

    err = alcp_drbg_supported(&drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_supported: " << err << std::endl;
        FAIL();
    }
    handle.ch_context = malloc(alcp_drbg_context_size(&drbg_info));
    if (handle.ch_context == nullptr) {
        std::cout << "Error: alcp_drbg_supported: " << std::endl;
        FAIL();
    }
    err = alcp_drbg_request(&handle, &drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_request: " << err << std::endl;
        FAIL();
    }
    const int cSecurityStrength = 100;
    err = alcp_drbg_initialize(&handle, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_initialize: " << err << std::endl;
        FAIL();
    }

    int loop_start = 1;
    for (int i = loop_start; i < InputSize_Max; i++) {
        std::vector<Uint8> input_data(i);
        /* shuffle input vector after each iterations */
        err = alcp_drbg_randomize(&handle,
                                  &(input_data[0]),
                                  input_data.size(),
                                  cSecurityStrength,
                                  NULL,
                                  0);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_drbg_randomize on input data: " << err
                      << std::endl;
            FAIL();
        }

        std::vector<Uint8> signature_data_main(KeySize, 0);
        std::vector<Uint8> signature_data_ext(KeySize, 0);
        std::vector<Uint8> PubKeyKeyMod_main(KeySize);
        std::vector<Uint8> PubKeyKeyMod_ext(KeySize);

        data_main.m_msg = data_ext.m_msg = &(input_data[0]);
        data_main.m_pub_key_mod          = &(PubKeyKeyMod_main[0]);
        data_ext.m_pub_key_mod           = &(PubKeyKeyMod_ext[0]);
        data_main.m_msg_len = data_ext.m_msg_len = input_data.size();
        data_main.m_key_len = data_ext.m_key_len = KeySize;

        rb_main->m_key_len = rb_ext->m_key_len = KeySize;
        rb_main->m_digest_info = rb_ext->m_digest_info = dinfo;
        rb_main->m_mgf_info = rb_ext->m_mgf_info = mgfinfo;
        rb_main->m_hash_len = rb_ext->m_hash_len = dinfo.dt_len / 8;

        /* seed and label for padding mode */
        /*FIXME: randomize salt and salt length ?*/
        std::vector<Uint8> salt(5);

        data_main.m_signature = &(signature_data_main[0]);
        data_ext.m_signature  = &(signature_data_ext[0]);
        data_main.m_salt = data_ext.m_salt = &(salt[0]);
        data_main.m_salt_len = data_ext.m_salt_len = salt.size();

        /* now generate keys, call sign and verify */
        if (!rb_main->init()) {
            std::cout << "Error in RSA init for " << LibStrMain << std::endl;
            FAIL();
        }
        if (!rb_ext->init()) {
            std::cout << "Error in RSA init for " << LibStrExt << std::endl;
            FAIL();
        }
        /* set pub, priv keys for main and ext lib */
        if (!rb_main->SetPublicKey(data_main)) {
            std::cout << "Error in RSA set pubkey for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (!rb_ext->SetPublicKey(data_ext)) {
            std::cout << "Error in RSA set pubkey for " << LibStrExt
                      << std::endl;
            FAIL();
        }
        /* set pvt key */
        if (!rb_main->SetPrivateKey(data_main)) {
            std::cout << "Error in RSA set pvt key for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (!rb_ext->SetPrivateKey(data_ext)) {
            std::cout << "Error in RSA set pvt key for " << LibStrExt
                      << std::endl;
            FAIL();
        }
        /* sign and verify */
        if (rb_main->Sign(data_main) != 0) {
            std::cout << "Error in RSA sign for " << LibStrMain << std::endl;
            FAIL();
        }
        if (rb_ext->Sign(data_ext) != 0) {
            std::cout << "Error in RSA sign for " << LibStrExt << std::endl;
            FAIL();
        }
        if (rb_main->Verify(data_main) != 0) {
            std::cout << "Error in RSA verify for " << LibStrMain << std::endl;
            FAIL();
        }
        if (rb_ext->Verify(data_ext) != 0) {
            std::cout << "Error in RSA verify for " << LibStrExt << std::endl;
            FAIL();
        }
        /* check if signature generated by both libraries are same */
        EXPECT_TRUE(
            ArraysMatch(signature_data_main, signature_data_ext, KeySize));

        /* verbose print the test data */
        if (verbose > 1) {
            PrintRsaTestData(data_main);
            PrintRsaTestData(data_ext);
        }
    }
    /* free the drbg allocations */
    alcp_drbg_finish(&handle);
    if (handle.ch_context) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
    }

    return;
}

void
Rsa_SignVerify(int                     padding_mode,
               int                     KeySize,
               const alc_digest_info_t dinfo,
               const alc_digest_info_t mgfinfo)
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

    std::string TestDataFile   = "";
    std::string PaddingModeStr = "";

    /* FIXME: different test data for diff padding modes? */
    if (padding_mode <= 0) {
        /* no padding mode is unsupported for this Algorithm as of now */
        std::cout << "No padding mode is unsupported for RSA Sign/Verify!"
                  << std::endl;
        FAIL();
    }

    rb->m_padding_mode = padding_mode;
    if (padding_mode == ALCP_TEST_RSA_PADDING_PSS) {
        PaddingModeStr = "PSS";
    } else if (padding_mode == ALCP_TEST_RSA_PADDING_PKCS) {
        PaddingModeStr = "PKCS";
    }
    TestDataFile =
        std::string("dataset_RSA_SignVerify_" + std::to_string(KeySize)
                    + "_padding_" + PaddingModeStr + ".csv");

    Csv csv = Csv(TestDataFile);

    /* Keysize is in bits (1024/2048) */
    KeySize = KeySize / 8;

    while (csv.readNext()) {
        /* input text to be loaded */
        /*FIXME: Signature, Salt, Label also should come from KAT csv file */
        std::vector<Uint8> input_data     = csv.getVect("INPUT");
        std::vector<Uint8> signature_data = csv.getVect("SIGNATURE");
        std::vector<Uint8> PubKeyKeyMod(KeySize, 0);
        /*FIXME: testing with diff salt value. Move this to test data or
         * randomize this?*/
        data.m_msg         = &(input_data[0]);
        data.m_pub_key_mod = &(PubKeyKeyMod[0]);
        data.m_msg_len     = input_data.size();
        data.m_key_len     = KeySize;

        rb->m_key_len     = KeySize;
        rb->m_digest_info = dinfo;
        rb->m_mgf_info    = mgfinfo;
        rb->m_hash_len    = dinfo.dt_len / 8;

        /* seed and label for padding mode */
        std::vector<Uint8> seed(rb->m_hash_len);
        data.m_pseed = &(seed[0]);
        std::vector<Uint8> label(5);
        data.m_label      = &(label[0]);
        data.m_label_size = label.size();

        /* for signature and verification */
        std::vector<Uint8> signature(KeySize, 0);
        Uint8              salt[] = { 'h', 'e', 'l', 'l', 'o' };
        data.m_signature          = &(signature[0]);
        data.m_salt               = &(salt[0]);
        data.m_salt_len           = 5;

        if (!rb->init()) {
            std::cout << "Error in RSA init" << std::endl;
            FAIL();
        }
        if (!rb->SetPublicKey(data)) {
            std::cout << "Error in RSA set pubkey" << std::endl;
            FAIL();
        }
        if (!rb->SetPrivateKey(data)) {
            std::cout << "Error in RSA set pvt key" << std::endl;
            FAIL();
        }
        if (rb->Sign(data) != 0) {
            std::cout << "Error in RSA sign" << std::endl;
            FAIL();
        }
        if (rb->Verify(data) != 0) {
            std::cout << "Error in RSA verify" << std::endl;
            FAIL();
        }
        if (verbose > 1) {
            PrintRsaTestData(data);
        }
        EXPECT_TRUE(ArraysMatch(signature_data, signature, KeySize));
    }
    return;
}

/* encrypt decrypt tests */
/* FIXME, change this name to Enc/Dec*/
void
Rsa_KAT(int                     padding_mode,
        int                     KeySize,
        const alc_digest_info_t dinfo,
        const alc_digest_info_t mgfinfo)
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

    std::string TestDataFile = "";
    if (padding_mode == 1) {
        rb->m_padding_mode = ALCP_TEST_RSA_PADDING;
        TestDataFile = std::string("dataset_RSA_" + std::to_string(KeySize)
                                   + "_padding" + ".csv");
    } else {
        rb->m_padding_mode = ALCP_TEST_RSA_NO_PADDING;
        TestDataFile = std::string("dataset_RSA_" + std::to_string(KeySize)
                                   + "_no_padding" + ".csv");
    }
    Csv csv = Csv(TestDataFile);

    /* Keysize is in bits (1024/2048) */
    KeySize = KeySize / 8;

    while (csv.readNext()) {
        /* input text to be loaded */
        std::vector<Uint8> input_data = csv.getVect("INPUT");
        std::vector<Uint8> encrypted_data(KeySize, 0);
        std::vector<Uint8> decrypted_data(KeySize, 0); /* keysize for padded */
        std::vector<Uint8> PubKeyKeyMod(KeySize, 0);

        data.m_msg            = &(input_data[0]);
        data.m_pub_key_mod    = &(PubKeyKeyMod[0]);
        data.m_encrypted_data = &(encrypted_data[0]);
        data.m_decrypted_data = &(decrypted_data[0]);
        data.m_msg_len        = input_data.size();
        data.m_key_len        = KeySize;

        rb->m_key_len     = KeySize;
        rb->m_digest_info = dinfo;
        rb->m_mgf_info    = mgfinfo;
        rb->m_hash_len    = dinfo.dt_len / 8;

        /* seed and label for padding mode */
        std::vector<Uint8> seed(rb->m_hash_len);
        data.m_pseed = &(seed[0]);
        std::vector<Uint8> label(5);
        data.m_label      = &(label[0]);
        data.m_label_size = label.size();

        int ret_val = 0;
        if (!rb->init()) {
            std::cout << "Error in RSA init" << std::endl;
            FAIL();
        }
        if (!rb->SetPublicKey(data)) {
            std::cout << "Error in RSA set pubkey" << std::endl;
            FAIL();
        }
        ret_val = rb->EncryptPubKey(data);
        if (ret_val != 0) {
            std::cout << "Error in RSA EncryptPubKey" << std::endl;
            FAIL();
        }

        if (!rb->SetPrivateKey(data)) {
            std::cout << "Error in RSA set pvt key" << std::endl;
            FAIL();
        }

        ret_val = rb->DecryptPvtKey(data);
        if (ret_val != 0) {
            std::cout << "Error in RSA DecryptPvtKey" << std::endl;
            FAIL();
        }
        /* check if dec val is same as input */
        if (padding_mode == 1) {
            input_data.resize(KeySize, 0);
            EXPECT_TRUE(
                ArraysMatch(decrypted_data, input_data, input_data.size()));
        } else
            EXPECT_TRUE(ArraysMatch(
                decrypted_data, input_data, csv, std::string("RSA")));
        if (verbose > 1) {
            PrintRsaTestData(data);
        }
    }
    return;
}

/* RSA Cross tests */
void
Rsa_Cross(int                     padding_mode,
          int                     KeySize,
          const alc_digest_info_t dinfo,
          const alc_digest_info_t mgfinfo)
{
    alcp_rsa_data_t   data_main{}, data_ext{};
    int               ret_val_main = 0, ret_val_ext = 0;
    AlcpRsaBase       arb;
    alc_drbg_handle_t handle{};
    alc_drbg_info_t   drbg_info{};
    alc_error_t       err = ALC_ERROR_NONE;

    // FIXME: Better use unique pointer here
    RsaBase *rb_main = {}, *rb_ext = {};
    RngBase  rngb;

    rb_main                = &arb;
    std::string LibStrMain = "ALCP", LibStrExt = "";

    /* Keysize is in bits */
    KeySize = KeySize / 8;
    int InputSize_Max;

#ifdef USE_OSSL
    OpenSSLRsaBase orb;
    if (useipp == false && useossl == false) {
        printErrors("Defaulting to OpenSSL");
        useossl = true;
    }
    if (useossl) {
        rb_ext    = &orb;
        LibStrExt = "OpenSSL";
    }
#else
    if ((useipp == false && useossl == false) || useossl == true) {
        printErrors("No Lib Selected. OpenSSL also not available");
        FAIL() << "OpenSSL not available, cannot proceed with defaults!";
    }
#endif
#ifdef USE_IPP
    IPPRsaBase irb;
    if (useipp == true) {
        rb_ext    = &irb;
        LibStrExt = "IPP";
    }
#else
    if (useipp == true) {
        printErrors("IPP selected, but not available.");
        FAIL() << "IPP Missing at compile time!";
    }
#endif

    if (rb_ext == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    rb_main->m_digest_info = rb_ext->m_digest_info = dinfo;
    rb_main->m_mgf_info = rb_ext->m_mgf_info = mgfinfo;
    rb_main->m_hash_len = rb_ext->m_hash_len = dinfo.dt_len / 8;

    if (padding_mode == 1) {
        rb_main->m_padding_mode = ALCP_TEST_RSA_PADDING;
        rb_ext->m_padding_mode  = ALCP_TEST_RSA_PADDING;
        /* input size should be 0 to m_key_size - 2 * m_hash_len - 2*/
        if (KeySize == 128) {
            InputSize_Max = 62;
        } else
            InputSize_Max = 47;
    } else {
        /* for no padding, input size = key size */
        rb_main->m_padding_mode = ALCP_TEST_RSA_NO_PADDING;
        rb_ext->m_padding_mode  = ALCP_TEST_RSA_NO_PADDING;
        InputSize_Max           = KeySize;
    }

    rb_main->m_key_len = KeySize;
    rb_ext->m_key_len  = KeySize;

    int loop_max = InputSize_Max, loop_start = 1;
    if (rb_ext == nullptr) {
        std::cout << "No external lib selected!" << std::endl;
        exit(-1);
    }
    std::vector<Uint8>::const_iterator pos1, pos2;
    auto                               rng = std::default_random_engine{};

    /* use ctr-drbg to randomize the input buffer */
    /* TO DO: maybe parameterize the DRBG type, and params in future? */
    drbg_info.di_algoinfo.ctr_drbg.di_keysize              = 128;
    drbg_info.di_algoinfo.ctr_drbg.use_derivation_function = true;
    drbg_info.di_type                                      = ALC_DRBG_CTR;
    drbg_info.max_entropy_len = drbg_info.max_nonce_len = 16;
    drbg_info.di_rng_sourceinfo.custom_rng              = false;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_distrib =
        ALC_RNG_DISTRIB_UNIFORM;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_source =
        ALC_RNG_SOURCE_ARCH;
    drbg_info.di_rng_sourceinfo.di_sourceinfo.rng_info.ri_type =
        ALC_RNG_TYPE_DISCRETE;

    err = alcp_drbg_supported(&drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_supported: " << err << std::endl;
        FAIL();
    }
    handle.ch_context = malloc(alcp_drbg_context_size(&drbg_info));
    if (handle.ch_context == nullptr) {
        std::cout << "Error: alcp_drbg_supported: " << std::endl;
        FAIL();
    }
    err = alcp_drbg_request(&handle, &drbg_info);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_request: " << err << std::endl;
        FAIL();
    }
    const int cSecurityStrength = 100;
    err = alcp_drbg_initialize(&handle, cSecurityStrength, NULL, 0);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_drbg_initialize: " << err << std::endl;
        FAIL();
    }

    int InputSize = 0;
    for (int i = loop_start; i < InputSize_Max; i++) {
        /* For non-padded mode, input len will always be KeySize */
        /* over-allocating this to test the misaligned pointers */
        if (padding_mode == 1)
            InputSize = i + 1;
        else
            InputSize = InputSize_Max + 1;

        std::vector<Uint8> input_data(InputSize);
        /* shuffle input vector after each iterations */
        err = alcp_drbg_randomize(&handle,
                                  &(input_data[0]),
                                  input_data.size(),
                                  cSecurityStrength,
                                  NULL,
                                  0);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_drbg_randomize on input data: " << err
                      << std::endl;
            FAIL();
        }

        /* set test data for each lib */
        std::vector<Uint8> encrypted_data_main(KeySize);
        std::vector<Uint8> decrypted_data_main(KeySize);
        std::vector<Uint8> PubKeyKeyMod_main(KeySize);
        std::vector<Uint8> encrypted_data_ext(KeySize);
        std::vector<Uint8> decrypted_data_ext(KeySize);
        std::vector<Uint8> PubKeyKeyMod_ext(KeySize);

        /* misalign if buffers are aligned */
        bool force_misaligned = false;
        if (is_aligned(&(input_data[0]))) {
            data_main.m_msg  = &(input_data[1]);
            data_ext.m_msg   = &(input_data[1]);
            force_misaligned = true;
        } else {
            data_main.m_msg = &(input_data[0]);
            data_ext.m_msg  = &(input_data[0]);
        }

        data_main.m_pub_key_mod    = &(PubKeyKeyMod_main[0]);
        data_main.m_encrypted_data = &(encrypted_data_main[0]);
        data_main.m_decrypted_data = &(decrypted_data_main[0]);

        data_ext.m_pub_key_mod    = &(PubKeyKeyMod_ext[0]);
        data_ext.m_encrypted_data = &(encrypted_data_ext[0]);
        data_ext.m_decrypted_data = &(decrypted_data_ext[0]);

        data_main.m_key_len = data_ext.m_key_len = KeySize;
        data_main.m_msg_len = data_ext.m_msg_len = input_data.size() - 1;

        /* set seed and label for padding mode */
        std::vector<Uint8> seed(rb_main->m_hash_len);
        /* shuffle seed data after each iterations */
        if (padding_mode == 1) {
            err = alcp_drbg_randomize(
                &handle, &(seed[0]), seed.size(), cSecurityStrength, NULL, 0);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_drbg_randomize seed data: " << err
                          << std::endl;
                FAIL();
            }
        }
        data_main.m_pseed = data_ext.m_pseed = &(seed[0]);

        /* label length should vary */
        std::vector<Uint8> label(i * KeySize);
        if (padding_mode == 1) {
            err = alcp_drbg_randomize(
                &handle, &(label[0]), label.size(), cSecurityStrength, NULL, 0);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_drbg_randomize label data: " << err
                          << std::endl;
                FAIL();
            }
        }
        data_main.m_label = data_ext.m_label = &(label[0]);
        data_main.m_label_size = data_ext.m_label_size = label.size();

        /* initialize */
        if (!rb_main->init()) {
            std::cout << "Error in RSA init for " << LibStrMain << std::endl;
            FAIL();
        }
        if (!rb_ext->init()) {
            std::cout << "Error in RSA init for " << LibStrExt << std::endl;
            FAIL();
        }

        /* set public, private keys for both libs */
        if (!rb_main->SetPublicKey(data_main)) {
            std::cout << "Error in RSA set pubkey for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (!rb_ext->SetPublicKey(data_ext)) {
            std::cout << "Error in RSA set pubkey for " << LibStrExt
                      << std::endl;
            FAIL();
        }
        if (!rb_main->SetPrivateKey(data_main)) {
            std::cout << "Error in RSA set pvt key for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (!rb_ext->SetPrivateKey(data_ext)) {
            std::cout << "Error in RSA set pvt key for " << LibStrExt
                      << std::endl;
            FAIL();
        }

        /* Call encrypt for both libs */
        ret_val_main = rb_main->EncryptPubKey(data_main);
        ret_val_ext  = rb_ext->EncryptPubKey(data_ext);
        if (SkipTest(ret_val_main, LibStrMain)
            && SkipTest(ret_val_ext, LibStrExt))
            continue;
        if (ret_val_main != 0) {
            std::cout << "Error in RSA EncryptPubKey for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (ret_val_ext != 0) {
            std::cout << "Error in RSA EncryptPubKey for " << LibStrExt
                      << std::endl;
            FAIL();
        }

        /* Call decrypt for both libs */
        ret_val_main = rb_main->DecryptPvtKey(data_main);
        ret_val_ext  = rb_ext->DecryptPvtKey(data_ext);
        if (SkipTest(ret_val_main, LibStrMain)
            && SkipTest(ret_val_ext, LibStrExt))
            continue;
        if (ret_val_main != 0) {
            std::cout << "Error in RSA EncryptPubKey for " << LibStrMain
                      << std::endl;
            FAIL();
        }
        if (ret_val_ext != 0) {
            std::cout << "Error in RSA EncryptPubKey for " << LibStrExt
                      << std::endl;
            FAIL();
        }

        /* if we are misaligning the input buffer, resize */
        if (force_misaligned) {
            input_data =
                std::vector<Uint8>(input_data.begin() + 1, input_data.end());
        }
        /* Now check outputs from both libs */
        if (padding_mode == 1) {
            input_data.resize(KeySize, 0);
            /* compare decrypted output for ext lib vs original input */
            EXPECT_TRUE(ArraysMatch(decrypted_data_main, input_data, i));
            EXPECT_TRUE(ArraysMatch(decrypted_data_ext, input_data, i));
            EXPECT_TRUE(
                ArraysMatch(decrypted_data_ext, decrypted_data_main, i));
            /* now revert input data to original length after verification
             */
            input_data.resize(i);
        } else {
            /* For non-padded mode, input len will always be KeySize */
            EXPECT_TRUE(
                ArraysMatch(decrypted_data_main, input_data, InputSize_Max));
            EXPECT_TRUE(
                ArraysMatch(decrypted_data_ext, input_data, InputSize_Max));
            EXPECT_TRUE(ArraysMatch(
                decrypted_data_ext, decrypted_data_main, InputSize_Max));
        }
        if (verbose > 1) {
            PrintRsaTestData(data_main);
            PrintRsaTestData(data_ext);
        }
    }
    alcp_drbg_finish(&handle);
    if (handle.ch_context) {
        free(handle.ch_context);
        handle.ch_context = nullptr;
    }
    return;
}
#endif