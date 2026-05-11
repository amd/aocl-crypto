/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#include <cstring>
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
    // Handle multibuffer modes
    if (HmacDigestMode == ALC_MB_SHA2_224
        || HmacDigestMode == ALC_MB_SHA2_256) {
        alc_digest_mode_t sb_mode =
            (HmacDigestMode == ALC_MB_SHA2_224) ? ALC_SHA2_224 : ALC_SHA2_256;
        std::string  HmacType   = DigestTypeToStr(sb_mode);
        int          HmacSize   = DigestTypeToLenMap[sb_mode];
        const Uint64 hash_bytes = HmacSize / 8;

        std::string TestDataFile =
            std::string("dataset_HMAC_" + HmacType + "_"
                        + std::to_string(HmacSize) + ".csv");
        Csv csv = Csv(std::move(TestDataFile));

        if (!csv.m_file_exists) {
            FAIL();
        }

        alc_mac_info_t info{ { HmacDigestMode } };
        AlcpHmacBase   ahb;

        const std::vector<Uint64> buffer_counts = { 1,  2,  3,  4,  5,  6,  7,
                                                    8,  9,  10, 11, 12, 13, 14,
                                                    15, 16, 32, 48, 64 };

        while (csv.readNext()) {
            auto msg           = csv.getVect("CIPHERTEXT");
            auto key           = csv.getVect("KEY");
            auto expected_hmac = csv.getVect("HMAC");

            for (auto buffers : buffer_counts) {
                std::vector<const Uint8*> mb_msg(buffers);
                std::vector<Uint8*>       mb_hmac(buffers);

                for (Uint64 i = 0; i < buffers; ++i) {
                    mb_msg[i]  = msg.data();
                    mb_hmac[i] = (Uint8*)std::malloc(hash_bytes);
                    ASSERT_NE(mb_hmac[i], nullptr);
                }

                alcp_hmac_data_t data{};
                data.in.m_p_msg     = mb_msg.data();
                data.in.m_key       = &(key[0]);
                data.out.m_p_hmac   = mb_hmac.data();
                data.in.m_msg_len   = msg.size();
                data.out.m_hmac_len = hash_bytes;
                data.in.m_key_len   = key.size();
                data.in.m_buffers   = buffers;

                if (!ahb.Init(info, key)) {
                    std::cout << "Error in hmac init function" << std::endl;
                    FAIL();
                }
                if (!ahb.MacFlush(data)) {
                    std::cout << "Error in Hmac mac_flush" << std::endl;
                    FAIL();
                }
                if (!ahb.MacDequeue(data)) {
                    std::cout << "Error in Hmac mac_dequeue" << std::endl;
                    FAIL();
                }

                for (Uint64 i = 0; i < buffers; ++i) {
                    EXPECT_EQ(0,
                              std::memcmp(
                                  mb_hmac[i], &(expected_hmac[0]), hash_bytes))
                        << "Multibuffer HMAC KAT mismatch at slot " << i
                        << " for buffers=" << buffers;
                }

                for (Uint64 i = 0; i < buffers; ++i) {
                    std::free(mb_hmac[i]);
                }
            }
        }
        return;
    }

    // Original single-buffer code
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

/* Hmac Multibuffer Cross tests */
void
Hmac_Multibuffer_Cross(int HmacSize, alc_digest_mode_t sb_mode)
{
#ifndef USE_OSSL
    std::cout << "Exiting, OSSL external lib not available" << std::endl;
    exit(-1);
#endif

    alc_digest_mode_t mb_mode{};
    switch (sb_mode) {
        case ALC_SHA2_224:
            mb_mode = ALC_MB_SHA2_224;
            break;
        case ALC_SHA2_256:
            mb_mode = ALC_MB_SHA2_256;
            break;
        default:
            std::cout << "Multibuffer is not supported for this mode; skipping "
                         "test (supported: SHA2-224, SHA2-256)."
                      << std::endl;
            return;
    }

    RngBase                   rb;
    if (seed_set)
        rb.setSeedMt19937(seed_override);
    std::cout << "[ SEED     ] " << rb.getSeedMt19937()
              << "  (repro: --seed " << rb.getSeedMt19937() << ")"
              << std::endl;
    const std::vector<Uint64> buffer_counts = { 1,  2,  3,  4,  5,  6,  7,
                                                8,  9,  10, 11, 12, 13, 14,
                                                15, 16, 32, 48, 64 };
    const Uint64              hash_bytes    = HmacSize / 8;

    alc_mac_info_t mb_info{ { mb_mode } };
    AlcpHmacBase   ahb_mb;

#ifdef USE_OSSL
    OpenSSLHmacBase ohb;
    alc_mac_info_t  sb_info{ { sb_mode } };
#endif

    for (auto buffers : buffer_counts) {
        for (Uint64 in_len = 0; in_len <= 1024; in_len++) {
            for (Uint64 key_len = 1; key_len <= 128; key_len += 16) {

                std::vector<Uint8> key(key_len);
                rb.genRandomMt19937(key);
                std::vector<std::vector<Uint8>> msgs(buffers);
                std::vector<const Uint8*>       src(buffers);
                std::vector<Uint8*>             expected(buffers);

                for (Uint64 i = 0; i < buffers; ++i) {
                    if (in_len == 0) {
                        msgs[i] = std::vector<Uint8>{ 0 };
                    } else {
                        msgs[i].resize(in_len);
                        rb.genRandomMt19937(msgs[i]);
                    }
                    src[i]      = &(msgs[i][0]);
                    expected[i] = (Uint8*)std::malloc(hash_bytes);
                    ASSERT_NE(expected[i], nullptr);
                }

#ifdef USE_OSSL
                // Calculate expected values using OpenSSL single-buffer
                for (Uint64 i = 0; i < buffers; ++i) {
                    alcp_hmac_data_t data{};
                    data.in.m_msg       = src[i];
                    data.in.m_msg_len   = in_len;
                    data.in.m_key       = &(key[0]);
                    data.in.m_key_len   = key.size();
                    data.out.m_hmac     = expected[i];
                    data.out.m_hmac_len = hash_bytes;

                    if (!ohb.Init(sb_info, key)) {
                        FAIL() << "OpenSSL HMAC init failed";
                    }
                    if (!ohb.MacUpdate(data)) {
                        FAIL() << "OpenSSL HMAC update failed";
                    }
                    if (!ohb.MacFinalize(data)) {
                        FAIL() << "OpenSSL HMAC finalize failed";
                    }
                }
#endif

                // Test with ALCP multibuffer
                std::vector<const Uint8*> mb_src(buffers);
                std::vector<Uint8*>       mb_dst(buffers);

                for (Uint64 i = 0; i < buffers; i++) {
                    mb_src[i] = src[i];
                    mb_dst[i] = (Uint8*)std::malloc(hash_bytes);
                    ASSERT_NE(mb_dst[i], nullptr);
                }

                alcp_hmac_data_t data{};
                data.in.m_p_msg     = mb_src.data();
                data.in.m_key       = &(key[0]);
                data.in.m_key_len   = key.size();
                data.out.m_p_hmac   = mb_dst.data();
                data.in.m_msg_len   = in_len;
                data.out.m_hmac_len = hash_bytes;
                data.in.m_buffers   = buffers;

                if (!ahb_mb.Init(mb_info, key)) {
                    FAIL() << "ALCP HMAC MB init failed";
                }
                if (!ahb_mb.MacFlush(data)) {
                    FAIL() << "ALCP HMAC MB flush failed";
                }
                if (!ahb_mb.MacDequeue(data)) {
                    FAIL() << "ALCP HMAC MB dequeue failed";
                }

                // Compare results
                for (Uint64 i = 0; i < buffers; i++) {
                    EXPECT_EQ(0,
                              std::memcmp(expected[i], mb_dst[i], hash_bytes))
                        << "Multibuffer HMAC cross test mismatch at slot " << i
                        << " for buffers=" << buffers << ", msg_len=" << in_len
                        << ", key_len=" << key_len;
                }

                // Cleanup
                for (Uint64 i = 0; i < buffers; ++i) {
                    std::free(mb_dst[i]);
                    std::free(expected[i]);
                }
            }
        }
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

    if (seed_set)
        rb.setSeedMt19937(seed_override);
    std::cout << "[ SEED     ] " << rb.getSeedMt19937()
              << "  (repro: --seed " << rb.getSeedMt19937() << ")"
              << std::endl;

    /* generate message key data, use it chunk by chunk in the loop */
    std::vector<Uint8> msg_full(MAX_LOOP);
    rb.genRandomMt19937(msg_full);
    std::vector<Uint8> key_full(KEY_LEN_MAX);
    rb.genRandomMt19937(key_full);

    std::vector<Uint8>::const_iterator pos1, pos2;
    std::vector<Uint8> rng_seed_bytes(4);
    rb.genRandomMt19937(rng_seed_bytes);
    uint32_t rng_seed_val;
    std::memcpy(&rng_seed_val, rng_seed_bytes.data(), 4);
    auto rng = std::default_random_engine{ rng_seed_val };

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
