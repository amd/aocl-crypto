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
#ifndef __GTEST_BASE_HH
#define __GTEST_BASE_HH 2

/* C/C++ Headers */
#include <cstring>
#include <iostream>
#include <string.h>
#include <vector>

/* ALCP Headers */
#include "alcp/alcp.h"
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "digest/gtest_base_digest.hh"
#include "gtest_common.hh"
#include "rng_base.hh"
#ifdef USE_IPP
#include "digest/ipp_digest.hh"
#endif
#ifdef USE_OSSL
#include "digest/openssl_digest.hh"
#endif

#define MAX_LOOP   16000
#define INC_LOOP   1
#define START_LOOP 1

/* print test data */
inline void
PrintDigestTestData(alcp_digest_data_t data, std::string mode)
{
    std::cout << "MSG: " << parseBytesToHexStr(data.m_msg, data.m_msg_len)
              << " MsgLen: " << data.m_msg_len << std::endl;
    std::cout << "Digest: "
              << parseBytesToHexStr(data.m_digest, data.m_digest_len)
              << " DigestLen(bytes): " << data.m_digest_len << std::endl;
    return;
}

/* to read csv file */
static inline std::string
GetDigestStr(alc_digest_mode_t mode)
{
    switch (mode) {
        case ALC_SHA2_224:
        case ALC_SHA2_256:
        case ALC_SHA2_384:
        case ALC_SHA2_512:
        case ALC_SHA2_512_224:
        case ALC_SHA2_512_256:
        case ALC_MB_SHA2_224:
        case ALC_MB_SHA2_256:
            return "SHA";
        case ALC_SHA3_224:
        case ALC_SHA3_256:
        case ALC_SHA3_384:
        case ALC_SHA3_512:
        case ALC_SHAKE_128:
        case ALC_SHAKE_256:
            return "SHA3";
        default:
            return "";
    }
}

void
Digest_KAT(alc_digest_mode_t mode, bool ctx_copy, bool test_squeeze)
{
    Uint8              Temp = 0;
    alcp_digest_data_t data;
    std::vector<Uint8> digest(GetDigestLen(mode) / 8);
    /* for storing the squeezed digest from duplicate handle */
    std::vector<Uint8> digest_dup(GetDigestLen(mode) / 8);
    AlcpDigestBase     adb(mode);
    DigestBase*        db;
    db = &adb;

    std::string TestDataFile       = "";
    std::string SHA3_SHAKE_Len_Str = "";
    /* for truncated sha512 (224,256)*/
    if (mode == ALC_SHA2_512_224 || mode == ALC_SHA2_512_256) {
        TestDataFile = "dataset_" + GetDigestStr(mode) + "_512_"
                       + std::to_string(GetDigestLen(mode)) + ".csv";
    }
    /* for SHA3 shake tests (128,256)*/
    else if (mode == ALC_SHAKE_128 || mode == ALC_SHAKE_256) {
        SHA3_SHAKE_Len_Str = (mode == ALC_SHAKE_128) ? "128" : "256";
        TestDataFile       = "dataset_" + GetDigestStr(mode) + "_SHAKE_"
                       + SHA3_SHAKE_Len_Str + ".csv";
    } else if (mode == ALC_MD5) {
        TestDataFile = "dataset_MD5.csv";
    } else if (mode == ALC_SHA1) {
        TestDataFile = "dataset_SHA1.csv";
    }
    /* for normal SHA2, SHA3 (224,256,384,512 bit) */
    else {
        TestDataFile = "dataset_" + GetDigestStr(mode) + "_"
                       + std::to_string(GetDigestLen(mode)) + ".csv";
    }
    Csv csv = Csv(std::move(TestDataFile));
    // check if file is valid
    if (!csv.m_file_exists) {
        FAIL();
    }

    if (useipp && (GetDigestStr(mode).compare("SHA3") == 0)) {
        std::cout << "IPPCP doesnt support SHA3 for now, skipping this test"
                  << std::endl;
        return;
    }

#ifdef USE_OSSL
    OpenSSLDigestBase odb(mode);
    if (useossl == true)
        db = &odb;
#endif
#ifdef USE_IPP
    IPPDigestBase idb(mode);
    if (useipp == true)
        db = &idb;
#endif

    /* for SHAKE variant */
    if (mode == ALC_SHAKE_128 || mode == ALC_SHAKE_256) {
        while (csv.readNext()) {
            auto msg          = csv.getVect("MESSAGE");
            data.m_msg_len    = msg.size();
            data.m_digest_len = csv.getVect("DIGEST").size();
            std::vector<Uint8> digest_(data.m_digest_len, 0);
            std::vector<Uint8> digest_dup_(data.m_digest_len, 0);
            data.m_digest     = &(digest_[0]);
            data.m_digest_dup = &(digest_dup_[0]);
            /* FIXME: Hack when msg is NULL, this case is not currently handled
             * in some of the digest apis */
            data.m_msg      = msg.empty() ? &Temp : msg.data();
            bool isMsgEmpty = std::all_of(
                msg.begin(), msg.end(), [](int i) { return i == 0; });
            if (isMsgEmpty) {
                data.m_msg     = &Temp;
                data.m_msg_len = 0;
            }

            if (!db->init()) {
                std::cout << "Error: Digest base init failed" << std::endl;
                FAIL();
            }
            if (!db->digest_update(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }
            if (ctx_copy) {
                if (!db->context_copy()) {
                    std::cout << "Error: Digest base context_copy failed"
                              << std::endl;
                    FAIL();
                }
            }
            /* Squeeze option only for SHAKE variants */
            if (test_squeeze) {
                if (!db->digest_squeeze(data)) {
                    std::cout << "Error: digest_squeeze failed" << std::endl;
                    FAIL();
                }
            }
            if (!db->digest_finalize(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }
            EXPECT_TRUE(ArraysMatch(
                digest_,               // output
                csv.getVect("DIGEST"), // expected, from the KAT test data
                csv,
                std::string(GetDigestStr(mode) + "_" + SHA3_SHAKE_Len_Str
                            + "_KAT")));

            /* for squeeze test, check digest outputs from both handles */
            if (test_squeeze) {
                EXPECT_TRUE(ArraysMatch(
                    digest_dup_, // output squeezed out of m_handle_dup
                    csv.getVect("DIGEST"), // expected, from the KAT test data
                    csv,
                    std::string(GetDigestStr(mode) + "_" + SHA3_SHAKE_Len_Str
                                + "_KAT" + " for duplicate digest")));
            }
        }
    } else if (mode == ALC_MB_SHA2_224 || mode == ALC_MB_SHA2_256) {
        /* Multibuffer KAT for SHA2-224 / SHA2-256:
         * For each CSV entry use the same message buffer for all multibuffer
         * slots. Allocate per-slot digest outputs, flush, dequeue and compare
         * each slot against the expected digest from the CSV.
         */
        const std::vector<Uint64> buffer_counts = { 1,  2,  3,  4,  5,  6,  7,
                                                    8,  9,  10, 11, 12, 13, 14,
                                                    15, 16, 32, 48, 64 };
        alc_digest_mode_t sb_mode    = (mode == ALC_MB_SHA2_224) ? ALC_SHA2_224
                                                                 : ALC_SHA2_256;
        const Uint64      hash_bytes = GetDigestLen(sb_mode) / 8;

        while (csv.readNext()) {
            auto msg = csv.getVect("MESSAGE");
            /* expected digest from CSV */
            auto expected_digest = csv.getVect("DIGEST");

            /* single message buffer reused across all slots */
            std::vector<Uint8> msg_buf(msg.begin(), msg.end());
            const Uint8*       msg_ptr    = nullptr;
            Uint64             msg_len    = csv.getVect("MESSAGE").size();
            bool               isMsgEmpty = std::all_of(
                msg.begin(), msg.end(), [](int i) { return i == 0; });
            if (msg_len == 0) {
                msg_ptr = &Temp;
                msg_len = 0;
            } else {
                msg_ptr = msg_buf.data();
            }
            if (isMsgEmpty) {
                msg_len = 0;
                msg_ptr = &Temp;
            }

            for (auto buffers : buffer_counts) {
                std::vector<const Uint8*> mb_src(buffers);
                std::vector<Uint8*>       mb_dst(buffers);

                for (Uint64 i = 0; i < buffers; ++i) {
                    mb_src[i] = msg_ptr;
                    mb_dst[i] = (Uint8*)std::malloc(hash_bytes);
                    ASSERT_NE(mb_dst[i], nullptr);
                }

                alcp_digest_data_t data{};
                data.m_p_msg      = mb_src.data();
                data.m_p_digest   = mb_dst.data();
                data.m_digest_len = hash_bytes;
                data.m_msg_len    = msg_len;
                data.m_buffers    = buffers;

                if (!adb.digest_flush(data)) {
                    std::cout << "Error: Digest flush failed" << std::endl;
                    FAIL();
                }
                if (!adb.digest_dequeue(data)) {
                    std::cout << "Error: Digest dequeue failed" << std::endl;
                    FAIL();
                }

                /* Compare every slot's output with expected digest from CSV */
                for (Uint64 i = 0; i < buffers; ++i) {
                    EXPECT_EQ(0,
                              std::memcmp(
                                  mb_dst[i], &(expected_digest[0]), hash_bytes))
                        << "Multibuffer KAT mismatch at slot " << i
                        << " for buffers=" << buffers;
                }

                for (Uint64 i = 0; i < buffers; ++i) {
                    std::free(mb_dst[i]);
                }
            }
        }
    } else {
        while (csv.readNext()) {
            auto msg          = csv.getVect("MESSAGE");
            data.m_msg_len    = msg.size();
            data.m_digest_len = csv.getVect("DIGEST").size();
            data.m_digest     = &(digest[0]);
            data.m_digest_dup = &(digest_dup[0]);
            /* FIXME: Hack when msg is NULL, this case is not currently handled
             * in some of the digest apis */
            data.m_msg      = msg.empty() ? &Temp : msg.data();
            bool isMsgEmpty = std::all_of(
                msg.begin(), msg.end(), [](int i) { return i == 0; });
            if (isMsgEmpty) {
                data.m_msg     = &Temp;
                data.m_msg_len = 0;
            }

            if (!db->init()) {
                std::cout << "Error: Digest base init failed" << std::endl;
                FAIL();
            }
            if (!db->digest_update(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }
            if (ctx_copy) {
                if (!db->context_copy()) {
                    std::cout << "Error: Digest base context_copy failed"
                              << std::endl;
                    FAIL();
                }
            }
            if (!db->digest_finalize(data)) {
                std::cout << "Error: Digest function failed" << std::endl;
                FAIL();
            }
            /*conv m_digest into a vector */
            std::vector<Uint8> digest_vector(std::begin(digest),
                                             std::end(digest));

            EXPECT_TRUE(ArraysMatch(
                digest_vector,         // output
                csv.getVect("DIGEST"), // expected, from the KAT test data
                csv,
                std::string(GetDigestStr(mode) + "_"
                            + std::to_string(GetDigestLen(mode)) + "_KAT")));
        }
    }
}

/* Digest Cross tests */
void
Digest_Cross(int HashSize, alc_digest_mode_t mode, bool ctx_copy)
{
    std::vector<Uint8> digestAlcp(HashSize / 8, 0);
    std::vector<Uint8> digestExt(HashSize / 8, 0);
    AlcpDigestBase     adb(mode);
    RngBase            rb;
    DigestBase*        db;
    DigestBase*        extDb = nullptr;
    db                       = &adb;

#ifdef USE_OSSL
    OpenSSLDigestBase odb(mode);
    if ((useossl == true) || (extDb == nullptr)) // Select OpenSSL by default
        extDb = &odb;
#endif
#ifdef USE_IPP
    IPPDigestBase idb(mode);
    if (useipp == true)
        extDb = &idb;
#endif
    /* do cross tests between ipp and openssl */
#if defined(USE_IPP) && defined(USE_OSSL)
    if (oa_override) {
        extDb = &odb;
        db    = &idb;
        std::cout << "Setting IPP as main Lib and OpenSSL as ext lib"
                  << std::endl;
    }
#endif

    if (extDb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    if (seed_set)
        rb.setSeedMt19937(seed_override);
    std::cout << "[ SEED     ] " << rb.getSeedMt19937()
              << "  (repro: --seed " << rb.getSeedMt19937() << ")"
              << std::endl;

    /* generate test data vector, and use it chunk by chunk in the loop */
    std::vector<Uint8> msg_full(MAX_LOOP);
    rb.genRandomMt19937(msg_full);
    std::vector<Uint8>::const_iterator pos1, pos2;
    std::vector<Uint8> rng_seed_bytes(4);
    rb.genRandomMt19937(rng_seed_bytes);
    uint32_t rng_seed_val;
    std::memcpy(&rng_seed_val, rng_seed_bytes.data(), 4);
    auto rng = std::default_random_engine{ rng_seed_val };

    for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
        alcp_digest_data_t data_alc, data_ext;

        msg_full = ShuffleVector(msg_full, rng);
        pos1     = msg_full.end() - i - 1;
        pos2     = msg_full.end();
        std::vector<Uint8> msg(pos1, pos2);

        /* misalign if buffers are aligned */
        if (is_aligned(&(msg[0]))) {
            data_alc.m_msg = &(msg[1]);
            data_ext.m_msg = &(msg[1]);
        } else {
            data_alc.m_msg = &(msg[0]);
            data_ext.m_msg = &(msg[0]);
        }

        data_alc.m_msg_len = data_ext.m_msg_len = msg.size() - 1;

        /* load test data */
        data_alc.m_digest     = &(digestAlcp[0]);
        data_alc.m_digest_len = digestAlcp.size();
        data_ext.m_digest     = &(digestExt[0]);
        data_ext.m_digest_len = digestExt.size();

        /* Initialize */
        if (!db->init()) {
            std::cout << "Error: Digest base init failed" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintDigestTestData(data_alc, GetDigestStr(mode));

        if (ctx_copy) {
            if (!db->context_copy()) {
                std::cout << "Error: Digest base context_copy failed"
                          << std::endl;
                FAIL();
            }
        }

        if (!db->digest_update(data_alc)) {
            std::cout << "Error: Digest function failed" << std::endl;
            FAIL();
        }
        if (!db->digest_finalize(data_alc)) {
            std::cout << "Error: Digest function failed" << std::endl;
            FAIL();
        }
        if (!extDb->init()) {
            std::cout << "Error: Ext Digest base init failed" << std::endl;
            FAIL();
        }
        if (verbose > 1)
            PrintDigestTestData(data_ext, GetDigestStr(mode));

        if (ctx_copy) {
            if (!extDb->context_copy()) {
                std::cout << "Error: Digest base context_copy failed"
                          << std::endl;
                FAIL();
            }
        }
        if (!extDb->digest_update(data_ext)) {
            std::cout << "Error: Ext Digest function failed" << std::endl;
            FAIL();
        }
        if (!extDb->digest_finalize(data_ext)) {
            std::cout << "Error: Ext Digest function failed" << std::endl;
            FAIL();
        }
        EXPECT_TRUE(ArraysMatch(digestAlcp, digestExt, i));
    }
}

void
Digest_Multibuffer_Cross(int HashSize, alc_digest_mode_t sb_mode)
{

#ifndef USE_OSSL
    printErrors("Exiting, OSSL external lib not available");
    GTEST_SKIP() << "OpenSSL not available for multibuffer cross test";
    return;
#else

    alc_digest_mode_t mb_mode{};
    switch (sb_mode) {
        case ALC_SHA2_224:
            ASSERT_EQ(HashSize, 224);
            mb_mode = ALC_MB_SHA2_224;
            break;
        case ALC_SHA2_256:
            ASSERT_EQ(HashSize, 256);
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
    OpenSSLDigestBase         odb(sb_mode);
    const std::vector<Uint64> buffer_counts = { 1,  2,  3,  4,  5,  6,  7,
                                                8,  9,  10, 11, 12, 13, 14,
                                                15, 16, 32, 48, 64 };
    const Uint64              hash_bytes    = HashSize / 8;
    AlcpDigestBase            adb(mb_mode);

    for (auto buffers : buffer_counts) {
        for (Uint64 in_len = 0; in_len <= 2048; in_len++) {

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

            // Calculate the expected value
            for (Uint64 i = 0; i < buffers; ++i) {
                alcp_digest_data_t data;
                data.m_msg        = src[i];
                data.m_msg_len    = in_len;
                data.m_digest_len = hash_bytes;
                data.m_digest     = expected[i];

                if (!odb.init()) {
                    std::cout << "Error: OpenSSL digest init failed"
                              << std::endl;
                    FAIL();
                }
                if (!odb.digest_update(data)) {
                    std::cout << "Error: OpenSSL digest update failed"
                              << std::endl;
                    FAIL();
                }
                if (!odb.digest_finalize(data)) {
                    std::cout << "Error: OpenSSL digest finalize failed"
                              << std::endl;
                    FAIL();
                }
            }

            std::vector<const Uint8*> mb_src(buffers);
            std::vector<Uint8*>       mb_dst(buffers);

            for (Uint64 i = 0; i < buffers; i++) {
                mb_src[i] = src[i];
                mb_dst[i] = (Uint8*)std::malloc(hash_bytes);
                ASSERT_NE(mb_dst[i], nullptr);
            }

            alcp_digest_data_t data{};
            data.m_p_msg      = mb_src.data();
            data.m_p_digest   = mb_dst.data();
            data.m_digest_len = hash_bytes;
            data.m_msg_len    = in_len;
            data.m_buffers    = buffers;

            // Flush and dequeue
            if (!adb.digest_flush(data)) {
                std::cout << "Error: Digest flush failed" << std::endl;
                FAIL();
            }
            if (!adb.digest_dequeue(data)) {
                std::cout << "Error: Digest dequeue failed" << std::endl;
                FAIL();
            }

            // Compare digest bytes
            for (Uint64 i = 0; i < buffers; i++) {
                EXPECT_EQ(0, std::memcmp(expected[i], mb_dst[i], hash_bytes))
                    << "Error\n";
            }

            // Cleanup
            for (Uint64 i = 0; i < buffers; ++i) {
                std::free(mb_dst[i]);
            }
            // Free memory allocated for expected values
            for (Uint64 i = 0; i < buffers; ++i) {
                std::free(expected[i]);
            }
        }
    }
#endif // USE_OSSL
}
#endif
