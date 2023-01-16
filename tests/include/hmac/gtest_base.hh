/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "gtest_common.hh"
#include "hmac/alc_base.hh"
#include "hmac/base.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <iostream>
#include <string.h>
#include <vector>
using namespace alcp::testing;
#ifdef USE_IPP
#include "hmac/ipp_base.hh"
#endif
#ifdef USE_OSSL
#include "hmac/openssl_base.hh"
#endif

#define MAX_LOOP   16000
#define INC_LOOP   1
#define START_LOOP 1

void
Hmac_KAT(int HmacSize, std::string HmacType, alc_mac_info_t info)
{
    alc_error_t        error;
    alcp_hmac_data_t   data;
    std::vector<Uint8> hmac(HmacSize / 8, 0);

    /* Initialize info params based on test type */
    info.mi_type = ALC_MAC_HMAC;
    info.mi_algoinfo.hmac.hmac_digest.dt_len =
        static_cast<enum _alc_digest_len>(HmacSize);

    AlcpHmacBase ahb(info);
    HmacBase*    hb;
    hb = &ahb;

    std::string TestDataFile = std::string("dataset_HMAC_" + HmacType + "_"
                                           + std::to_string(HmacSize) + ".csv");
    DataSet     ds           = DataSet(TestDataFile);

#ifdef USE_OSSL
    /*FIXME: this is not getting set for some reason*/
    OpenSSLHmacBase ohb(info);
    if (useossl == true)
        hb = &ohb;
#endif
#ifdef USE_IPP
    /*FIXME: this is not getting set for some reason*/
    IPPHmacBase ihb(info);
    if (useipp == true)
        hb = &ihb;
#endif

    while (ds.readMsgKeyHmac()) {
        auto msg = ds.getMessage();
        auto key = ds.getKey();

        data.m_msg  = &(msg[0]);
        data.m_key  = &(key[0]);
        data.m_hmac = &(hmac[0]);

        data.m_msg_len  = ds.getMessage().size();
        data.m_hmac_len = hmac.size();
        data.m_key_len  = key.size();

        if (!hb->init(info, key)) {
            printf("Error in hmac init function\n");
            return;
        }
        error = hb->Hmac_function(data);
        if (alcp_is_error(error)) {
            printf("Error in Hmac function\n");
            return;
        }

        /*conv m_digest into a vector */
        std::vector<uint8_t> hmac_vector(std::begin(hmac), std::end(hmac));

        EXPECT_TRUE(
            ArraysMatch(hmac_vector,  // Actual output
                        ds.getHmac(), // expected output, from the csv test data
                        ds,
                        std::string("HMAC_" + HmacType + "_"
                                    + std::to_string(HmacSize) + "_KAT")));
    }
}

/* Hmac Cross tests */
void
Hmac_Cross(int HmacSize, std::string HmacType, alc_mac_info_t info)
{
    alc_error_t        error;
    std::vector<Uint8> data;
    int                KeySize, KeyLenMin = START_LOOP, KeyLenMax = MAX_LOOP;
    std::vector<Uint8> HmacAlcp(HmacSize / 8, 0);
    std::vector<Uint8> HmacExt(HmacSize / 8, 0);

    /* Initialize info params based on test type */
    info.mi_type = ALC_MAC_HMAC;
    info.mi_algoinfo.hmac.hmac_digest.dt_len =
        static_cast<enum _alc_digest_len>(HmacSize);

    AlcpHmacBase ahb(info);
    RngBase      rb;
    HmacBase*    hb;
    HmacBase*    extHb = nullptr;
    hb                 = &ahb;

#ifdef USE_OSSL
    /*FIXME: this is not getting set properly even with -o option*/
    // useossl = true;
    OpenSSLHmacBase ohb(info);
    if ((useossl == true) || (extHb == nullptr))
        extHb = &ohb;
#endif
#ifdef USE_IPP
    IPPHmacBase ihb(info);
    if (useipp == true)
        extHb = &ihb;
#endif
    if (extHb == nullptr) {
        printErrors("No external lib selected!");
        exit(-1);
    }

    for (int j = KeyLenMin; j < KeyLenMax; j++) {
        for (int i = START_LOOP; i < MAX_LOOP; i += INC_LOOP) {
            alcp_hmac_data_t data_alc, data_ext;

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
            data_alc.m_hmac     = &(HmacAlcp[0]);
            data_alc.m_hmac_len = HmacAlcp.size();
            data_alc.m_key      = &(key[0]);
            data_alc.m_key_len  = key.size();

            /* load ext test data */
            data_ext.m_msg      = &(msg[0]);
            data_ext.m_msg_len  = msg.size();
            data_ext.m_hmac     = &(HmacExt[0]);
            data_ext.m_hmac_len = HmacExt.size();
            data_ext.m_key      = &(key[0]);
            data_ext.m_key_len  = key.size();

            if (!hb->init(info, key)) {
                printf("Error in hmac init\n");
                return;
            }
            error = hb->Hmac_function(data_alc);
            if (alcp_is_error(error)) {
                printf("Error in hmac function\n");
                return;
            }

            if (!extHb->init(info, key)) {
                printf("Error in hmac ext init function\n");
                return;
            }
            error = extHb->Hmac_function(data_ext);
            if (alcp_is_error(error)) {
                printf("Error in hmac (ext lib) function\n");
                return;
            }
            EXPECT_TRUE(ArraysMatch(HmacAlcp, HmacExt, i));
        }
    }
}

#endif