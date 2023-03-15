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
#include "ecdh/alc_ecdh_base.hh"
#include "ecdh/ecdh_base.hh"

// #ifdef USE_IPP
// #include "ecdh/ipp_ecdh_base.hh"
// #endif

#ifdef USE_OSSL
#include "ecdh/openssl_ecdh_base.hh"
#endif

#include "gbench_base.hh"
#include "rng_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

void inline ecdh_Bench(benchmark::State& state, alc_ec_info_t info)
{
    alc_error_t error  = {};
    std::string LibStr = "";

    /*TODO, Keysize in bytes. might change for other curves */
    int                KeySize = 32;
    std::vector<Uint8> Peer1PubKey(KeySize, 0), Peer2PubKey(KeySize, 0),
        Peer1SharedSecretKey(KeySize, 0), Peer2SharedSecretKey(KeySize, 0);

    alcp_ecdh_data_t data;

    AlcpEcdhBase aeb(info);
    EcdhBase*    Eb;
    RngBase      rb;
    Eb     = &aeb;
    LibStr = "ALCP";

#ifdef USE_OSSL
    OpenSSLEcdhBase oeb(info);
    /* Select by default openssl for cross testing if nothing provided*/
    if ((useossl == true)) {
        Eb     = &oeb;
        LibStr = "OpenSSL";
    }
#endif
    /* TODO , initialize classes for IPP here */

    std::vector<Uint8> Peer1PvtKey = rb.genRandomBytes(KeySize);
    std::vector<Uint8> Peer2PvtKey = rb.genRandomBytes(KeySize);

    /* now load this pvtkey pair into both alc, ext data */
    data.m_Peer1_PvtKey    = &(Peer1PvtKey[0]);
    data.m_Peer2_PvtKey    = &(Peer2PvtKey[0]);
    data.m_Peer1_PvtKeyLen = KeySize;
    data.m_Peer2_PvtKeyLen = KeySize;
    data.m_Peer1_PubKey    = &(Peer1PubKey[0]);
    data.m_Peer2_PubKey    = &(Peer2PubKey[0]);
    data.m_Peer1_PubKeyLen = KeySize;
    data.m_Peer2_PubKeyLen = KeySize;
    data.m_Peer1_SecretKey = &(Peer1SharedSecretKey[0]);
    data.m_Peer2_SecretKey = &(Peer2SharedSecretKey[0]);

    if (!Eb->init(info, data)) {
        std::cout << "Error in ECDH init: " << LibStr << std::endl;
        return;
    }
    for (auto _ : state) {
        if (!Eb->GeneratePublicKey(data)) {
            std::cout << "Error in ECDH Generate public key: " << LibStr
                      << std::endl;
            return;
        }
    }
    if (!Eb->ComputeSecretKey(data)) {
        std::cout << "Error in ECDH Compute Secret key: " << LibStr
                  << std::endl;
        return;
    }
    state.counters["PublicKeysGenPerSecond"] =
        benchmark::Counter(state.iterations(), benchmark::Counter::kIsRate);
    return;
}

/* add all your new benchmarks here */
/* ecdh benchmarks */
static void
BENCH_ECDH_x25519(benchmark::State& state)
{
    alc_ec_info_t info;
    info.ecCurveId     = ALCP_EC_CURVE25519;
    info.ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY;
    info.ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED;
    ecdh_Bench(state, info);
}

/* add benchmarks */
int
AddBenchmarks_ecdh()
{
    BENCHMARK(BENCH_ECDH_x25519);
    return 0;
}