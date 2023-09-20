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
#include "poly1305/alc_poly1305.hh"
#include "poly1305/poly1305.hh"

#ifdef USE_IPP
#include "cmac/ipp_cmac.hh"
#endif

#ifdef USE_OSSL
#include "cmac/openssl_cmac.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

/* Valid block sizes for performance comparison */
std::vector<Int64> poly1305_blocksizes = {
    16, 64, 256, 1024, 8192, 16384, 32768
};
void inline Poly1305_Bench(benchmark::State& state,
                           alc_mac_info_t    info,
                           Uint64            block_size,
                           Uint64            KeySize)
{

    /* MAX len of cmac would be 128 bits */
    std::vector<Uint8> poly1305_mac(128 / 8, 0);
    std::vector<Uint8> message(block_size, 0);
    std::vector<Uint8> Key(KeySize / 8, 0);

    /* Initialize info params based on cmac type */
    info.mi_type                                         = ALC_MAC_POLY1305;
    info.mi_algoinfo.cmac.cmac_cipher.ci_algo_info.ai_iv = NULL;

    AlcpPoly1305Base     acb(info);
    Poly1305Base*        cb = &acb;
    alcp_poly1305_data_t data;
#ifdef USE_IPP
    IPPCmacBase icb(info);
    if (useipp) {
        cb = &icb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLCmacBase ocb(info);
    if (useossl) {
        cb = &ocb;
    }
#endif

    data.m_msg     = &(message[0]);
    data.m_msg_len = message.size();
    data.m_mac     = &(poly1305_mac[0]);
    data.m_mac_len = poly1305_mac.size();
    data.m_key     = &(Key[0]);
    data.m_key_len = Key.size();

    if (!cb->init(info, Key)) {
        state.SkipWithError("Error in cmac init function");
    }
    for (auto _ : state) {
        if (!cb->mac(data)) {
            state.SkipWithError("Error in cmac bench function");
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}

/* add all your new benchmarks here */
/* CMAC AES benchmarks */
static void
BENCH_POLY1305(benchmark::State& state)
{
    alc_mac_info_t info;
    Poly1305_Bench(state, info, state.range(0), 256);
}

/* add benchmarks */
int
AddBenchmarks_Poly1305()
{
    BENCHMARK(BENCH_POLY1305)->ArgsProduct({ poly1305_blocksizes });
    return 0;
}