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
#include "digest/alc_base.hh"
#include "digest/base.hh"

#ifdef USE_IPP
#include "digest/ipp_base.hh"
#endif

#ifdef USE_OSSL
#include "digest/openssl_base.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

std::vector<int64_t> digest_block_sizes = { 16, 64, 256, 1024, 8192, 16384, 32768 };

void
Digest_Bench(benchmark::State& state, _alc_digest_type digest_type, 
                   _alc_digest_len digest_len, uint64_t block_size)
{
    alc_error_t    error;
    Uint8          message[32768] = { 0 };
    Uint8          digest[512]    = { 0 };
    AlcpDigestBase adb(digest_type, digest_len);
    DigestBase*    db = &adb;
#ifdef USE_IPP
    IPPDigestBase idb(digest_type, digest_len);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(digest_type, digest_len);
    if (useossl) {
        db = &odb;
    }
#endif

    for (auto _ : state) {
        error =
            db->digest_function(message, block_size, digest, sizeof(digest));
        db->reset();
        if (alcp_is_error(error)) {
            printf("Error in running benchmark");
            return;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * block_size, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = block_size;
    return;
}



/* add all your new benchmarks here */
/* SHA2 benchmarks */
static void
BENCH_SHA2_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_224, state.range(0));
}
static void
BENCH_SHA2_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256, state.range(0));
}
static void
BENCH_SHA2_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_384, state.range(0));
}
static void
BENCH_SHA2_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_512, state.range(0));
}
/* SHA3 benchmarks */
static void
BENCH_SHA3_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_224, state.range(0));
}
static void
BENCH_SHA3_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_256, state.range(0));
}
static void
BENCH_SHA3_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_384, state.range(0));
}
static void
BENCH_SHA3_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_DIGEST_TYPE_SHA3, ALC_DIGEST_LEN_512, state.range(0));
}

/* add benchmarks */
int AddBenchmarks() {
    BENCHMARK(BENCH_SHA2_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_256)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_384)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA3_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA3_256)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA3_384)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA3_512)->ArgsProduct({ digest_block_sizes });
    return 0;
}