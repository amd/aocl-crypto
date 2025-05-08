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
#include "digest/alc_digest.hh"
#include "digest/digest.hh"
#include "rng_base.hh"

#ifdef USE_IPP
#include "digest/ipp_digest.hh"
#endif

#ifdef USE_OSSL
#include "digest/openssl_digest.hh"
#endif

#include "gbench_base.hh"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>
#include <string.h>

using namespace alcp::testing;

std::vector<Int64> digest_block_sizes = {
    16, 64, 256, 1024, 8192, 16384, 32768
};

void inline Digest_Bench(benchmark::State& state,
                         alc_digest_mode_t mode,
                         Uint64            block_size)
{
    RngBase            rb;
    std::vector<Uint8> msg(block_size);
    AlcpDigestBase     adb(mode);
    DigestBase*        db = &adb;
    alcp_digest_data_t data;
#ifdef USE_IPP
    IPPDigestBase idb(mode);
    if (useipp) {
        db = &idb;
    }
#endif

#ifdef USE_OSSL
    OpenSSLDigestBase odb(mode);
    if (useossl) {
        db = &odb;
    }
#endif

    data.m_digest_len = GetDigestLen(mode) / 8;

    Uint8 digest[data.m_digest_len];
    memset(digest, 0, data.m_digest_len * sizeof(Uint8));
    /* generate random bytes */
    msg = rb.genRandomBytes(block_size);

    data.m_msg     = &(msg[0]);
    data.m_digest  = digest;
    data.m_msg_len = block_size;

    for (auto _ : state) {
        if (!db->digest_update(data)) {
            state.SkipWithError("Error in running digest benchmark:");
        }
        if (!db->digest_finalize(data)) {
            state.SkipWithError("Error in running digest benchmark:");
        }
        db->reset();
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
    Digest_Bench(state, ALC_SHA2_224, state.range(0));
}
static void
BENCH_SHA2_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_256, state.range(0));
}
static void
BENCH_SHA2_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_384, state.range(0));
}
static void
BENCH_SHA2_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512, state.range(0));
}
/* SHA 512 224 and 256 len*/
static void
BENCH_SHA2_512_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512_224, state.range(0));
}
static void
BENCH_SHA2_512_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA2_512_256, state.range(0));
}

/* SHA3 benchmarks */
static void
BENCH_SHA3_224(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_224, state.range(0));
}
static void
BENCH_SHA3_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_256, state.range(0));
}
static void
BENCH_SHA3_384(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_384, state.range(0));
}
static void
BENCH_SHA3_512(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHA3_512, state.range(0));
}

/* SHAKE */
static void
BENCH_SHAKE_128(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHAKE_128, state.range(0));
}
static void
BENCH_SHAKE_256(benchmark::State& state)
{
    Digest_Bench(state, ALC_SHAKE_256, state.range(0));
}

/* add benchmarks */
int
AddBenchmarks()
{
    /* check if custom block size is provided by user */
    if (block_size != 0) {
        std::cout << "Custom block size selected:" << block_size << std::endl;
        digest_block_sizes.resize(1);
        digest_block_sizes[0] = block_size;
    }
    BENCHMARK(BENCH_SHA2_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_256)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_384)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_224)->ArgsProduct({ digest_block_sizes });
    BENCHMARK(BENCH_SHA2_512_256)->ArgsProduct({ digest_block_sizes });

    /* SHA3 is not supported for IPP */
    if (!useipp) {
        BENCHMARK(BENCH_SHA3_224)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_256)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_384)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHA3_512)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_128)->ArgsProduct({ digest_block_sizes });
        BENCHMARK(BENCH_SHAKE_256)->ArgsProduct({ digest_block_sizes });
    }
    return 0;
}